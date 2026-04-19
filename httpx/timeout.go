// Package httpx provides small HTTP middleware primitives shared across
// DorsalMail server products.
package httpx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Timeout runs the next handler in a goroutine with a context deadline.
// If the deadline is exceeded before the handler finishes, the client
// receives 504 Gateway Timeout with a small JSON body and further writes
// from the handler fail with [http.ErrHandlerTimeout] (matching
// [http.TimeoutHandler] semantics, but using 504 instead of 503).
//
// When skip returns true for a request, the handler runs inline with no
// deadline (used for long-running upload URL generation).
func Timeout(dt time.Duration, skip func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip != nil && skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			h := &timeoutHandler{handler: next, dt: dt}
			h.serveHTTP(w, r)
		})
	}
}

type timeoutHandler struct {
	handler http.Handler
	dt      time.Duration
}

func (h *timeoutHandler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.dt)
	defer cancel()
	r = r.WithContext(ctx)
	done := make(chan struct{})
	tw := &timeoutWriter{w: w, hdr: make(http.Header)}
	panicChan := make(chan any, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				panicChan <- p
			}
		}()
		h.handler.ServeHTTP(tw, r)
		close(done)
	}()
	select {
	case p := <-panicChan:
		panic(p)
	case <-done:
		tw.mu.Lock()
		defer tw.mu.Unlock()
		dst := w.Header()
		for k, vv := range tw.hdr {
			dst[k] = vv
		}
		if !tw.wroteHeader {
			tw.code = http.StatusOK
		}
		w.WriteHeader(tw.code)
		_, _ = w.Write(tw.buf.Bytes())
	case <-ctx.Done():
		tw.mu.Lock()
		defer tw.mu.Unlock()
		if ctx.Err() == context.DeadlineExceeded && !tw.wroteHeader {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = io.WriteString(w, `{"error":"gateway_timeout"}`)
			tw.err = http.ErrHandlerTimeout
		}
	}
}

type timeoutWriter struct {
	w    http.ResponseWriter
	hdr  http.Header
	buf  bytes.Buffer
	mu   sync.Mutex
	err  error
	code int

	wroteHeader bool
}

func (tw *timeoutWriter) Header() http.Header { return tw.hdr }

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.err != nil {
		return 0, tw.err
	}
	if !tw.wroteHeader {
		tw.writeHeaderLocked(http.StatusOK)
	}
	return tw.buf.Write(p)
}

func (tw *timeoutWriter) writeHeaderLocked(code int) {
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
	switch {
	case tw.err != nil:
		return
	case tw.wroteHeader:
		return
	default:
		tw.wroteHeader = true
		tw.code = code
	}
}

func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.writeHeaderLocked(code)
}
