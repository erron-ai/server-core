package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTimeout_Returns504WhenSlow(t *testing.T) {
	t.Parallel()

	h := Timeout(50*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
}

func TestTimeout_SkipBypassesDeadline(t *testing.T) {
	t.Parallel()

	skip := func(r *http.Request) bool { return r.Header.Get("X-Skip") == "1" }
	h := Timeout(30*time.Millisecond, skip)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Skip", "1")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestTimeout_FastHandlerOK(t *testing.T) {
	t.Parallel()

	h := Timeout(200*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestTimeout_Returns504JSONBody(t *testing.T) {
	t.Parallel()
	h := Timeout(30*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("code = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if strings.TrimSpace(rec.Body.String()) != `{"error":"gateway_timeout"}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestTimeout_HandlerWriteAfterDeadlineReturnsErrHandlerTimeout(t *testing.T) {
	t.Parallel()
	ch := make(chan error, 1)
	h := Timeout(30*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		_, err := w.Write([]byte("late"))
		ch <- err
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("code = %d", rec.Code)
	}
	select {
	case err := <-ch:
		if err != http.ErrHandlerTimeout {
			t.Fatalf("Write err = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for handler Write")
	}
}

func TestTimeout_WriteHeaderThenSlow_NoSecond504(t *testing.T) {
	t.Parallel()
	h := Timeout(30*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		time.Sleep(80 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d (regression: must not emit 504 after 200)", rec.Code)
	}
}

func TestTimeout_ContextCanceled_NoGatewayTimeoutBody(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	h := Timeout(200*time.Millisecond, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusGatewayTimeout {
		t.Fatal("canceled request must not produce 504")
	}
	if strings.Contains(rec.Body.String(), "gateway_timeout") {
		t.Fatalf("body: %s", rec.Body.String())
	}
}
