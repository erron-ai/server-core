// Package ratelimit ships shared HTTP rate-limiting primitives:
// IP/Org limiter wrappers around golang.org/x/time/rate, a Redis-first
// fail-closed counter for distributed caps, and `ClientBucketKey` /
// `TrustedProxyRealIP` for consistent client-IP extraction across
// products. The product-side wiring is a thin attach-and-go.
//
// PII contract: keys are derived from `r.RemoteAddr` (IP literal) or
// the per-org UUID. Neither is PII. The limiter never logs key values.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// ClientBucketKey returns the limiter bucket identifier for a request:
// the remote IP with the ephemeral TCP port stripped off. Without this
// normalisation, an attacker opening N TCP connections from the same
// IP lands in N distinct buckets and effectively gets N×burst.
//
// SRV-P1-5: ported from product/api/clientBucketKey unchanged. The
// trusted-proxy path in TrustedProxyRealIP rewrites r.RemoteAddr to
// "ip:0" so both paths produce identical keys.
func ClientBucketKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

type timedLimiter struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// IPLimiter is a per-IP token-bucket limiter with idle eviction.
type IPLimiter struct {
	perMin int
	idle   time.Duration

	mu    sync.Mutex
	store map[string]*timedLimiter
	once  sync.Once
}

// NewIPLimiter constructs an IPLimiter that issues `perMinute` tokens
// (with burst = perMinute) per IP. Buckets idle for `idleTTL` are
// removed by a background sweeper.
func NewIPLimiter(perMinute int, idleTTL time.Duration) *IPLimiter {
	if perMinute <= 0 {
		perMinute = 120
	}
	if idleTTL <= 0 {
		idleTTL = 15 * time.Minute
	}
	return &IPLimiter{perMin: perMinute, idle: idleTTL, store: map[string]*timedLimiter{}}
}

// Allow attempts to consume one token from the bucket for `ip`.
// Returns the underlying limiter so the caller can write standard
// rate-limit headers without re-deriving values.
func (l *IPLimiter) Allow(ip string) (*rate.Limiter, bool) {
	l.startEvictionOnce()
	l.mu.Lock()
	entry, ok := l.store[ip]
	if !ok {
		entry = &timedLimiter{
			lim: rate.NewLimiter(rate.Limit(float64(l.perMin)/60.0), l.perMin),
		}
		l.store[ip] = entry
	}
	entry.lastSeen = time.Now()
	l.mu.Unlock()
	return entry.lim, entry.lim.Allow()
}

func (l *IPLimiter) startEvictionOnce() {
	l.once.Do(func() {
		go func() {
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for range t.C {
				l.evict()
			}
		}()
	})
}

func (l *IPLimiter) evict() {
	cutoff := time.Now().Add(-l.idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.store {
		if v.lastSeen.Before(cutoff) {
			delete(l.store, k)
		}
	}
}

// OrgLimiter is the per-org-UUID equivalent of IPLimiter.
type OrgLimiter struct {
	perMin int
	idle   time.Duration

	mu    sync.Mutex
	store map[uuid.UUID]*timedLimiter
	once  sync.Once
}

// NewOrgLimiter constructs an OrgLimiter with `perMinute` tokens per
// org. `idleTTL` controls bucket eviction.
func NewOrgLimiter(perMinute int, idleTTL time.Duration) *OrgLimiter {
	if perMinute <= 0 {
		perMinute = 600
	}
	if idleTTL <= 0 {
		idleTTL = 15 * time.Minute
	}
	return &OrgLimiter{perMin: perMinute, idle: idleTTL, store: map[uuid.UUID]*timedLimiter{}}
}

// Allow attempts to consume one token for `org`.
func (l *OrgLimiter) Allow(org uuid.UUID) (*rate.Limiter, bool) {
	l.startEvictionOnce()
	l.mu.Lock()
	entry, ok := l.store[org]
	if !ok {
		entry = &timedLimiter{
			lim: rate.NewLimiter(rate.Limit(float64(l.perMin)/60.0), l.perMin),
		}
		l.store[org] = entry
	}
	entry.lastSeen = time.Now()
	l.mu.Unlock()
	return entry.lim, entry.lim.Allow()
}

func (l *OrgLimiter) startEvictionOnce() {
	l.once.Do(func() {
		go func() {
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for range t.C {
				l.evict()
			}
		}()
	})
}

func (l *OrgLimiter) evict() {
	cutoff := time.Now().Add(-l.idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range l.store {
		if v.lastSeen.Before(cutoff) {
			delete(l.store, k)
		}
	}
}
