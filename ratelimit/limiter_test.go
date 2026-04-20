package ratelimit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClientBucketKeyStripsPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	if got := ClientBucketKey(r); got != "10.1.2.3" {
		t.Fatalf("got %q", got)
	}
	r.RemoteAddr = "10.1.2.3"
	if got := ClientBucketKey(r); got != "10.1.2.3" {
		t.Fatalf("got %q", got)
	}
}

func TestIPLimiterBurst(t *testing.T) {
	l := NewIPLimiter(2, time.Minute)
	_, ok := l.Allow("1.2.3.4")
	if !ok {
		t.Fatal("first call should be allowed")
	}
	_, ok = l.Allow("1.2.3.4")
	if !ok {
		t.Fatal("second call should be allowed")
	}
	_, ok = l.Allow("1.2.3.4")
	if ok {
		t.Fatal("third immediate call should be rejected")
	}
}

func TestOrgLimiterIsolation(t *testing.T) {
	l := NewOrgLimiter(1, time.Minute)
	a, b := uuid.New(), uuid.New()
	if _, ok := l.Allow(a); !ok {
		t.Fatal("a first call allowed")
	}
	if _, ok := l.Allow(a); ok {
		t.Fatal("a second call denied")
	}
	if _, ok := l.Allow(b); !ok {
		t.Fatal("b first call allowed (separate bucket)")
	}
}

func TestIncrementExpiringCounter_NilRedis(t *testing.T) {
	t.Parallel()
	_, err := IncrementExpiringCounter(context.Background(), nil, "k", time.Minute)
	if !errors.Is(err, ErrNoRedis) {
		t.Fatalf("got %v", err)
	}
}

type errRedis struct{}

func (errRedis) IncrementExpiringCounter(ctx context.Context, key string, ttl time.Duration) (int, error) {
	return 0, errors.New("boom")
}

func (errRedis) Delete(ctx context.Context, key string) error { return nil }

func TestIncrementExpiringCounter_ErrorPropagates(t *testing.T) {
	t.Parallel()
	var r errRedis
	_, err := IncrementExpiringCounter(context.Background(), r, "k", time.Minute)
	if err == nil || err.Error() != "boom" {
		t.Fatalf("got %v", err)
	}
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTrustedProxyRealIP_NoTrustedNetsNoRewrite(t *testing.T) {
	t.Parallel()
	h := TrustedProxyRealIP(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "203.0.113.5:1234" {
			t.Fatalf("RemoteAddr = %q", r.RemoteAddr)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 198.51.100.2")
	h.ServeHTTP(rec, req)
}

func TestTrustedProxyRealIP_PeerTrustedEmptyXFFNoRewrite(t *testing.T) {
	t.Parallel()
	trusted := []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")}
	h := TrustedProxyRealIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "10.1.2.3:4444" {
			t.Fatalf("RemoteAddr = %q", r.RemoteAddr)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:4444"
	h.ServeHTTP(rec, req)
}

func TestTrustedProxyRealIP_PicksRightmostUntrusted(t *testing.T) {
	t.Parallel()
	trusted := []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")}
	h := TrustedProxyRealIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "198.51.100.9:0" {
			t.Fatalf("RemoteAddr = %q", r.RemoteAddr)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.2")
	h.ServeHTTP(rec, req)
}

func TestTrustedProxyRealIP_AllXFFTrustedNoRewrite(t *testing.T) {
	t.Parallel()
	trusted := []*net.IPNet{mustParseCIDR(t, "10.0.0.0/8")}
	h := TrustedProxyRealIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "10.0.0.1:443" {
			t.Fatalf("RemoteAddr = %q", r.RemoteAddr)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")
	h.ServeHTTP(rec, req)
}

func TestClientBucketKey_NilRequestPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil request")
		}
	}()
	_ = ClientBucketKey(nil)
}

func TestNewIPLimiter_ZeroUsesDefaultBurst120(t *testing.T) {
	t.Parallel()
	l := NewIPLimiter(0, 0)
	ip := "9.9.9.9"
	for i := 0; i < 120; i++ {
		if _, ok := l.Allow(ip); !ok {
			t.Fatalf("call %d: expected allow", i+1)
		}
	}
	if _, ok := l.Allow(ip); ok {
		t.Fatal("121st immediate call should be rejected with default perMin=120")
	}
}
