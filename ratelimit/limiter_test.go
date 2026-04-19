package ratelimit

import (
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
