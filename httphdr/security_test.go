package httphdr_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dorsalmail/server-core/httphdr"
)

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	handler := httphdr.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	cases := [][2]string{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
		{"Content-Security-Policy", "default-src 'none'"},
	}
	for _, tc := range cases {
		if got := rec.Header().Get(tc[0]); got != tc[1] {
			t.Errorf("%s: want %q, got %q", tc[0], tc[1], got)
		}
	}
}

func TestSecurityHeaders_CallsNext(t *testing.T) {
	t.Parallel()
	called := false
	handler := httphdr.SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("SecurityHeaders must call the next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", rec.Code)
	}
}
