package httpx

import (
	"net/http"
	"net/http/httptest"
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
