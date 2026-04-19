package httpauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestBearerHappyPath(t *testing.T) {
	mw := BearerTokenMiddleware("super-secret")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret")
	mw.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestBearerWrongToken(t *testing.T) {
	mw := BearerTokenMiddleware("super-secret")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	mw.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthorized") {
		t.Fatalf("body: %s", rec.Body.String())
	}
}

func TestBearerUnconfiguredReturns503(t *testing.T) {
	mw := BearerTokenMiddleware("")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer anything")
	mw.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestHeaderTokenMatch(t *testing.T) {
	mw := HeaderTokenMiddleware("X-Internal-Token", "secret-x")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Internal-Token", "secret-x")
	mw.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestHeaderTokenMismatch(t *testing.T) {
	mw := HeaderTokenMiddleware("X-Internal-Token", "secret-x")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Internal-Token", "secret-y")
	mw.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestConstantTimeEqualLength(t *testing.T) {
	if constantTimeStringEqual("abc", "abc") != true {
		t.Fatal("equal strings must compare equal")
	}
	if constantTimeStringEqual("abc", "abd") {
		t.Fatal("different equal-length strings must not compare equal")
	}
}

func TestConstantTimeDifferentLength(t *testing.T) {
	if constantTimeStringEqual("abc", "abcd") {
		t.Fatal("different-length strings must not compare equal")
	}
	if constantTimeStringEqual("", "abc") {
		t.Fatal("empty vs non-empty must not compare equal")
	}
}
