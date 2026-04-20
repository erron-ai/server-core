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
	if rec.Body.String() != uniformResponseUnconfigured {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestMiddleware_UnconfiguredSecret_503JSONAndBodyExact(t *testing.T) {
	t.Parallel()
	assertUnconfigured := func(t *testing.T, h http.Handler) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("code = %d", rec.Code)
		}
		if rec.Body.String() != uniformResponseUnconfigured {
			t.Fatalf("body = %q", rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q", ct)
		}
	}
	t.Run("Bearer", func(t *testing.T) {
		t.Parallel()
		called := false
		h := BearerTokenMiddleware("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		assertUnconfigured(t, h)
		if called {
			t.Fatal("next must not run")
		}
	})
	t.Run("HeaderToken", func(t *testing.T) {
		t.Parallel()
		called := false
		h := HeaderTokenMiddleware("X-Token", "")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		assertUnconfigured(t, h)
		if called {
			t.Fatal("next must not run")
		}
	})
}

func TestBearer_NoAuthorizationHeader_401(t *testing.T) {
	t.Parallel()
	mw := BearerTokenMiddleware("secret")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Body.String() != uniformResponseUnauthorized {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestBearer_AuthorizationBearerNoSpace_401(t *testing.T) {
	t.Parallel()
	mw := BearerTokenMiddleware("secret")(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer")
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
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
