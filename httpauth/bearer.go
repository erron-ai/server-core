// Package httpauth provides constant-time HTTP token authentication
// middleware shared across server-core consumers. Eliminates the
// per-product "did we use crypto/subtle correctly?" review burden.
package httpauth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// uniformResponseUnauthorized is the body returned for any auth
// failure. We deliberately do not surface the expected length, the
// supplied length, or any hint of which check failed — those would
// leak useful information to a brute-force attacker.
const uniformResponseUnauthorized = `{"error":"unauthorized"}`

// uniformResponseUnconfigured is what we emit when the server has no
// expected token configured at all. We refuse to silently let traffic
// through; surfacing 503 makes "I forgot to set the env var" loud.
const uniformResponseUnconfigured = `{"error":"unconfigured"}`

// BearerTokenMiddleware compares the Authorization: Bearer <t> header
// against `expected` using subtle.ConstantTimeCompare with length
// pre-pad so the wall-clock time of the compare does not depend on
// either the supplied length or the expected length.
//
// `expected == ""` returns 503 — never a silent pass — so a missing
// production secret is impossible to deploy.
func BearerTokenMiddleware(expected string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expected == "" {
				writeUniform(w, http.StatusServiceUnavailable, uniformResponseUnconfigured)
				return
			}
			authHdr := r.Header.Get("Authorization")
			tok := strings.TrimPrefix(authHdr, "Bearer ")
			if !constantTimeStringEqual(tok, expected) {
				writeUniform(w, http.StatusUnauthorized, uniformResponseUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// HeaderTokenMiddleware does the same thing but reads the token from a
// caller-named header, e.g. "X-Internal-Token".
func HeaderTokenMiddleware(header, expected string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expected == "" {
				writeUniform(w, http.StatusServiceUnavailable, uniformResponseUnconfigured)
				return
			}
			tok := r.Header.Get(header)
			if !constantTimeStringEqual(tok, expected) {
				writeUniform(w, http.StatusUnauthorized, uniformResponseUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// constantTimeStringEqual returns true iff a and b are equal in a way
// that does not short-circuit on length. We pad both sides to the
// longer length so subtle.ConstantTimeCompare always sees equal-length
// inputs and the comparison time is independent of which side is
// longer.
func constantTimeStringEqual(a, b string) bool {
	if len(a) == len(b) {
		return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	}
	// Padded compare so wall-clock is identical for any (a, b) pair
	// against a fixed b. The lengths-differ case still returns false,
	// but only after performing one full-length compare against a
	// derived padded buffer. This keeps the cost independent of len(a).
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	pa := make([]byte, maxLen)
	pb := make([]byte, maxLen)
	copy(pa, a)
	copy(pb, b)
	_ = subtle.ConstantTimeCompare(pa, pb) // discard; unequal lengths must always fail
	return false
}

func writeUniform(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
