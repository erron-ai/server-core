// Package httphdr provides HTTP security header middleware for Dorsal API servers.
package httphdr

import "net/http"

// SecurityHeaders returns middleware that sets defensive HTTP security headers.
// Designed for API-only servers (no inline scripts, no frames, no external loads).
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'none'")
			next.ServeHTTP(w, r)
		})
	}
}
