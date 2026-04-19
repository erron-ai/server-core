package ratelimit

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxyRealIP returns middleware that rewrites r.RemoteAddr to
// the rightmost X-Forwarded-For entry that is NOT itself a trusted
// proxy IP, but only when the direct peer IP is in `nets`. When `nets`
// is empty no rewriting happens — useful for direct-to-Internet
// deploys. The plan-server SRV-P1-5 lift moves this from the product
// to server-core unchanged so DorsalForms / Files / Chat get the same
// XFF-spoof guard for free.
func TrustedProxyRealIP(nets []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(nets) > 0 {
				peerStr, _, err := net.SplitHostPort(r.RemoteAddr)
				if err == nil {
					peerIP := net.ParseIP(peerStr)
					if peerIP != nil && containsIP(nets, peerIP) {
						if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
							parts := strings.Split(xff, ",")
							for i := len(parts) - 1; i >= 0; i-- {
								ip := net.ParseIP(strings.TrimSpace(parts[i]))
								if ip != nil && !containsIP(nets, ip) {
									r.RemoteAddr = ip.String() + ":0"
									break
								}
							}
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
