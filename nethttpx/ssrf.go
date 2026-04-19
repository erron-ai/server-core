// Package nethttpx ships the cross-product SSRF guard: an IP-range
// blocklist, an http.Transport DialContext that rejects post-DNS the
// resolved peer if it falls inside that blocklist, and a registration-
// time URL validator that resolves and checks the host before storing
// the URL.
//
// PII contract: opaque input — URLs, IPs, and ports are operational
// metadata. The package never logs or stores the targets it inspects.
package nethttpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// ErrBlockedAddress is returned by DialContextForPublic when the
// resolved peer IP falls inside an SSRF-blocked range.
var ErrBlockedAddress = errors.New("nethttpx: blocked address")

var (
	// blockedIPv4Nets are CIDRs we always refuse to connect to from a
	// "public" outbound HTTP client. Order is irrelevant — we run a
	// linear membership check.
	blockedIPv4Nets = mustParseCIDRs(
		"0.0.0.0/8",       // current network
		"10.0.0.0/8",      // RFC1918
		"100.64.0.0/10",   // Carrier-grade NAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local + IMDS
		"172.16.0.0/12",   // RFC1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.168.0.0/16",  // RFC1918
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved
	)

	blockedIPv6Nets = mustParseCIDRs(
		"::1/128",        // loopback
		"::/128",         // unspecified
		"fc00::/7",       // unique local (RFC4193)
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
		"2001::/32",      // TEREDO
		"2001:db8::/32",  // documentation
		"64:ff9b::/96",   // NAT64 well-known
		"100::/64",       // discard prefix
		"fd00:ec2::/32",  // AWS IMDS via IPv6 (mirrors 169.254.169.254)
	)

	// devOnlyAllowedV4 is intersected with the blocklist when the
	// dialer is configured for non-production: loopback + 172.16/12
	// stay allowed so Docker bridge gateway addresses and local
	// httptest servers keep working in tests.
	devOnlyAllowedV4 = mustParseCIDRs("127.0.0.0/8", "172.16.0.0/12")
	// devOnlyAllowedV6 mirrors the v4 list for IPv6 loopback.
	devOnlyAllowedV6 = mustParseCIDRs("::1/128")

	// awsIMDSv4 is the AWS Instance-Metadata Service IPv4 literal. It
	// already falls inside 169.254.0.0/16 above, but we surface it as
	// a named match so detection logic can attribute the block reason.
	awsIMDSv4 = net.ParseIP("169.254.169.254")
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("nethttpx: bad CIDR %q: %v", c, err))
		}
		out = append(out, n)
	}
	return out
}

// IsBlockedIP reports whether ip is in any range that outbound public
// HTTP must never reach. Production-only: link-local, IMDS, RFC1918,
// loopback, multicast, etc.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4.Equal(awsIMDSv4) {
			return true
		}
		for _, n := range blockedIPv4Nets {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range blockedIPv6Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isDevAllowed returns true when ip is in the dev-only allowlist
// (loopback + 172.16/12 for Docker bridges and local httptest).
// AWS IMDS stays hard-blocked even in dev — no environment ever
// legitimately calls it from outbound HTTP.
func isDevAllowed(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		if v4.Equal(awsIMDSv4) {
			return false
		}
		for _, n := range devOnlyAllowedV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range devOnlyAllowedV6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// shouldBlockForMode applies the production / dev policy split for
// the live-dial path. In production every blocked range is hard-
// blocked. In dev we soften loopback + 172.16/12 so local httptest
// servers and Docker bridges work; AWS IMDS stays hard-blocked.
func shouldBlockForMode(ip net.IP, production bool) bool {
	if !production && isDevAllowed(ip) {
		return false
	}
	return IsBlockedIP(ip)
}

// (registration uses the same policy as the dialer — strict in
// production, lenient toward loopback + Docker bridges in dev so
// local httptest servers can be registered as webhook targets.)

// DialContextForPublic returns an http.Transport.DialContext that
// dials, then rejects + closes the connection if the resolved peer IP
// falls inside the SSRF blocklist. The post-dial check defeats DNS
// rebind attacks where a hostname resolves to a public IP at validate
// time but a private IP at delivery time.
func DialContextForPublic(production bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 15 * time.Second}
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		var peerIP net.IP
		switch ta := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			peerIP = ta.IP
		case *net.UDPAddr:
			peerIP = ta.IP
		default:
			_ = conn.Close()
			return nil, fmt.Errorf("nethttpx: unsupported address type %T", conn.RemoteAddr())
		}
		if shouldBlockForMode(peerIP, production) {
			_ = conn.Close()
			return nil, ErrBlockedAddress
		}
		return conn, nil
	}
}

// ValidatePublicURL parses raw, requires http(s), requires https in
// production, resolves the host, and rejects if any resolved IP falls
// inside the SSRF blocklist. Use this at registration time (webhooks,
// schema URLs) — it's an early check, NOT a substitute for
// DialContextForPublic at delivery time. DNS records change.
func ValidatePublicURL(raw string, production bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("nethttpx: invalid url")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("nethttpx: scheme must be http or https")
	}
	if production && scheme != "https" {
		return errors.New("nethttpx: production url must use https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return errors.New("nethttpx: empty host")
	}
	// Reject obvious dotless hostnames (e.g. "localhost") even when
	// they don't resolve to a blocked literal.
	if host == "localhost" || host == "ip6-localhost" || host == "ip6-loopback" {
		return errors.New("nethttpx: localhost not allowed")
	}
	// If the host is an IP literal, check it directly.
	if ip := net.ParseIP(host); ip != nil {
		if shouldBlockForMode(ip, production) {
			return ErrBlockedAddress
		}
		return nil
	}
	// Otherwise resolve and check every record.
	addrs, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("nethttpx: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("nethttpx: no addresses for %q", host)
	}
	for _, ip := range addrs {
		if shouldBlockForMode(ip, production) {
			return ErrBlockedAddress
		}
	}
	return nil
}
