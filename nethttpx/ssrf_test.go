package nethttpx

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsBlockedIPv4(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"172.17.0.1", true},
		{"100.64.0.1", true},
		{"169.254.169.254", true},
		{"169.254.10.10", true},
		{"203.0.113.5", true},
		{"198.51.100.5", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, c := range cases {
		if got := IsBlockedIP(net.ParseIP(c.ip)); got != c.blocked {
			t.Errorf("%s: got %v want %v", c.ip, got, c.blocked)
		}
	}
}

func TestIsBlockedIPv6(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"::1", true},
		{"fc00::1", true},
		{"fd00::1", true},
		{"fe80::1", true},
		{"ff02::1", true},
		{"2001:db8::1", true},
		{"2001::1", true},
		{"fd00:ec2::254", true},
		{"2606:4700:4700::1111", false},
	}
	for _, c := range cases {
		if got := IsBlockedIP(net.ParseIP(c.ip)); got != c.blocked {
			t.Errorf("%s: got %v want %v", c.ip, got, c.blocked)
		}
	}
}

func TestDevAllowsDocker(t *testing.T) {
	if !shouldBlockForMode(net.ParseIP("172.17.0.1"), true) {
		t.Fatal("production must block 172.17.0.1")
	}
	if shouldBlockForMode(net.ParseIP("172.17.0.1"), false) {
		t.Fatal("dev must allow 172.17.0.1")
	}
	if shouldBlockForMode(net.ParseIP("127.0.0.1"), false) {
		t.Fatal("dev must allow loopback (httptest)")
	}
	if !shouldBlockForMode(net.ParseIP("127.0.0.1"), true) {
		t.Fatal("production must block loopback")
	}
	if !shouldBlockForMode(net.ParseIP("169.254.169.254"), false) {
		t.Fatal("AWS IMDS must stay blocked even in dev")
	}
}

func TestValidatePublicURL_Schemes(t *testing.T) {
	if err := ValidatePublicURL("ftp://example.com/", false); err == nil {
		t.Fatal("ftp must be rejected")
	}
	if err := ValidatePublicURL("http://example.com/", true); err == nil {
		t.Fatal("http must be rejected in production")
	}
	if err := ValidatePublicURL("https://example.com/", true); err != nil {
		t.Fatalf("https public must pass: %v", err)
	}
}

func TestValidatePublicURL_ProductionHTTPErrorMessage(t *testing.T) {
	t.Parallel()
	err := ValidatePublicURL("http://example.com/", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "nethttpx: production url must use https" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePublicURL_LiteralIP127ProductionBlocked(t *testing.T) {
	t.Parallel()
	err := ValidatePublicURL("https://127.0.0.1/", true)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("want ErrBlockedAddress, got %v", err)
	}
}

func TestValidatePublicURL_UserinfoURLDoesNotPanic(t *testing.T) {
	t.Parallel()
	// Hostname is example.com; userinfo is ignored for resolution.
	if err := ValidatePublicURL("https://user@example.com", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsBlockedIP_Nil(t *testing.T) {
	t.Parallel()
	if !IsBlockedIP(nil) {
		t.Fatal("nil IP must be blocked")
	}
}

func TestIsBlockedIP_172Boundary(t *testing.T) {
	t.Parallel()
	if IsBlockedIP(net.ParseIP("172.15.255.255")) {
		t.Fatal("172.15.0.0/16 must not be private")
	}
	if !IsBlockedIP(net.ParseIP("172.16.0.1")) {
		t.Fatal("172.16.0.0/12 must be blocked")
	}
}

func TestIsBlockedIP_IMDSIPv4(t *testing.T) {
	t.Parallel()
	if !IsBlockedIP(net.ParseIP("169.254.169.254")) {
		t.Fatal("IMDS must be blocked")
	}
}

func TestDialContextForPublic_UnsupportedRemoteAddrType(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	sock := filepath.Join(tmp, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()
	dial := DialContextForPublic(true)
	_, err = dial(context.Background(), "unix", sock)
	if err == nil {
		t.Fatal("expected error for non-TCP/UDP remote addr")
	}
	if !strings.Contains(err.Error(), "unsupported address type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePublicURL_LocalhostBlocked(t *testing.T) {
	// "localhost" is rejected even in dev (dotless hostname rule).
	if err := ValidatePublicURL("http://localhost/", false); err == nil {
		t.Fatal("localhost must be rejected even in dev")
	}
	// 127.0.0.1 is allowed in dev (httptest servers) but blocked
	// in production.
	if err := ValidatePublicURL("http://127.0.0.1/", true); err == nil {
		t.Fatal("127.0.0.1 must be rejected in production")
	}
}

func TestValidatePublicURL_IMDSBlocked(t *testing.T) {
	if err := ValidatePublicURL("http://169.254.169.254/latest/meta-data/", false); err == nil {
		t.Fatal("AWS IMDS must be rejected")
	}
	if err := ValidatePublicURL("http://[fd00:ec2::254]/latest/meta-data/", false); err == nil {
		t.Fatal("AWS IPv6 IMDS must be rejected")
	}
}

func TestValidatePublicURL_IPv6LiteralBlocked(t *testing.T) {
	if err := ValidatePublicURL("http://[fc00::1]/", false); err == nil {
		t.Fatal("IPv6 ULA must be rejected")
	}
}

func TestValidatePublicURL_DockerAllowedInDev(t *testing.T) {
	if err := ValidatePublicURL("http://172.17.0.1/webhook", false); err != nil {
		t.Fatalf("dev must allow Docker bridge: %v", err)
	}
	if err := ValidatePublicURL("http://172.17.0.1/webhook", true); err == nil {
		t.Fatal("production must block 172.17.0.1")
	}
}

func TestValidatePublicURL_HostnameResolution(t *testing.T) {
	// Use a name that is guaranteed to resolve to a public address.
	// We tolerate offline test environments by skipping if resolution
	// fails altogether.
	addrs, err := net.LookupIP("dns.google")
	if err != nil || len(addrs) == 0 {
		t.Skip("DNS not available")
	}
	if err := ValidatePublicURL("https://dns.google/", true); err != nil {
		t.Fatalf("dns.google must pass: %v", err)
	}
}
