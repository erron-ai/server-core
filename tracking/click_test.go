package tracking

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestIssueAndVerifyClick(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	target := "https://example.com/page?x=1"
	urlStr, err := IssueClickURL(id, target, testKeyHex, "https://api.example/")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(urlStr, "https://api.example/v1/tracking/click/") {
		t.Fatalf("unexpected URL: %s", urlStr)
	}
	tok := strings.TrimPrefix(urlStr, "https://api.example/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	got, err := VerifyClickRequest(tok, target, testKeyHex)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != id {
		t.Fatalf("id mismatch: %v vs %v", got, id)
	}
}

func TestMutatedTargetRejected(t *testing.T) {
	id := uuid.New()
	target := "https://example.com/good"
	urlStr, _ := IssueClickURL(id, target, testKeyHex, "https://api.example")
	tok := strings.TrimPrefix(urlStr, "https://api.example/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	if _, err := VerifyClickRequest(tok, "https://attacker.example/", testKeyHex); err == nil {
		t.Fatal("mutated target must be rejected")
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	id := uuid.New()
	if _, err := IssueClickURL(id, "https://x", "", "https://api.example"); err == nil {
		t.Fatal("empty key must be rejected")
	}
	if _, err := VerifyClickRequest("v1.x.y", "https://x", ""); err == nil {
		t.Fatal("empty key on verify must be rejected")
	}
}

func TestShortKeyRejected(t *testing.T) {
	id := uuid.New()
	short := "0011223344556677" // 8 bytes
	if _, err := IssueClickURL(id, "https://x", short, "https://api.example"); err == nil {
		t.Fatal("short key must be rejected")
	}
}

func TestNonHexKeyRejected(t *testing.T) {
	id := uuid.New()
	if _, err := IssueClickURL(id, "https://x", "not-hex", "https://api.example"); err == nil {
		t.Fatal("non-hex key must be rejected")
	}
}

func TestPixelRoundtrip(t *testing.T) {
	id := uuid.New()
	urlStr, err := IssuePixelURL(id, testKeyHex, "https://api.example")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tok := strings.TrimPrefix(urlStr, "https://api.example/v1/tracking/pixel/")
	got, err := VerifyPixelRequest(tok, testKeyHex)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != id {
		t.Fatalf("id mismatch")
	}
}

func TestPixelTokenRejectedAsClick(t *testing.T) {
	id := uuid.New()
	purl, _ := IssuePixelURL(id, testKeyHex, "")
	if _, err := VerifyClickRequest(strings.TrimPrefix(purl, "/v1/tracking/pixel/"), "https://x", testKeyHex); err == nil {
		t.Fatal("pixel token must not verify as click")
	}
}

func TestClickTokenRejectedAsPixel(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	target := "https://example.com/x"
	urlStr, err := IssueClickURL(id, target, testKeyHex, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(urlStr, "https://api.example/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	if _, err := VerifyPixelRequest(tok, testKeyHex); err == nil {
		t.Fatal("click token must not verify as pixel")
	}
}

func TestTagFullLength(t *testing.T) {
	id := uuid.New()
	urlStr, _ := IssueClickURL(id, "https://x", testKeyHex, "")
	tok := strings.TrimPrefix(urlStr, "/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token parts, got %d", len(parts))
	}
	if len(parts[2]) != 64 {
		t.Fatalf("expected 64-hex (32-byte) tag, got %d", len(parts[2]))
	}
}

func TestParseTokenRejectsTruncatedTag(t *testing.T) {
	id := uuid.New()
	urlStr, _ := IssueClickURL(id, "https://x", testKeyHex, "")
	tok := strings.TrimPrefix(urlStr, "/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	parts := strings.Split(tok, ".")
	truncated := parts[0] + "." + parts[1] + "." + parts[2][:16]
	if _, err := VerifyClickRequest(truncated, "https://x", testKeyHex); err == nil {
		t.Fatal("truncated tag must be rejected")
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	id := uuid.New()
	urlStr, _ := IssueClickURL(id, "https://x", testKeyHex, "")
	tok := strings.TrimPrefix(urlStr, "/v1/tracking/click/")
	tok = strings.SplitN(tok, "?", 2)[0]
	parts := strings.Split(tok, ".")
	bad := "v0." + parts[1] + "." + parts[2]
	if _, err := VerifyClickRequest(bad, "https://x", testKeyHex); err == nil {
		t.Fatal("wrong version must be rejected")
	}
}
