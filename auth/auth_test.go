package auth

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestCanonicalRequest(t *testing.T) {
	t.Parallel()

	got := string(CanonicalRequest("dorsalmail", http.MethodPost, "/transit", 123, "abcd", []byte(`{"ok":true}`)))
	want := "dorsalmail\nPOST\n/transit\n123\nabcd\n{\"ok\":true}"
	if got != want {
		t.Fatalf("canonical mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestSignedHeadersAndVerifySignature(t *testing.T) {
	t.Parallel()

	headers, signed, err := SignedHeaders(
		testKeyHex,
		"dorsalmail",
		http.MethodPost,
		"/transit",
		[]byte(`{"hello":"world"}`),
		SignOptions{
			Now:   time.Unix(1_700_000_000, 0).UTC(),
			Nonce: "00112233445566778899aabb",
		},
	)
	if err != nil {
		t.Fatalf("SignedHeaders: %v", err)
	}
	if headers.Get(HeaderTimestamp) != "1700000000" {
		t.Fatalf("timestamp = %q", headers.Get(HeaderTimestamp))
	}
	if headers.Get(HeaderNonce) != "00112233445566778899aabb" {
		t.Fatalf("nonce = %q", headers.Get(HeaderNonce))
	}
	if headers.Get(HeaderSignature) == "" || signed.Signature == "" {
		t.Fatal("signature should not be empty")
	}

	parsed, err := ParseHeaders(headers)
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	if err := VerifySignature(testKeyHex, "dorsalmail", http.MethodPost, "/transit", []byte(`{"hello":"world"}`), parsed); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestValidateProductID(t *testing.T) {
	t.Parallel()

	good := []string{"dorsalmail", "dorsalforms", "dorsalfiles", "dorsalsocket", "dorsalchat", "dorsal01"}
	for _, p := range good {
		if err := ValidateProductID(p); err != nil {
			t.Fatalf("ValidateProductID(%q): unexpected error: %v", p, err)
		}
	}
	bad := []string{"", "dorsal", "dorsala", "DorsalMail", "mail", "dorsalMAIL", "dorsal-mail", "dorsal_mail", "dorsalmail!"}
	for _, p := range bad {
		if err := ValidateProductID(p); err == nil {
			t.Fatalf("ValidateProductID(%q): expected error", p)
		}
	}
}

func TestSignRequestRejectsInvalidProduct(t *testing.T) {
	t.Parallel()

	_, _, err := SignedHeaders(testKeyHex, "", http.MethodPost, "/x", []byte(`{}`), SignOptions{
		Nonce: "00112233445566778899aabb",
	})
	if err == nil {
		t.Fatal("expected error on empty product")
	}
}

func TestDerivePrincipalHashNormalizes(t *testing.T) {
	t.Parallel()

	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	a, err := DerivePrincipalHash(testKeyHex, orgID, " User@Example.com ")
	if err != nil {
		t.Fatalf("DerivePrincipalHash: %v", err)
	}
	b, err := DerivePrincipalHash(testKeyHex, orgID, "user@example.com")
	if err != nil {
		t.Fatalf("DerivePrincipalHash: %v", err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("principal hash must be case/whitespace insensitive")
	}
}

func TestParseHeadersRejectsInvalidNonce(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	headers.Set(HeaderTimestamp, "123")
	headers.Set(HeaderNonce, "not-hex")
	headers.Set(HeaderSignature, "abcd")

	if _, err := ParseHeaders(headers); err == nil {
		t.Fatal("expected ParseHeaders error")
	}
}

func TestValidateTimestamp(t *testing.T) {
	t.Parallel()

	now := time.Unix(1000, 0).UTC()
	if err := ValidateTimestamp(1000, now, time.Minute); err != nil {
		t.Fatalf("expected timestamp to pass: %v", err)
	}
	if err := ValidateTimestamp(1000-120, now, time.Minute); err == nil {
		t.Fatal("expected stale timestamp error")
	}
}

func TestDeriveTransitHashKey(t *testing.T) {
	t.Parallel()

	orgID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	keyA, err := DeriveTransitHashKey(testKeyHex, orgID)
	if err != nil {
		t.Fatalf("DeriveTransitHashKey: %v", err)
	}
	keyB, err := DeriveTransitHashKey(testKeyHex, orgID)
	if err != nil {
		t.Fatalf("DeriveTransitHashKey: %v", err)
	}
	if hex.EncodeToString(keyA) != hex.EncodeToString(keyB) {
		t.Fatal("expected deterministic org key")
	}
}

func TestComputeAndVerifyBlobMAC(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"ciphertext_blob":  "abc",
		"encrypted_dek":    "def",
		"attachment_count": 1,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	mac, err := ComputeBlobMAC(testKeyHex, raw)
	if err != nil {
		t.Fatalf("ComputeBlobMAC: %v", err)
	}
	payload["blob_mac"] = mac
	verified, err := VerifyBlobMap(payload, testKeyHex)
	if err != nil {
		t.Fatalf("VerifyBlobMap: %v", err)
	}
	if _, ok := verified["blob_mac"]; ok {
		t.Fatal("verified payload must not include blob_mac")
	}
}

func TestVerifyBlobMapRejectsTamper(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"ciphertext_blob":  "abc",
		"encrypted_dek":    "def",
		"attachment_count": 1,
	}
	raw, _ := json.Marshal(payload)
	mac, _ := ComputeBlobMAC(testKeyHex, raw)
	payload["blob_mac"] = mac
	payload["ciphertext_blob"] = "tampered"

	if _, err := VerifyBlobMap(payload, testKeyHex); err == nil {
		t.Fatal("expected tamper verification error")
	}
}
