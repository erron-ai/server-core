package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	coreerrors "github.com/erron-ai/server-core/errors"
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

func TestSignRequest_InvalidHexKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  string
	}{
		{name: "wrongLenHex", key: "ab"},
		{name: "invalidHex", key: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := SignRequest(tc.key, "dorsalmail", http.MethodPost, "/x", []byte(`{}`), SignOptions{
				Nonce: "00112233445566778899aabb",
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidField) {
				t.Fatalf("code = %q, want invalid_field", coreerrors.CodeOf(err))
			}
		})
	}
}

func TestSignRequest_DeterministicSignature(t *testing.T) {
	t.Parallel()
	fixed := time.Unix(1_700_000_000, 0).UTC()
	signed, err := SignRequest(testKeyHex, "dorsalmail", http.MethodPost, "/transit", []byte(`{"a":1}`), SignOptions{
		Now:   fixed,
		Nonce: "00112233445566778899aabb",
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	keyBytes, err := hex.DecodeString(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write(signed.Canonical)
	want := hex.EncodeToString(mac.Sum(nil))
	if signed.Signature != want {
		t.Fatalf("signature mismatch\n got: %s\nwant: %s", signed.Signature, want)
	}
}

func TestParseHeaders_MissingHeaderCodes(t *testing.T) {
	t.Parallel()
	base := func() http.Header {
		h := make(http.Header)
		h.Set(HeaderTimestamp, "1")
		h.Set(HeaderNonce, "00112233445566778899aabb")
		h.Set(HeaderSignature, "ab")
		return h
	}
	t.Run("missing timestamp", func(t *testing.T) {
		h := base()
		h.Del(HeaderTimestamp)
		_, err := ParseHeaders(h)
		if err == nil {
			t.Fatal("expected error")
		}
		if coreerrors.CodeOf(err) != string(coreerrors.CodeMissingTimestamp) {
			t.Fatalf("code = %q", coreerrors.CodeOf(err))
		}
	})
	t.Run("missing nonce", func(t *testing.T) {
		h := base()
		h.Del(HeaderNonce)
		_, err := ParseHeaders(h)
		if err == nil {
			t.Fatal("expected error")
		}
		if coreerrors.CodeOf(err) != string(coreerrors.CodeMissingNonce) {
			t.Fatalf("code = %q", coreerrors.CodeOf(err))
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		h := base()
		h.Del(HeaderSignature)
		_, err := ParseHeaders(h)
		if err == nil {
			t.Fatal("expected error")
		}
		if coreerrors.CodeOf(err) != string(coreerrors.CodeMissingSignature) {
			t.Fatalf("code = %q", coreerrors.CodeOf(err))
		}
	})
}

func TestParseHeaders_OddLengthSignatureHex(t *testing.T) {
	t.Parallel()
	h := make(http.Header)
	h.Set(HeaderTimestamp, "1")
	h.Set(HeaderNonce, "00112233445566778899aabb")
	h.Set(HeaderSignature, "abc")
	_, err := ParseHeaders(h)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidSignature) {
		t.Fatalf("code = %q, want invalid_signature", coreerrors.CodeOf(err))
	}
}

func TestParseHeaders_TrimSpace(t *testing.T) {
	t.Parallel()
	h := make(http.Header)
	h.Set(HeaderTimestamp, "  1700000000  ")
	h.Set(HeaderNonce, "  00112233445566778899aabb  ")
	h.Set(HeaderSignature, "  abc  ")
	_, err := ParseHeaders(h)
	if err == nil {
		t.Fatal("expected invalid signature (odd-length hex)")
	}
	// Valid 32-byte hex signature
	sig := hex.EncodeToString(make([]byte, 32))
	h.Set(HeaderSignature, "  "+sig+"  ")
	parsed, err := ParseHeaders(h)
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	if parsed.Timestamp != 1700000000 {
		t.Fatalf("timestamp = %d", parsed.Timestamp)
	}
	if parsed.Nonce != "00112233445566778899aabb" {
		t.Fatalf("nonce = %q", parsed.Nonce)
	}
	if parsed.Signature != sig {
		t.Fatalf("signature not normalized: got %q want %q", parsed.Signature, sig)
	}
}

func TestValidateTimestamp_PastBeyondSkew(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0).UTC()
	err := ValidateTimestamp(1000-400, now, time.Minute)
	if err == nil {
		t.Fatal("expected stale error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidField) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestValidateTimestamp_FutureBeyondSkew(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0).UTC()
	err := ValidateTimestamp(1000+400, now, time.Minute)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidField) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestValidateTimestamp_ZeroSkewWindowUsesDefault(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0).UTC()
	if err := ValidateTimestamp(now.Unix(), now, 0); err != nil {
		t.Fatalf("expected ok at exact now: %v", err)
	}
	past := now.Add(-6 * time.Minute)
	if err := ValidateTimestamp(past.Unix(), now, 0); err == nil {
		t.Fatal("expected beyond default 5m window")
	}
}

func TestValidateTimestamp_UsesProvidedNow(t *testing.T) {
	t.Parallel()
	fixed := time.Unix(5000, 0).UTC()
	if err := ValidateTimestamp(5000, fixed, time.Minute); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
}

func TestVerifyBlobMap_MissingBlobMACKey(t *testing.T) {
	t.Parallel()
	_, err := VerifyBlobMap(map[string]any{"x": 1}, testKeyHex)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeBlobMACMissing) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestVerifyBlobMap_BlobMACWrongType(t *testing.T) {
	t.Parallel()
	_, err := VerifyBlobMap(map[string]any{"blob_mac": 123}, testKeyHex)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeInvalidField) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestVerifyBlobMap_WrongMAC(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"ciphertext_blob": "abc",
		"blob_mac":        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}
	_, err := VerifyBlobMap(payload, testKeyHex)
	if err == nil {
		t.Fatal("expected error")
	}
	if coreerrors.CodeOf(err) != string(coreerrors.CodeBlobMACVerificationFailed) {
		t.Fatalf("code = %q", coreerrors.CodeOf(err))
	}
}

func TestVerifyBlobPayload_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := VerifyBlobPayload([]byte(`{`), testKeyHex)
	if err == nil {
		t.Fatal("expected json error")
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("expected json.SyntaxError, got %v", err)
	}
}

func TestSignRequest_CanonicalBodyLineEndingsAffectSignature(t *testing.T) {
	t.Parallel()
	opts := SignOptions{
		Now:   time.Unix(99, 0).UTC(),
		Nonce: "00112233445566778899aabb",
	}
	a, err := SignRequest(testKeyHex, "dorsalmail", "POST", "/x", []byte("a\nb"), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignRequest(testKeyHex, "dorsalmail", "POST", "/x", []byte("a\r\nb"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if a.Signature == b.Signature {
		t.Fatal("signatures must differ when body bytes differ")
	}
}
