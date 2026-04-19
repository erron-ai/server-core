package attest

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func mockDoc(nonce []byte, ts int64, pcrs map[int][]byte) []byte {
	b, _ := json.Marshal(nsmDocOuter{
		ModuleID:  "mock-module",
		Digest:    "SHA384",
		Timestamp: ts,
		Nonce:     nonce,
		PCRs:      pcrs,
	})
	return b
}

func TestParseAndVerifyDevHappyPath(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	nonce := []byte{1, 2, 3, 4, 5}
	now := time.Now().UTC()
	pcr0 := []byte{0xaa, 0xbb}
	doc := mockDoc(nonce, now.Unix(), map[int][]byte{0: pcr0})
	allow := []PCRSet{{0: pcr0}}
	m, err := ParseAndVerify(doc, nonce, allow, time.Minute, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.ModuleID != "mock-module" {
		t.Fatalf("got %q", m.ModuleID)
	}
}

func TestParseAndVerifyNonceMismatch(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	now := time.Now().UTC()
	doc := mockDoc([]byte{1}, now.Unix(), map[int][]byte{0: {0xaa}})
	if _, err := ParseAndVerify(doc, []byte{2}, nil, time.Minute, now); err == nil {
		t.Fatal("nonce mismatch must fail")
	}
}

func TestParseAndVerifyTooOld(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	now := time.Now().UTC()
	old := now.Add(-2 * time.Minute).Unix()
	doc := mockDoc([]byte{1}, old, map[int][]byte{0: {0xaa}})
	if _, err := ParseAndVerify(doc, []byte{1}, nil, time.Minute, now); err == nil {
		t.Fatal("old doc must fail")
	}
}

func TestParseAndVerifyPCRMismatch(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	now := time.Now().UTC()
	doc := mockDoc([]byte{1}, now.Unix(), map[int][]byte{0: {0xaa}})
	if _, err := ParseAndVerify(doc, []byte{1}, []PCRSet{{0: {0xbb}}}, time.Minute, now); err == nil {
		t.Fatal("PCR mismatch must fail")
	}
}

func TestParseAndVerifyProductionRefusesEmptyAllow(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	if _, err := ParseAndVerify([]byte("ignored"), nil, nil, time.Minute, time.Now()); err == nil {
		t.Fatal("production with empty allowlist must fail")
	} else if err != ErrNoAllowlist {
		t.Fatalf("want ErrNoAllowlist, got %v", err)
	}
}

func TestParseAndVerifyProductionRejectsNonCOSEGarbage(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	allow := []PCRSet{{0: {0xaa}}}
	_, err := ParseAndVerify([]byte("not-valid-cose"), nil, allow, time.Minute, time.Now())
	if err == nil {
		t.Fatal("production must reject non-COSE attestation bytes")
	}
	if !errors.Is(err, ErrMalformedDoc) {
		t.Fatalf("want ErrMalformedDoc, got %v", err)
	}
}
