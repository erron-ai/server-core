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

func TestParseAndVerify_Dev_MaxAgeZeroSkipsTooOld(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	nonce := []byte{1, 2, 3, 4, 5}
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour).Unix()
	doc := mockDoc(nonce, old, map[int][]byte{0: {0xaa}})
	_, err := ParseAndVerify(doc, nonce, nil, 0, now)
	if err != nil {
		t.Fatalf("maxAge=0 must not return ErrTooOld: %v", err)
	}
}

func TestParseAndVerify_Dev_NilAllowSkipsPCRMatching(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	nonce := []byte{1, 2, 3, 4, 5}
	now := time.Now().UTC()
	doc := mockDoc(nonce, now.Unix(), map[int][]byte{0: {0xde}})
	_, err := ParseAndVerify(doc, nonce, nil, time.Minute, now)
	if err != nil {
		t.Fatalf("nil allowlist must skip PCR check: %v", err)
	}
}

func TestParseAndVerify_Production_PCRMismatch(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	prev := verifyNitroCOSEFunc
	verifyNitroCOSEFunc = func([]byte, []byte, []byte, []PCRSet, time.Duration, time.Time) (Measurements, error) {
		return Measurements{}, ErrPCRMismatch
	}
	t.Cleanup(func() { verifyNitroCOSEFunc = prev })

	allow := []PCRSet{{0: {0xaa}}}
	_, err := ParseAndVerify([]byte("stub-cose"), []byte("nonce"), allow, time.Minute, time.Now())
	if err == nil {
		t.Fatal("expected ErrPCRMismatch")
	}
	if !errors.Is(err, ErrPCRMismatch) {
		t.Fatalf("want ErrPCRMismatch, got %v", err)
	}
}

func TestErrorCode_Table(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{ErrNoAllowlist, "attest_no_allowlist"},
		{ErrChainUnverified, "attest_chain_unverified"},
		{ErrNonceMismatch, "attest_nonce_mismatch"},
		{ErrPCRMismatch, "attest_pcr_mismatch"},
		{ErrTooOld, "attest_too_old"},
		{ErrMalformedDoc, "attest_malformed_doc"},
	}
	for _, tc := range cases {
		if got := ErrorCode(tc.err); got != tc.want {
			t.Fatalf("ErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
