package attest

import (
	"crypto/hmac"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corecfg "github.com/erron-ai/server-core/config"
)

// DefaultAttestationMaxAge is the maximum age for an NSM attestation document
// (wall-clock skew vs server time).
const DefaultAttestationMaxAge = 10 * time.Minute

// nitroRootPEM holds the AWS Nitro Enclaves root certificate(s). It
// is shipped as a server-core artefact (not a runtime env var) so
// rotation lives behind a code review. Empty placeholder until the
// Nitro root pin is committed via a follow-up PR; ParseAndVerify will
// refuse to chain-verify until non-empty.
//
//go:embed nitro-root.pem
var nitroRootPEM []byte

// PCRSet maps a PCR index to its measurement bytes. Each enclave
// image produces a deterministic set of PCRs (PCR0 = image, PCR1 =
// kernel/initrd, PCR2 = application), so the allowlist is a slice of
// (image-id) PCRSets the operator pre-pins via config.
type PCRSet map[int][]byte

// Measurements is the verified output of ParseAndVerify.
type Measurements struct {
	PCRs     PCRSet
	ModuleID string
	Digest   string
	IssuedAt time.Time
}

// Sentinel errors returned by ParseAndVerify so callers can branch
// without string matching.
var (
	ErrNoAllowlist = errors.New("attest: empty PCR allowlist not permitted in production")
	// ErrChainUnverified is returned when the embedded root CA is missing or
	// chain building fails before COSE verification (distinct from ErrMalformedDoc).
	ErrChainUnverified = errors.New("attest: NSM certificate chain could not be verified against embedded root")
	ErrNonceMismatch   = errors.New("attest: nonce did not match")
	ErrPCRMismatch     = errors.New("attest: PCRs did not match any allowlisted set")
	ErrTooOld          = errors.New("attest: NSM document older than maxAge")
	ErrMalformedDoc    = errors.New("attest: malformed NSM document")
)

// nsmDocOuter is the minimal client-shaped envelope we accept while
// the production COSE verifier lands. The enclave-side serializer
// emits a JSON envelope with these fields in dev/mock mode; in real
// Nitro mode the payload is COSE_Sign1+CBOR and verifying it requires
// a Nitro root + CBOR parser (deferred — see ErrChainUnverified).
type nsmDocOuter struct {
	ModuleID  string         `json:"module_id"`
	Digest    string         `json:"digest"`
	Timestamp int64          `json:"timestamp"`
	Nonce     []byte         `json:"nonce"`
	PCRs      map[int][]byte `json:"pcrs"`
}

// ParseAndVerify accepts an NSM attestation document, applies the
// product-supplied allowlist + nonce + age gates, and returns the
// extracted measurements on success.
//
// Production policy:
//   - `allow` MUST be non-empty (otherwise ErrNoAllowlist).
//   - The embedded Nitro root cert MUST be non-empty (otherwise
//     ErrChainUnverified is returned to make the missing pin loud).
//
// Dev/mock policy:
//   - `allow` may be empty.
//   - The mock NSM envelope (nsmDocOuter) is accepted directly.
//
// In both modes, the document's nonce MUST match `expectedNonce` via
// constant-time compare, the timestamp MUST be within `maxAge` of
// `now`, and the PCRs MUST match at least one entry in `allow`
// (when `allow` is non-empty).
// verifyNitroCOSEFunc is the production COSE verifier; tests may swap it to
// assert policy outcomes without shipping golden attestation blobs.
var verifyNitroCOSEFunc = verifyNitroCOSE

func ParseAndVerify(doc, expectedNonce []byte, allow []PCRSet, maxAge time.Duration, now time.Time) (Measurements, error) {
	if corecfg.InProduction() {
		if len(allow) == 0 {
			return Measurements{}, ErrNoAllowlist
		}
		if len(nitroRootPEM) == 0 {
			return Measurements{}, ErrChainUnverified
		}
		return verifyNitroCOSEFunc(doc, nitroRootPEM, expectedNonce, allow, maxAge, now)
	}

	var outer nsmDocOuter
	if err := json.Unmarshal(doc, &outer); err != nil {
		return Measurements{}, fmt.Errorf("%w: %v", ErrMalformedDoc, err)
	}
	if len(outer.PCRs) == 0 {
		return Measurements{}, ErrMalformedDoc
	}
	if !hmac.Equal(outer.Nonce, expectedNonce) {
		return Measurements{}, ErrNonceMismatch
	}
	issued := time.Unix(outer.Timestamp, 0).UTC()
	if maxAge > 0 && now.Sub(issued) > maxAge {
		return Measurements{}, ErrTooOld
	}
	if len(allow) > 0 {
		if !pcrMatchesAny(outer.PCRs, allow) {
			return Measurements{}, ErrPCRMismatch
		}
	}
	return Measurements{
		PCRs:     PCRSet(outer.PCRs),
		ModuleID: outer.ModuleID,
		Digest:   outer.Digest,
		IssuedAt: issued,
	}, nil
}

func pcrMatchesAny(got map[int][]byte, allow []PCRSet) bool {
	for _, want := range allow {
		if pcrSetEqual(got, want) {
			return true
		}
	}
	return false
}

func pcrSetEqual(a map[int][]byte, b PCRSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if !hmac.Equal(av, bv) {
			return false
		}
	}
	return true
}
