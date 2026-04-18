// Package replay implements idempotency fingerprinting and stored-row
// classification used across all server-core-consuming products. Any verb
// that needs idempotent first-seen semantics plugs into this package — it is
// explicitly product-neutral.
//
// PII contract: ciphertext/identifier-only input. The fingerprinted body MUST
// contain only SDK-produced ciphertext plus identifier hashes. Callers MUST
// reject plaintext PII fields in the request BEFORE fingerprinting (see
// plan §6.1 transit plaintext-rejection gate for the Mail gate).
package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
)

// Outcome is the classification result of an idempotency-cache lookup.
type Outcome string

const (
	OutcomeFirstClaim Outcome = "first_claim"
	OutcomeCached     Outcome = "cached"
	OutcomeConflict   Outcome = "conflict"
	OutcomeInFlight   Outcome = "in_flight"
	OutcomeNoState    Outcome = "no_state"
)

// Decision is the caller-facing result of ClassifyExisting.
type Decision struct {
	Outcome Outcome
	Status  int
	Body    json.RawMessage
}

// FingerprintBody returns SHA-256(raw). The bytes SHOULD be the canonical
// request body; callers MUST gate plaintext PII rejection upstream.
//
// PII contract: ciphertext/identifier-only input. See package doc.
func FingerprintBody(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// ClassifyExisting compares the in-flight fingerprint against the stored row
// and returns the idempotency decision for the handler to act on.
func ClassifyExisting(requestFingerprint, storedFingerprint []byte, storedStatus int, storedBody []byte) Decision {
	if len(storedFingerprint) == 0 {
		return Decision{Outcome: OutcomeNoState}
	}
	if len(requestFingerprint) > 0 && !bytes.Equal(storedFingerprint, requestFingerprint) {
		return Decision{Outcome: OutcomeConflict}
	}
	if len(storedBody) > 0 {
		return Decision{
			Outcome: OutcomeCached,
			Status:  storedStatus,
			Body:    json.RawMessage(storedBody),
		}
	}
	return Decision{Outcome: OutcomeInFlight}
}
