// Package auth implements the server-core request-signing contract used for
// server→enclave calls, per-org transit-hash-key derivation, principal-hash
// derivation, and secure-blob integrity MAC primitives.
//
// Canonical signing bytes (6 lines): product\nmethod\npath\ntimestamp\nnonce\nbody.
// Nonces are 24 lowercase hex characters (12 random bytes). Cross-language
// reference vectors live in server-core/vectors/testdata.
//
// PII contract: every exported primitive documents the expected input class
// (opaque / ciphertext-only / identifier-only / plaintext-with-warning). The
// Go server that imports this package MUST never pass plaintext PII through a
// primitive whose contract forbids it. See the "PII contract:" doc-line on
// each exported symbol below.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	coreerrors "github.com/erron-ai/server-core/errors"
)

const (
	HeaderTimestamp     = "X-Vault-Timestamp"
	HeaderNonce         = "X-Vault-Nonce"
	HeaderSignature     = "X-Vault-Sig"
	nonceByteLength     = 12
	defaultSkewWindow   = 5 * time.Minute
	blobMACFieldName    = "blob_mac"
	hexEncodedNonceSize = nonceByteLength * 2
)

// productIDPattern locks the reserved product namespace. Future products
// (dorsalmail, dorsalforms, dorsalfiles, dorsalsocket, dorsalchat) register
// under this grammar without needing a central registry.
var productIDPattern = regexp.MustCompile(`^dorsal[a-z0-9]{2,24}$`)

// SignOptions allows callers to inject a fixed clock and/or nonce for
// deterministic test signing. Leave zero-valued in production.
type SignOptions struct {
	Now   time.Time
	Nonce string
}

// SignedRequest is the output of SignRequest: the wire-ready timestamp/nonce/
// signature triple plus the canonical bytes that were signed.
type SignedRequest struct {
	Timestamp int64
	Nonce     string
	Signature string
	Canonical []byte
}

// ParsedHeaders is the result of ParseHeaders — already-validated timestamp/
// nonce/signature values drawn from an inbound HTTP request.
type ParsedHeaders struct {
	Timestamp int64
	Nonce     string
	Signature string
}

// ValidateProductID rejects any product string that does not match the
// reserved `dorsal[a-z0-9]{2,24}` grammar. Sign/verify primitives call it
// before producing canonical bytes so an empty or misspelled product can
// never silently sign or verify as a different product.
//
// PII contract: identifier-only input.
func ValidateProductID(product string) error {
	if product == "" {
		return coreerrors.New(coreerrors.CodeInvalidField, "product id required")
	}
	if !productIDPattern.MatchString(product) {
		return coreerrors.New(coreerrors.CodeInvalidField, "invalid product id")
	}
	return nil
}

// CanonicalRequest constructs the six-line signing preimage.
// Format: product\nmethod\npath\ntimestamp\nnonce\nbody.
//
// PII contract: opaque input — `body` is the outbound request body bytes.
// Callers MUST NOT inject plaintext PII into the body; use SDK-produced
// ciphertext fields and identifier hashes only.
// ZK note: the canonical preimage is HMAC-signed; any plaintext PII pushed in
// by a caller would be carried across the MAC boundary as plaintext.
func CanonicalRequest(product, method, path string, timestamp int64, nonce string, body []byte) []byte {
	var canonical []byte
	canonical = append(canonical, []byte(product)...)
	canonical = append(canonical, '\n')
	canonical = append(canonical, []byte(method)...)
	canonical = append(canonical, '\n')
	canonical = append(canonical, []byte(path)...)
	canonical = append(canonical, '\n')
	canonical = append(canonical, []byte(strconv.FormatInt(timestamp, 10))...)
	canonical = append(canonical, '\n')
	canonical = append(canonical, []byte(nonce)...)
	canonical = append(canonical, '\n')
	canonical = append(canonical, body...)
	return canonical
}

// SignRequest produces a SignedRequest over the canonical preimage. The
// caller supplies the product string; ValidateProductID gates it first.
//
// PII contract: opaque input. See CanonicalRequest.
func SignRequest(hexKey, product, method, path string, body []byte, options SignOptions) (SignedRequest, error) {
	if err := ValidateProductID(product); err != nil {
		return SignedRequest{}, err
	}
	keyBytes, err := decodeHexKey(hexKey)
	if err != nil {
		return SignedRequest{}, err
	}

	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonce := options.Nonce
	if nonce == "" {
		nonce, err = generateNonce()
		if err != nil {
			return SignedRequest{}, err
		}
	}
	if err := ValidateNonce(nonce); err != nil {
		return SignedRequest{}, err
	}

	timestamp := now.Unix()
	canonical := CanonicalRequest(product, method, path, timestamp, nonce, body)
	signature := signCanonical(keyBytes, canonical)
	return SignedRequest{
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
		Canonical: canonical,
	}, nil
}

// SignedHeaders is a convenience wrapper that returns ready-to-send HTTP
// headers plus the SignedRequest value for callers that want both.
//
// PII contract: opaque input. See CanonicalRequest.
func SignedHeaders(hexKey, product, method, path string, body []byte, options SignOptions) (http.Header, SignedRequest, error) {
	signed, err := SignRequest(hexKey, product, method, path, body, options)
	if err != nil {
		return nil, SignedRequest{}, err
	}
	headers := make(http.Header)
	headers.Set(HeaderTimestamp, strconv.FormatInt(signed.Timestamp, 10))
	headers.Set(HeaderNonce, signed.Nonce)
	headers.Set(HeaderSignature, signed.Signature)
	return headers, signed, nil
}

// ParseHeaders extracts and validates the three vault-signature headers from
// an inbound request. It does NOT verify the signature (VerifySignature does).
func ParseHeaders(headers http.Header) (ParsedHeaders, error) {
	timestamp := strings.TrimSpace(headers.Get(HeaderTimestamp))
	if timestamp == "" {
		return ParsedHeaders{}, coreerrors.New(coreerrors.CodeMissingTimestamp, "")
	}
	nonce := strings.TrimSpace(headers.Get(HeaderNonce))
	if nonce == "" {
		return ParsedHeaders{}, coreerrors.New(coreerrors.CodeMissingNonce, "")
	}
	signature := strings.TrimSpace(headers.Get(HeaderSignature))
	if signature == "" {
		return ParsedHeaders{}, coreerrors.New(coreerrors.CodeMissingSignature, "")
	}

	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ParsedHeaders{}, coreerrors.Wrap(coreerrors.CodeInvalidField, "invalid X-Vault-Timestamp", err)
	}
	if err := ValidateNonce(nonce); err != nil {
		return ParsedHeaders{}, err
	}
	if _, err := hex.DecodeString(signature); err != nil {
		return ParsedHeaders{}, coreerrors.Wrap(coreerrors.CodeInvalidSignature, "invalid X-Vault-Sig", err)
	}
	return ParsedHeaders{
		Timestamp: parsedTimestamp,
		Nonce:     nonce,
		Signature: strings.ToLower(signature),
	}, nil
}

// ValidateTimestamp enforces a symmetric skew window around `now`.
func ValidateTimestamp(timestamp int64, now time.Time, skewWindow time.Duration) error {
	if skewWindow <= 0 {
		skewWindow = defaultSkewWindow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ts := time.Unix(timestamp, 0)
	if ts.Before(now.Add(-skewWindow)) || ts.After(now.Add(skewWindow)) {
		return coreerrors.New(coreerrors.CodeInvalidField, "stale request timestamp")
	}
	return nil
}

// ValidateNonce enforces the hex-24 nonce contract: exactly 24 lowercase hex
// characters decoding to 12 random bytes. Any other shape is rejected.
func ValidateNonce(nonce string) error {
	if len(nonce) != hexEncodedNonceSize {
		return coreerrors.New(coreerrors.CodeInvalidField, "invalid X-Vault-Nonce")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return coreerrors.Wrap(coreerrors.CodeInvalidField, "invalid X-Vault-Nonce", err)
	}
	return nil
}

// VerifySignature recomputes the canonical bytes from the caller-supplied
// product/method/path/body and the parsed timestamp+nonce, then
// constant-time-compares against the parsed signature.
//
// PII contract: opaque input. See CanonicalRequest.
func VerifySignature(hexKey, product, method, path string, body []byte, parsed ParsedHeaders) error {
	if err := ValidateProductID(product); err != nil {
		return err
	}
	keyBytes, err := decodeHexKey(hexKey)
	if err != nil {
		return err
	}
	canonical := CanonicalRequest(product, method, path, parsed.Timestamp, parsed.Nonce, body)
	expected := signCanonical(keyBytes, canonical)
	if !hmac.Equal([]byte(expected), []byte(parsed.Signature)) {
		return coreerrors.New(coreerrors.CodeInvalidField, "invalid signature")
	}
	return nil
}

// DeriveTransitHashKey returns the HMAC-SHA256 of the org UUID (binary form)
// under the master key. The result is the per-org key handed to the SDK so
// clients can compute transit-hash addresses locally without ever disclosing
// the master.
//
// PII contract: identifier-only input — `orgID` is a UUID, never PII.
func DeriveTransitHashKey(masterHex string, orgID uuid.UUID) ([]byte, error) {
	masterKey, err := decodeHexKey(masterHex)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, masterKey)
	orgBytes, err := orgID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("org id marshal: %w", err)
	}
	_, _ = mac.Write(orgBytes)
	return mac.Sum(nil), nil
}

// DerivePrincipalHash computes HMAC-SHA256(per-org-key, lower(trim(principal))).
// "Principal" is product-neutral: for Mail it is a recipient address; for
// Forms a submitter identifier; for Chat a handle. Lowercase+trim
// normalization is the only canonicalization.
//
// PII contract: PLAINTEXT-INPUT — the `principal` is plaintext. This primitive
// is only safe to call when (a) the principal comes from an external source
// that has already disclosed it (e.g. an SES SNS webhook processed inside the
// enclave, NEVER on the Go server), OR (b) it is a test-mode literal. NEVER
// call with a principal sourced from a client request body on the Go server
// in a ZK product — hash derivation must happen in the enclave. See the
// zero-knowledge invariant in plan §1.6.
// ZK note: a compromised Go server calling this with the master key and a
// plaintext principal can reverse stored hashes. Keep custody in the enclave.
func DerivePrincipalHash(masterHex string, orgID uuid.UUID, principal string) ([]byte, error) {
	orgKey, err := DeriveTransitHashKey(masterHex, orgID)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, orgKey)
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(principal))))
	return mac.Sum(nil), nil
}

// ComputeBlobMAC returns the hex HMAC-SHA256 of `data` under the supplied key.
// Used to MAC secure-send blob JSON before persisting.
//
// PII contract: ciphertext-only input — `data` is SDK-encrypted bytes or
// canonicalized JSON whose values are SDK-produced ciphertext. Callers MUST
// NOT pass plaintext map values.
func ComputeBlobMAC(hexKey string, data []byte) (string, error) {
	keyBytes, err := decodeHexKey(hexKey)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyBlobPayload JSON-decodes `raw`, then delegates to VerifyBlobMap.
//
// PII contract: ciphertext-only input. See ComputeBlobMAC.
func VerifyBlobPayload(raw []byte, hexKey string) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return VerifyBlobMap(payload, hexKey)
}

// VerifyBlobMap verifies the `blob_mac` field of a map over its non-MAC
// entries canonicalized via json.Marshal (keys sorted). Returns the cloned
// payload with `blob_mac` removed on success.
//
// PII contract: ciphertext-only input. Callers MUST NOT pass plaintext map
// values (see zero-knowledge invariant).
func VerifyBlobMap(payload map[string]any, hexKey string) (map[string]any, error) {
	cloned := cloneMap(payload)
	rawMAC, ok := cloned[blobMACFieldName]
	if !ok {
		return nil, coreerrors.New(
			coreerrors.CodeBlobMACMissing,
			"blob_mac missing: blob may be tampered or pre-dates MAC enforcement",
		)
	}
	storedMAC, ok := rawMAC.(string)
	if !ok {
		return nil, coreerrors.New(coreerrors.CodeInvalidField, "blob_mac must be a JSON string")
	}
	if strings.TrimSpace(storedMAC) == "" {
		return nil, coreerrors.New(
			coreerrors.CodeBlobMACMissing,
			"blob_mac missing: blob may be tampered or pre-dates MAC enforcement",
		)
	}
	delete(cloned, blobMACFieldName)
	canonical, err := json.Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("blob canonicalization failed: %w", err)
	}
	expected, err := ComputeBlobMAC(hexKey, canonical)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(expected), []byte(strings.TrimSpace(storedMAC))) {
		return nil, coreerrors.New(
			coreerrors.CodeBlobMACVerificationFailed,
			"blob_mac verification failed: blob integrity compromised",
		)
	}
	return cloned, nil
}

func decodeHexKey(hexKey string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, coreerrors.Wrap(coreerrors.CodeInvalidField, "invalid hex key", err)
	}
	if len(keyBytes) != 32 {
		return nil, coreerrors.New(coreerrors.CodeInvalidField, fmt.Sprintf("hex key must decode to 32 bytes, got %d", len(keyBytes)))
	}
	return keyBytes, nil
}

func signCanonical(key, canonical []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

func generateNonce() (string, error) {
	var nonce [nonceByteLength]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

func cloneMap(payload map[string]any) map[string]any {
	cloned := make(map[string]any, len(payload))
	for key, value := range payload {
		cloned[key] = value
	}
	return cloned
}
