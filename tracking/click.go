// Package tracking provides product-neutral primitives for HMAC-signed
// click and pixel tracking URLs. The signature binds both the email ID
// AND the redirect target so an attacker who captures a tracking URL
// cannot mutate `?u=` to point elsewhere — the canonical preimage in
// IssueClickURL/VerifyClickRequest closes the SRV-P0-1 open-redirect.
//
// PII contract: identifier-only input. The target URL is hashed
// (sha256) before being mixed into the HMAC preimage; the URL itself is
// never stored on the server. The email ID is an opaque UUID.
package tracking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// ClickDomainSep separates click-token preimages from any other HMAC use
// of the same key. The literal value is part of the wire contract — do
// not change without bumping the version.
const ClickDomainSep = "dorsal-tracking-click-v1"

// PixelDomainSep is the equivalent separator for pixel-open tokens.
const PixelDomainSep = "dorsal-tracking-pixel-v1"

// MinHMACTagBytes is the minimum HMAC key length we accept. 16 bytes
// (128 bits) sits above the NIST SP 800-107 80-bit floor and matches
// AES-CMAC guidance — the strictest common recommendation. Keys shorter
// than this are rejected at issue/verify time.
const MinHMACTagBytes = 16

// Version is the only token version this package emits or accepts.
// A future rotation must add a new const and a new branch in
// VerifyClickRequest; we do not silently parse old versions.
const Version = "v1"

// ClickToken is the parsed shape of a token. Returned by callers that
// need access to the raw fields; most callers only need the email ID
// from VerifyClickRequest.
type ClickToken struct {
	Version    string
	EmailID    uuid.UUID
	TargetHash []byte
}

// ErrInvalidKey is returned when the HMAC key is missing, non-hex, or
// shorter than MinHMACTagBytes.
var ErrInvalidKey = errors.New("tracking: invalid HMAC key")

// ErrInvalidToken is returned when the token shape, signature, or
// payload does not match what IssueClickURL would produce for this
// (emailID, target, key) triple.
var ErrInvalidToken = errors.New("tracking: invalid token")

func decodeKey(keyHex string) ([]byte, error) {
	if keyHex == "" {
		return nil, ErrInvalidKey
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(key) < MinHMACTagBytes {
		return nil, ErrInvalidKey
	}
	return key, nil
}

// clickPreimage builds the HMAC preimage. Layout is fixed by the test
// vectors at server-core/vectors/testdata/click_v1.json — any change
// here MUST update the vectors or cross-product verification breaks.
func clickPreimage(emailID uuid.UUID, target string) []byte {
	h := sha256.Sum256([]byte(target))
	parts := [][]byte{
		[]byte(ClickDomainSep),
		{0x00},
		[]byte(Version),
		{0x00},
		emailID[:],
		{0x00},
		h[:],
	}
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// pixelPreimage is the equivalent for pixel tokens (no target).
func pixelPreimage(emailID uuid.UUID) []byte {
	parts := [][]byte{
		[]byte(PixelDomainSep),
		{0x00},
		[]byte(Version),
		{0x00},
		emailID[:],
	}
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func computeMAC(keyHex string, preimage []byte) (string, error) {
	key, err := decodeKey(keyHex)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(preimage)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// IssueClickURL returns a click-tracking URL whose token binds emailID
// and target so any mutation to ?u= invalidates the signature.
//
// The returned URL has the form:
//
//	{publicBaseURL}/v1/tracking/click/{token}?u={target}
//
// where {token} = "v1.{base64url(emailID)}.{hex(hmac_sha256_full)}".
// The target is URL-encoded but the HMAC binds the *unencoded* target
// so encoding flips don't break verification.
func IssueClickURL(emailID uuid.UUID, target string, keyHex string, publicBaseURL string) (string, error) {
	tok, err := issueToken(emailID, target, keyHex, ClickDomainSep)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(publicBaseURL, "/")
	return base + "/v1/tracking/click/" + tok + "?u=" + url.QueryEscape(target), nil
}

// IssuePixelURL returns a pixel URL using the pixel domain separator.
func IssuePixelURL(emailID uuid.UUID, keyHex string, publicBaseURL string) (string, error) {
	tok, err := issueToken(emailID, "", keyHex, PixelDomainSep)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(publicBaseURL, "/")
	return base + "/v1/tracking/pixel/" + tok, nil
}

func issueToken(emailID uuid.UUID, target, keyHex, sep string) (string, error) {
	if _, err := decodeKey(keyHex); err != nil {
		return "", err
	}
	var preimage []byte
	if sep == ClickDomainSep {
		preimage = clickPreimage(emailID, target)
	} else {
		preimage = pixelPreimage(emailID)
	}
	sig, err := computeMAC(keyHex, preimage)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(emailID[:])
	return fmt.Sprintf("%s.%s.%s", Version, payload, sig), nil
}

// VerifyClickRequest verifies a click token against the supplied
// target. Returns the embedded email ID on success.
//
// The caller MUST pass the unescaped target string — the same value
// that was passed to IssueClickURL. Mismatched targets return
// ErrInvalidToken; that is the SRV-P0-1 fix.
func VerifyClickRequest(rawToken, providedTarget string, keyHex string) (uuid.UUID, error) {
	id, sig, err := parseToken(rawToken)
	if err != nil {
		return uuid.UUID{}, err
	}
	expect, err := computeMAC(keyHex, clickPreimage(id, providedTarget))
	if err != nil {
		return uuid.UUID{}, err
	}
	if !hmac.Equal([]byte(sig), []byte(expect)) {
		return uuid.UUID{}, ErrInvalidToken
	}
	return id, nil
}

// VerifyPixelRequest is the equivalent for pixel tokens.
func VerifyPixelRequest(rawToken string, keyHex string) (uuid.UUID, error) {
	id, sig, err := parseToken(rawToken)
	if err != nil {
		return uuid.UUID{}, err
	}
	expect, err := computeMAC(keyHex, pixelPreimage(id))
	if err != nil {
		return uuid.UUID{}, err
	}
	if !hmac.Equal([]byte(sig), []byte(expect)) {
		return uuid.UUID{}, ErrInvalidToken
	}
	return id, nil
}

func parseToken(raw string) (uuid.UUID, string, error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 || parts[0] != Version {
		return uuid.UUID{}, "", ErrInvalidToken
	}
	idBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(idBytes) != 16 {
		return uuid.UUID{}, "", ErrInvalidToken
	}
	var id uuid.UUID
	copy(id[:], idBytes)
	if len(parts[2]) != 64 { // 32-byte hex tag
		return uuid.UUID{}, "", ErrInvalidToken
	}
	return id, parts[2], nil
}
