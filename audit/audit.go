// Package audit implements the product-neutral tamper-evident audit-log
// primitives used by server-core consumers: path redaction, event
// normalization, and SHA-256 entry-hash chaining.
//
// PII contract: ciphertext/identifier-only input. Audit rows MUST NOT contain
// recipient addresses, subject lines, bodies, OTP codes, raw tokens, or any
// other plaintext PII. Callers MUST pass pre-redacted paths, HMAC-fingerprinted
// tokens, and ECIES-encrypted IP columns. `EntryHash` SHA-256s the preimage;
// any plaintext PII passed in would land in the audit chain and be readable by
// anyone with DB access.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Event is the product-neutral audit row. Consumer products (Mail, Forms,
// Files, Chat, Socket) all funnel into this structure; product-specific
// path/route redaction happens via the Redactor chain passed to RedactPath.
type Event struct {
	EventID          uuid.UUID
	EventType        string
	RequestID        string
	OrgID            *uuid.UUID
	APIKeyID         *uuid.UUID
	ActorType        string
	ActorID          string
	ResourceType     string
	ResourceID       string
	Action           string
	Outcome          string
	ErrorCode        string
	Method           string
	Path             string
	RoutePattern     string
	StatusCode       int
	IPHMAC           []byte
	IPOrgECIES       []byte
	TokenFingerprint string
	CreatedAt        time.Time
}

// Redactor inspects a URL path and, if it matches a product-specific
// sensitive pattern, returns the redacted form and true. If it does not
// match, it returns the original path and false. Redactors are pure functions;
// no I/O, no state.
type Redactor func(path string) (string, bool)

// RedactPath runs the supplied redactor chain in order and returns the first
// match. If no redactor matches, the raw path is returned unchanged.
// server-core ships zero built-in redactor literals — each consuming product
// registers its own redactor table.
//
// PII contract: callers MUST redact path segments that could contain tokens,
// emails, subjects, or OTP codes before passing the result into EntryHash or
// any storage path.
func RedactPath(path string, redactors ...Redactor) string {
	for _, r := range redactors {
		if out, ok := r(path); ok {
			return out
		}
	}
	return path
}

// NormalizeEvent fills defaults for an Event before hashing or storage.
func NormalizeEvent(in Event) Event {
	if in.EventID == uuid.Nil {
		in.EventID = uuid.New()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	} else {
		in.CreatedAt = in.CreatedAt.UTC()
	}
	if in.EventType == "" {
		in.EventType = "http.request"
	}
	if in.ActorType == "" {
		in.ActorType = "unknown"
	}
	if in.Outcome == "" {
		in.Outcome = "unknown"
	}
	return in
}

// EntryHash returns the SHA-256 hex digest of the event preimage, chained to
// prevHash. The preimage format is pinned by the golden vector at
// server-core/vectors/testdata/audit_entry_hash.json — any change to the
// format string MUST update the vector or tests fail.
//
// PII contract: ciphertext/identifier-only input. See package doc.
func EntryHash(in Event, prevHash string) string {
	in = NormalizeEvent(in)
	orgStr := ""
	if in.OrgID != nil {
		orgStr = in.OrgID.String()
	}
	apiKeyStr := ""
	if in.APIKeyID != nil {
		apiKeyStr = in.APIKeyID.String()
	}
	raw := fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%x|%x|%v|%v|%v|%v|%s|%v|%v",
		in.EventID.String(),
		in.EventType,
		in.CreatedAt.Format(time.RFC3339Nano),
		orgStr,
		apiKeyStr,
		in.ActorType,
		in.Method,
		in.StatusCode,
		in.Path,
		in.RoutePattern,
		in.Outcome,
		in.ErrorCode,
		in.RequestID,
		in.TokenFingerprint,
		in.IPHMAC,
		in.IPOrgECIES,
		nilIfEmpty(in.ActorID),
		nilIfEmpty(in.ResourceType),
		nilIfEmpty(in.ResourceID),
		nilIfEmpty(in.Action),
		prevHash,
		nilIfEmpty(in.RequestID),
		nilIfEmpty(in.ErrorCode),
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Preimage exposes the exact byte preimage used by EntryHash. Test-only; the
// golden vector at server-core/vectors/testdata/audit_entry_hash.json pins
// this preimage so format drift fails loudly.
func Preimage(in Event, prevHash string) []byte {
	in = NormalizeEvent(in)
	orgStr := ""
	if in.OrgID != nil {
		orgStr = in.OrgID.String()
	}
	apiKeyStr := ""
	if in.APIKeyID != nil {
		apiKeyStr = in.APIKeyID.String()
	}
	return []byte(fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%x|%x|%v|%v|%v|%v|%s|%v|%v",
		in.EventID.String(),
		in.EventType,
		in.CreatedAt.Format(time.RFC3339Nano),
		orgStr,
		apiKeyStr,
		in.ActorType,
		in.Method,
		in.StatusCode,
		in.Path,
		in.RoutePattern,
		in.Outcome,
		in.ErrorCode,
		in.RequestID,
		in.TokenFingerprint,
		in.IPHMAC,
		in.IPOrgECIES,
		nilIfEmpty(in.ActorID),
		nilIfEmpty(in.ResourceType),
		nilIfEmpty(in.ResourceID),
		nilIfEmpty(in.Action),
		prevHash,
		nilIfEmpty(in.RequestID),
		nilIfEmpty(in.ErrorCode),
	))
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
