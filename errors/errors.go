// Package errors defines the stable, machine-readable security error-code
// catalog shared across server-core consumers.
//
// Reserved prefixes (doc-only — codes are registered here as the consuming
// work lands, never invented ad-hoc in callers):
//
//   - frame_*        — streaming / framed-channel errors (Files, Socket, Chat)
//   - stream_*       — long-lived stream lifecycle errors
//   - attest_bundle_*— attestation-bundle parse/verify errors
//
// PII contract: error code strings are identifier-only; messages must never
// embed user data. Callers adding new codes should route PII out of messages
// before the error leaves server-core.
package errors

import (
	"errors"
	"fmt"
)

// Code is a stable machine-readable security error code.
type Code string

const (
	CodeUnauthorized              Code = "unauthorized"
	CodeInvalidJSON               Code = "invalid_json"
	CodeInvalidField              Code = "invalid_field"
	CodeIdempotency               Code = "idempotency"
	CodeIdempotencyConflict       Code = "idempotency_conflict"
	CodeEnclaveError              Code = "enclave_error"
	CodeMissingTimestamp          Code = "missing_timestamp"
	CodeMissingNonce              Code = "missing_nonce"
	CodeMissingSignature          Code = "missing_signature"
	CodeInvalidTimestamp          Code = "invalid_timestamp"
	CodeInvalidNonce              Code = "invalid_nonce"
	CodeInvalidSignature          Code = "invalid_signature"
	CodeStaleTimestamp            Code = "stale_timestamp"
	CodeBlobMACFailed             Code = "blob_mac_failed"
	CodeBlobMACMissing            Code = "blob_mac_missing"
	CodeBlobMACVerificationFailed Code = "blob_mac_verification_failed"
	// CodeEnclaveReauthFailed marks the specific failure mode where the Go
	// server detected a stale `AuthKey` — it retried the enclave request
	// after rebootstrapping and still got a 401. This is distinct from
	// `invalid_otp` (which means a real, user-supplied OTP was rejected)
	// and from `CodeEnclaveError` (generic enclave-side error). The
	// `/unlock` handler branches on it to rotate the auth key and alert
	// ops rather than surfacing a misleading "bad OTP" to the caller.
	CodeEnclaveReauthFailed Code = "enclave_reauth_failed"
)

var messages = map[string]string{
	string(CodeUnauthorized):              "Authentication required. Provide a valid Bearer token.",
	string(CodeInvalidJSON):               "The request body is not valid JSON.",
	string(CodeInvalidField):              "One or more fields contain invalid values.",
	string(CodeIdempotency):               "An idempotency error occurred. Please try again.",
	string(CodeIdempotencyConflict):       "An idempotency key conflict occurred. The same key was used with a different request body.",
	string(CodeEnclaveError):              "The enclave request failed.",
	string(CodeMissingTimestamp):          "The request is missing the enclave timestamp header.",
	string(CodeMissingNonce):              "The request is missing the enclave nonce header.",
	string(CodeMissingSignature):          "The request is missing the enclave signature header.",
	string(CodeInvalidTimestamp):          "The enclave timestamp header is invalid.",
	string(CodeInvalidNonce):              "The enclave nonce header is invalid.",
	string(CodeInvalidSignature):          "The enclave signature is invalid.",
	string(CodeStaleTimestamp):            "The enclave request timestamp is stale.",
	string(CodeBlobMACFailed):             "The secure blob integrity check failed.",
	string(CodeBlobMACMissing):            "The secure blob is missing its integrity MAC.",
	string(CodeBlobMACVerificationFailed): "The secure blob integrity check failed.",
	string(CodeEnclaveReauthFailed):       "The enclave authentication key could not be refreshed.",
}

type Error struct {
	code    Code
	message string
	err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.err == nil || e.err.Error() == "" {
		return e.message
	}
	if e.message == "" {
		return e.err.Error()
	}
	return fmt.Sprintf("%s: %v", e.message, e.err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *Error) Code() string {
	if e == nil {
		return ""
	}
	return string(e.code)
}

func New(code Code, message string) error {
	if message == "" {
		if defaultMessage, ok := Message(string(code)); ok {
			message = defaultMessage
		}
	}
	return &Error{code: code, message: message}
}

func Wrap(code Code, message string, err error) error {
	if err == nil {
		return New(code, message)
	}
	if message == "" {
		if defaultMessage, ok := Message(string(code)); ok {
			message = defaultMessage
		}
	}
	return &Error{code: code, message: message, err: err}
}

func CodeOf(err error) string {
	var securityErr *Error
	if errors.As(err, &securityErr) {
		return securityErr.Code()
	}
	return ""
}

func Message(code string) (string, bool) {
	msg, ok := messages[code]
	return msg, ok
}

func Messages() map[string]string {
	out := make(map[string]string, len(messages))
	for code, message := range messages {
		out[code] = message
	}
	return out
}
