// Package config holds cross-product helpers for production-mode invariants.
// Every product's config loader enforces "strict in production" guardrails
// (TLS on Postgres and Redis, no plaintext transports, no test hooks). These
// helpers centralise the policy so DorsalForms / DorsalFiles / DorsalChat can
// adopt the same gate without re-implementing the string parsing.
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ParseBoolExplicit parses an opt-out flag with zero tolerance for typos.
//
// `"1"` and `"true"` (case-insensitive) mean "explicitly opted out".
// `""` (unset) means "use the default (still strict)".
// Every other value — including `"false"`, `"0"`, `"no"`, `"off"`, typos,
// empty-after-trim whitespace — is rejected so a misspelled flag never
// silently disables a production guardrail.
//
// Returns `(parsed, ok)`. `ok` is false iff the string is not one of the
// recognised forms above.
func ParseBoolExplicit(raw string) (parsed bool, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false, true
	}
	switch strings.ToLower(trimmed) {
	case "1", "true":
		return true, true
	default:
		return false, false
	}
}

// RequireStrict reports whether the caller should keep a production-mode
// invariant ON. The invariant stays on unless the named env var is
// explicitly set to `"1"` or `"true"` — any other non-empty value (typo,
// `"false"`, `"0"`, …) is an error and will cause the caller to refuse to
// boot via the returned non-nil error.
//
// The typical usage pattern in a product:
//
//	strict, err := corecfg.RequireStrict("SKIP_PROD_TLS_CHECKS")
//	if err != nil { return err }
//	if strict { // enforce TLS }
func RequireStrict(envKey string) (bool, error) {
	raw := os.Getenv(envKey)
	optedOut, ok := ParseBoolExplicit(raw)
	if !ok {
		return false, fmt.Errorf(
			"%s: unrecognised value %q (use \"1\", \"true\", or unset to keep strict mode on)",
			envKey, raw,
		)
	}
	return !optedOut, nil
}

// InProduction reads the ENVIRONMENT env var (case-insensitive) and
// reports whether it equals "production". Centralised so every product
// agrees on the gate string.
func InProduction() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ENVIRONMENT")), "production")
}

// RequireHex returns nil unless InProduction() AND `value` is missing,
// non-hex, or decodes to fewer than `minBytes`. Error messages name
// the env var but NEVER its value (no secret leakage to logs).
func RequireHex(name, value string, minBytes int) error {
	if !InProduction() {
		return nil
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return fmt.Errorf("%s: required in production", name)
	}
	raw, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("%s: must be hex-encoded", name)
	}
	if len(raw) < minBytes {
		return fmt.Errorf("%s: must decode to at least %d bytes", name, minBytes)
	}
	return nil
}

// RequireNonEmpty returns nil unless InProduction() AND `value` is
// empty after trimming. Names the env var but never the value.
func RequireNonEmpty(name, value string) error {
	if !InProduction() {
		return nil
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: required in production", name)
	}
	return nil
}

// RequireEnum returns nil unless InProduction() AND `value` (after
// case-insensitive trim) is not one of `allowed`. The error names
// allowed values so the operator can fix typos quickly.
func RequireEnum(name, value string, allowed ...string) error {
	if !InProduction() {
		return nil
	}
	v := strings.ToLower(strings.TrimSpace(value))
	for _, a := range allowed {
		if v == strings.ToLower(strings.TrimSpace(a)) {
			return nil
		}
	}
	return fmt.Errorf("%s: must be one of %v", name, allowed)
}

// RequirePGURLSSL returns nil unless InProduction() AND the supplied
// Postgres DSN explicitly contains `sslmode=disable`. We accept any
// mode other than `disable` (e.g. `require`, `verify-full`) on the
// theory that the operator already chose the strictness floor.
func RequirePGURLSSL(dsn string) error {
	if !InProduction() {
		return nil
	}
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL: required in production")
	}
	if strings.Contains(strings.ToLower(dsn), "sslmode=disable") {
		return fmt.Errorf("DATABASE_URL: sslmode=disable not allowed in production")
	}
	return nil
}

// RequireRediss returns nil if Redis is unconfigured, or if the URL
// uses the rediss:// scheme. In production a `redis://` (plaintext)
// URL is a hard error.
func RequireRediss(dsn string) error {
	if !InProduction() {
		return nil
	}
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("REDIS_URL: invalid url")
	}
	if !strings.EqualFold(u.Scheme, "rediss") {
		return fmt.Errorf("REDIS_URL: must use rediss:// in production")
	}
	return nil
}
