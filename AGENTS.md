# server-core

Shared Go library (`github.com/erron-ai/server-core`, Go 1.25.9) of cross-product server primitives consumed by DorsalMail / DorsalForms / DorsalFiles / DorsalChat. PII contract throughout: inputs are ciphertext or identifier-only; strict-in-production gates refuse silent opt-outs.

Module manifest: [go.mod](go.mod).

## Architecture

A request into a product server traverses these layers: **bootstrap** (once, to get MAC key) → **HTTP middleware stack** (security headers → SSRF dialer → real-IP → rate limit → bearer auth → timeout) → **signed transit** to enclave → **audit log** + **observability** on egress. Errors surface through a stable code catalog; replay/idempotency gates every state-changing handler.

## Packages

### Enclave trust & transit
- [auth/auth.go](auth/auth.go) — Canonical 6-line HMAC-SHA256 server↔enclave request signing; transit/principal-hash key derivation; blob-MAC primitives. `SignRequest`, `VerifySignature`, `DeriveTransitHashKey`, `ComputeBlobMAC`.
- [bootstrap/bootstrap.go](bootstrap/bootstrap.go) — Server→enclave handshake (X25519 → HKDF-SHA256 → AES-256-GCM) delivering the AuthKey. `Session`, `NewSetupRequest`, `DecryptAuthKey`.
- [enclaveauth/rebootstrap.go](enclaveauth/rebootstrap.go) — Singleflight dedupe for concurrent stale-key 401s → single ECDH re-handshake. `Rebootstrapper.Refresh`.
- [attest/verify.go](attest/verify.go), [attest/nitro_verify.go](attest/nitro_verify.go), [attest/attest.go](attest/attest.go) — AWS Nitro Enclave attestation: challenge shape-validation, COSE/CBOR NSM doc parsing against embedded Nitro root, nonce/PCR/max-age gates. `ParseAndVerify`, `ParseChallengeRequest`, `PCRSet`.

### HTTP edge
- [httphdr/security.go](httphdr/security.go) — Defensive security headers for API-only servers (XCTO, XFO, Referrer-Policy, CSP). `SecurityHeaders`.
- [nethttpx/ssrf.go](nethttpx/ssrf.go) — SSRF guard: IP blocklist + post-DNS dialer (anti-rebind) + webhook URL validator; always hard-blocks AWS IMDS. `DialContextForPublic`, `ValidatePublicURL`, `IsBlockedIP`.
- [httpx/timeout.go](httpx/timeout.go) — Request-deadline middleware returning 504 JSON on timeout. `Timeout`.
- [httpauth/bearer.go](httpauth/bearer.go) — Constant-time bearer / header-token middleware; 503s if no token configured (no silent pass). `BearerTokenMiddleware`, `HeaderTokenMiddleware`.
- [ratelimit/iplimiter.go](ratelimit/iplimiter.go), [ratelimit/realip.go](ratelimit/realip.go), [ratelimit/counter.go](ratelimit/counter.go) — Per-IP / per-org token buckets with idle eviction, trusted-proxy XFF real-IP extraction, Redis-first fail-closed distributed counter. `IPLimiter`, `OrgLimiter`, `TrustedProxyRealIP`, `IncrementExpiringCounter`.

### Idempotency & tracking
- [replay/replay.go](replay/replay.go) — Idempotency fingerprinting (SHA-256), attempt-rate counting, stored-row classification with in-memory fallback. `FingerprintBody`, `AttemptCounter`, `ClassifyExisting`, outcomes `FirstClaim`/`Cached`/`Conflict`/`InFlight`.
- [tracking/click.go](tracking/click.go) — HMAC-signed click/pixel URL primitives; signature binds email UUID + SHA-256 of redirect target (closes open-redirect SRV-P0-1). `IssueClickURL`, `IssuePixelURL`, `VerifyClickRequest`.

### Audit, observability, errors
- [audit/audit.go](audit/audit.go), [audit/writer.go](audit/writer.go) — Tamper-evident audit chain: normalized `Event`, path redaction, SHA-256 entry-hash chaining, per-org advisory-locked inserts into `audit_log`. `WriteEntry`, `VerifyChain`, `EntryHash`.
- [observe/safelog/handler.go](observe/safelog/handler.go) — PII-redacting `slog.Handler` wrapper; denylist (email/token/body/subject/…) + email-shaped regex catch-all. `NewRedactingHandler`.
- [errors/errors.go](errors/errors.go) — Stable machine-readable error-code catalog (`CodeUnauthorized`, `CodeInvalidSignature`, `CodeStaleTimestamp`, `CodeBlobMACFailed`, …) with wrapping `Error` type. `New`, `Wrap`, `CodeOf`.

### Config & binaries
- [config/prodgate.go](config/prodgate.go) — "Strict in production" env-var gates: TLS-required PG/Redis, typo-is-error parsing, no silent opt-outs. `RequireStrict`, `RequirePGURLSSL`, `RequireRediss`, `InProduction`.
- [cmd/audit-verify/main.go](cmd/audit-verify/main.go) — Binary `audit-verify`: nightly cron that walks the `audit_log` hash chain per org, non-zero exit on tamper/out-of-order. Delegates to `audit.VerifyChain`. Flags: `--dsn`, `--org`, `--json`, `--timeout`.
