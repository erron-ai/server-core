# Unit and integration tests to add (server-core)

This document lists **deliberate, high-signal** tests for `github.com/erron-ai/server-core`, prioritized by risk to downstream correctness. It was produced by cross-reviewing package sources, existing `*_test.go` files, and `vectors/testdata/`. Goals:

- Lock **cryptographic and canonicalization** contracts (auth, attest, bootstrap, tracking, audit hashing).
- Lock **security boundaries** (SSRF, replay, rate limits, HTTP middleware).
- Cover **error paths and boundaries** that are easy to break silently (nil inputs, skew windows, empty allowlists).
- Add **regression tests** where behavior is subtle (timeout writer, singleflight, advisory locks).

**Legend:** P0 = correctness or security critical; P1 = strong regression value; P2 = operational / polish.

---

## Cross-cutting

| Priority | Test type | What | Why |
|----------|-----------|------|-----|
| P0 | `go test -race` | Run on packages with mutexes + globals: `replay`, `ratelimit`, `httpx` | Catches map/goroutine regressions. |
| P0 | Fuzz (where safe) | `attest.ParseChallengeRequest`, `attest.ParsePCRAllowlistJSON`, `auth.ParseHeaders` (valid UTF-8 / arbitrary bytes → must not panic; oracle = strict JSON/base64 rules) | No fuzz targets exist in-repo today. |
| P1 | Golden / vector parity | Extend `vectors/` so **issuance** matches **verification** for the same fixtures (see Tracking). | Prevents drift between “issue URL” and “verify token” in different services. |

---

## Package: `attest`

**Risk:** Wrong PCR or nonce handling → unauthorized enclave acceptance; malformed challenges accepted or good requests rejected.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `ParseChallengeRequest` | Valid minimal JSON; challenge trimmed; decoded length **≥ 32**; encoded base64 **byte length ≤ 512**; reject decoded length 31; reject non-base64; extra JSON fields allowed; whitespace in challenge value. |
| P0 | `ParsePCRAllowlistJSON` | Empty string → `nil, nil`; invalid JSON; PCR index **> 31** or negative; odd-length hex; invalid hex; empty inner map. **Currently under-tested vs `attest/pcr_allowlist.go`.** |
| P0 | `ParseAndVerify` (dev path) | `maxAge == 0` skips freshness; empty allowlist skips PCR check when policy allows; `hmac.Equal` on nonce; malformed outer/inner document paths. |
| P0 | `ParseAndVerify` (production path) | Empty embedded Nitro root PEM → `ErrChainUnverified` (or documented equivalent); non-empty allowlist requires **full PCR map equality** (same keys, per-value `hmac.Equal`); extra/missing PCR index fails. |
| P1 | Nitro / COSE path | ES384-only; bad signature; empty `cabundle` / chain failure; PCR CBOR with int vs uint keys; `expectedNonce` empty vs non-empty behavior. **Much of `nitro_verify.go` lacks direct unit tests.** |
| P1 | `ErrorCode` | Stable mapping from sentinel errors to codes for API consumers. |

---

## Package: `auth`

**Risk:** Signature bypass, wrong canonical body, blob MAC confusion across products.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `decodeHexKey` / `SignRequest` | Key not exactly 32 bytes after hex decode; invalid hex. |
| P0 | `ParseHeaders` | Missing each required header; **odd-length signature hex**; invalid timestamp; trim on values; returned signature lowercasing + `VerifySignature` acceptance. |
| P0 | `ValidateTimestamp` | Past skew (existing); **future** skew beyond window; `skewWindow <= 0` → default 5m; `now.IsZero()` uses current time. |
| P0 | `VerifyBlobMap` / `VerifyBlobPayload` | Missing `blob_mac` → `CodeBlobMACMissing`; wrong MAC → `CodeBlobMACVerificationFailed`; `blob_mac` not a string; **`VerifyBlobPayload` invalid JSON** delegates/errors clearly. |
| P1 | `ValidateNonce` | Document says lowercase; `hex.DecodeString` accepts uppercase — **either enforce in code or test documented behavior.** |
| P1 | Canonical request | Trailing newline / CRLF in `body` changes MAC; method/path normalization edge cases already implied by `CanonicalRequest` — add one row per distinct failure mode. |

**Existing:** `vectors/testdata/transit_signature.json` — keep in sync with any canonicalization change.

---

## Package: `httpauth`

**Risk:** Unconfigured secret accidentally allows traffic; distinguishable errors leak information.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | Unconfigured | `expected == ""` → **503** + stable JSON body for **both** `BearerTokenMiddleware` and `HeaderTokenMiddleware`. **Header path for empty secret is a noted gap.** |
| P0 | Bearer parsing | Missing `Authorization`; `Bearer` without space; wrong scheme (`Token x` → full value compared); case variants of `Bearer`. |
| P1 | Response contract | Exact `Content-Type` and body for 401/503 (client-stable). |
| P2 | `constantTimeStringEqual` | Equal length true/false; very long strings; Unicode (allocation / length behavior). |

---

## Package: `httphdr`

**Risk:** Low; middleware is small.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P2 | Headers | Assert `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy` set; handler still invoked (`security_test.go` already covers basics). |

---

## Package: `nethttpx` (SSRF)

**Risk:** SSRF to metadata endpoints or internal networks from downstream HTTP callbacks.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `ValidatePublicURL` | `http` allowed in non-production, rejected in production; **https** in production; localhost hostnames; **IPv4/IPv6 loopback** string forms; IP literals; **userinfo** in URL (`https://user@host`); default ports. |
| P0 | DNS | Hostname resolving to **mixed** A/AAAA where one answer is blocked → must fail (every resolved addr checked). |
| P0 | `DialContextForPublic` | Connection to blocked remote (e.g. IMDS range) **closed** with `ErrBlockedAddress`; unsupported `RemoteAddr` type; dev vs prod allow/deny lists (`127.0.0.0/8`, `172.16.0.0/12`, never `169.254.169.254`). **Dial path is largely untested vs `ValidatePublicURL`.** |
| P1 | `IsBlockedIP` | `nil` → blocked; CIDR boundary cases (e.g. `172.15.x`, `172.32.x`, IPv4-mapped IPv6). |

---

## Package: `replay`

**Risk:** Wrong replay classification → duplicate side effects or incorrect blocking.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `AttemptCounter` | **Redis stub**: increment sequence; `max <= 0` disables block; boundary **`c > max`** (not `>=`) per `replay.go`. |
| P0 | In-memory path | `ttl > 0` expiry clears counter (requires injectable clock or small refactor); **`ttl == 0`** never ages out except `Reset` / restart — document with test. |
| P0 | Concurrency | Parallel increments same key with `rdb == nil` under `-race` — linearizable count. |
| P1 | `ClassifyExisting` | Empty stored fingerprint → `OutcomeNoState`; mismatch; empty request FP with non-empty stored; whitespace-only `storedBody`; non-empty `storedBody` with `{}` still cached. |

---

## Package: `ratelimit`

**Risk:** Rate-limit bypass or accidental panic on bad config.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `IncrementExpiringCounter` | `rdb == nil` → `ErrNoRedis`; stub returning errors propagates. |
| P0 | `TrustedProxyRealIP` | Peer inside trusted CIDR; **X-Forwarded-For** with multiple hops; untrusted rightmost; IPv6; **empty XFF**; invalid tokens; **`nets` nil/empty** → no rewrite. |
| P1 | `ClientBucketKey` | **`nil *http.Request`** — today likely panics; test documents behavior or add guard. |
| P1 | `IPLimiter` / `OrgLimiter` | `perMinute <= 0` and `idleTTL <= 0` defaults; eviction after idle (short TTL in test or fake clock). |
| P2 | `containsIP` | **`nil` `*net.IPNet` in slice** — document panic or filter. |

---

## Package: `audit`

**Risk:** Tamper-evident chain breaks silently; wrong hash preimage across services.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `VerifyChain` | **Stub `pgx` Queryer** (no DB): empty chain; first row with non-NULL `prev_hash`; tampered `entry_hash`; broken `prev_hash` link; duplicate sequence. |
| P0 | `EntryHash` / `Preimage` | Assert parity with **`vectors/testdata/audit_entry_hash.json`** (hashes mentioned in `audit.go` — **wire golden into test**). |
| P1 | `NormalizeEvent` | Nil `EventID`; zero `CreatedAt`; non-UTC `CreatedAt` normalized; default `EventType` / `ActorType` / `Outcome`. |
| P1 | `WriteEntry` | Stub `Tx`: optional fields NULL vs empty; `OrgID == nil` advisory key behavior; lock query present. |
| P0 | Integration | Existing `writer_test.go` integration tests — keep for advisory lock + concurrency; gate on `PG_TEST_DSN`. |

---

## Package: `bootstrap`

**Risk:** Wire format mismatch with enclave (Rust); failed decrypt accepted.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `ParseBootstrapResponse` | Odd-length hex; wrong nonce length; empty ciphertext; GCM failure paths. |
| P0 | `DecryptAuthKey` | Wrong AAD; wrong nonce; truncated ciphertext; non-empty plaintext length checks. |
| P1 | `Session.Request` / `ParseSetupResponse` | Round-trip `session_id` bytes; channel key derivation matches expected test vectors if added. |

---

## Package: `enclaveauth`

**Risk:** Thundering herd to enclave; error propagation to all waiters.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `Refresh` | `fn` runs once; concurrent callers get same result; **`fn` returns error** → all waiters see it. |
| P1 | Context | First caller’s `ctx` drives `singleflight` — second caller with cancelled ctx still waits; document. |
| P1 | Panic in `fn` | Propagates / does not deadlock (stdlib `singleflight` behavior). |

---

## Package: `httpx`

**Risk:** Timeout behavior diverges from stdlib expectations; leaked goroutines or double responses.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | After timeout | Writes after deadline return **`http.ErrHandlerTimeout`** on the wrapped `ResponseWriter`; 504 JSON only when **no headers written**. |
| P1 | Headers already written | Inner handler calls `WriteHeader` then sleeps past deadline — **no second 504** (document interaction). |
| P1 | `skip(r)` | When true, handler runs **without** artificial deadline (no timeout). |
| P1 | Non-deadline cancel | Client disconnect / `context.Canceled` vs `DeadlineExceeded` — assert whether 504 is sent (lock intended behavior). |

---

## Package: `observe/safelog`

**Risk:** PII in structured logs.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P1 | `NewRedactingHandler(nil)` | Returns nil — document that `slog.New(nil)` panics; or add guard. |
| P1 | Redaction | Denylist keys case-insensitivity; email regex on string values; **non-string** attribute kinds (no email scan — explicit). |
| P2 | `WithGroup` / nested attrs | Redaction still applied. |

---

## Package: `tracking`

**Risk:** Cross-product token forgery; click vs pixel domain confusion.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | Vectors round-trip | For each row in **`vectors/testdata/click_v1.json`**: `IssueClickURL` / `IssuePixelURL` with `base_url`, `email_id`, `target`, `key_hex` → **`url` and `token` match file** (encoding, path, query order, `TrimRight` on base URL). **Vectors today only call `Verify*`.** |
| P1 | MAC | Wrong key; truncated token; `VerifyPixelRequest` vs click domain separation (partially covered — extend edge cases). |

---

## Package: `config`

**Risk:** Production misconfiguration (TLS, Redis).

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P0 | `RequireStrict` / `ParseBoolExplicit` | Only `1`/`true` opt-out; unrecognized value errors include env key. |
| P0 | `RequirePGURLSSL` | Production: empty DSN error; `sslmode=disable` rejected; OK path. |
| P1 | `RequireRediss` | Malformed URL; scheme case; `rediss` vs `redis`; empty URL allowed in prod. |
| P1 | `InProduction` | Gate behavior for helpers that no-op in dev. |

---

## Package: `errors`

**Risk:** SDKs mapping `code` → message break.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P2 | `CodeOf` | Wrapped error chains; no `*Error` in chain → `""`. |
| P2 | `Wrap(nil, ...)` | Delegates to `New`; `Error()` string composition without leaking user data in **catalogued** paths. |

---

## Command: `cmd/audit-verify`

**Risk:** Wrong exit code in automation; silent skip of orgs.

| Priority | Test focus | Concrete cases |
|----------|------------|----------------|
| P1 | Flags | Missing `--dsn` → exit **2**; invalid `--org` UUID → **2**. |
| P1 | DB failures | Connect failure → **1**; `VerifyChain` error → **1** before remaining orgs. |
| P1 | `listOrgs` | Empty table; NULL `org_id` rows behavior with `uuid.UUID` scan (define expected exit / logging). |
| P2 | `--json` | One JSON object per org; stderr vs stdout split. |

**Note:** Full CLI tests often need a test DB or heavy mocking; prioritize table-driven tests for pure helpers (`orgString`, flag validation) if extracted.

---

## Implementation order (suggested)

1. **P0 vectors:** `audit_entry_hash.json` + tracking issue/verify parity with `click_v1.json`.
2. **P0 security:** `nethttpx.DialContextForPublic`, `ValidatePublicURL` DNS mixed results, `auth` blob + header matrix.
3. **P0 attest:** `ParsePCRAllowlistJSON` + production chain/allowlist errors.
4. **P0 httpx:** post-timeout `Write` error + early-`WriteHeader` interaction.
5. **P1** replay/redis stub, ratelimit XFF + nil request, enclaveauth singleflight, `httpauth` header middleware empty secret.

---

## Existing tests to preserve

Do not remove or weaken: `vectors/vectors_test.go` (cross-package golden checks), `replay/replay_test.go`, `auth/auth_test.go`, `nethttpx/ssrf_test.go`, `audit/writer_test.go` (integration), `bootstrap/bootstrap_test.go`, `tracking/click_test.go`, `httpx/timeout_test.go`, `config/prodgate_test.go`, `observe/safelog/handler_test.go`, `attest/verify_test.go`, `enclaveauth/rebootstrap_test.go`, `httpauth/bearer_test.go`, `httphdr/security_test.go`, `ratelimit/limiter_test.go`.

New tests should **extend** coverage, especially where this document marks a gap.
