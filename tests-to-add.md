# Unit and integration tests to add (server-core)

This document lists **deliberate, high-signal** tests for `github.com/erron-ai/server-core`, prioritized by risk to downstream correctness. It was produced by cross-reviewing package sources, existing `*_test.go` files, and `vectors/testdata/`. Goals:

- Lock **cryptographic and canonicalization** contracts (auth, attest, bootstrap, tracking, audit hashing).
- Lock **security boundaries** (SSRF, replay, rate limits, HTTP middleware).
- Cover **error paths and boundaries** that are easy to break silently (nil inputs, skew windows, empty allowlists).
- Add **regression tests** where behavior is subtle (timeout writer, singleflight, advisory locks).

**Legend:** P0 = correctness or security critical; P1 = strong regression value; P2 = operational / polish.

**Scope:** This backlog is for **local and manual** test development. It does **not** prescribe continuous integration, scheduled jobs, or pipeline gates.

---

## How to implement this backlog

These rules keep tests **refactor-safe** and **readable six months later**.

1. **One behavior per test (or per `t.Run` subtest).** Before writing assertions, finish this sentence: *Under \<preconditions\>, \<exported API\> must \<observable outcome\>.* If you cannot, split the case or narrow the unit.
2. **Design against the public API.** Assert on return values, `errors.Is` / `coreerrors.CodeOf`, HTTP status and **exact** stable JSON bodies where this document lists them. Avoid asserting on unexported helpers unless the contract is explicitly “middleware never leaks timing” style — prefer observable outcomes.
3. **Single Act.** The Act step is **one** call to the function under test, or **one** `ServeHTTP` through middleware, unless the documented contract is explicitly end-to-end (then name the test for that combined contract).
4. **Arrange / Act / Assert.** Arrange only what the Act needs; no extra calls before Act except constructors and fakes.
5. **Tables.** Use a table when arrange is **identical** except for input and expected output. If setup differs (different fake, env, clock, or middleware wiring), use a **separate** `Test…` or a top-level `t.Run` with its own arrange — avoid `if kind == …` inside a shared loop.
6. **Naming.** Prefer `TestParseChallengeRequest_RejectsBase64DecodingTo31Bytes` over `TestParseChallengeRequest_Case7`. The name states the **expected** behavior.
7. **Errors.** Prefer `errors.Is(err, attest.Err…)` or `coreerrors.CodeOf(err) == coreerrors.Code…` over substring matching on `err.Error()`, unless this document specifies a stable prefix for operational errors (e.g. `nethttpx: …`).
8. **Time, network, DB.** Unit tests use **injected** times (`auth.SignOptions.Now`, fixed `now` in `ValidateTimestamp` tests), **fake** Redis/`pgx` stubs, and **fake** host resolvers where the production code hard-codes `net.LookupIP` (see **Open design notes**). Do not use `time.Sleep` for correctness assertions unless the test is explicitly marked **integration / slow** and uses generous bounds.
9. **Concurrency.** When testing parallel behavior, assert a **numeric invariant** (e.g. final count == N, `fn` invocation count == 1), not “no race” as a vague goal.

---

## Open design notes (block or unblock tests)

| Topic | Why it matters | Resolution before locking tests |
|--------|----------------|-----------------------------------|
| **`nethttpx.ValidatePublicURL` + DNS** | Implementation uses `net.LookupIP(host)` with no injection. “Mixed A/AAAA” cannot be asserted deterministically without network control or a **refactor** (e.g. `Resolver interface { LookupIP(ctx, host) ([]net.IP, error) }`). | Either add an injectable resolver for tests **or** document this row as **manual / integration only** with a fixed hosts file or test hostname. |
| **`auth` nonce casing** | Docs say 24 **lowercase** hex chars; `hex.DecodeString` accepts uppercase. | Decide: **enforce** lowercase in `ValidateNonce` / `ParseHeaders` **or** officially accept uppercase and test that. |
| **`ratelimit.ClientBucketKey(nil)`** | May panic. | Decide: **document panic** in package doc **or** return error / empty key (API change). |
| **`observe/safelog.NewRedactingHandler(nil)`** | Returns `nil`; `slog` with nil handler panics. | Document “must not pass nil” **or** return `nop` handler. |
| **`httpx.Timeout` + `context.Canceled`** | 504 path runs only when `ctx.Err() == context.DeadlineExceeded && !tw.wroteHeader`. Client disconnect is usually `Canceled`, not `DeadlineExceeded`. | Decide expected behavior (no 504 vs 504) and add one test that locks it. |

---

## Cross-cutting

| ID | Priority | Contract | Implementation hint |
|----|----------|----------|---------------------|
| **vec-001** | P1 | For each vector in `vectors/testdata/click_v1.json`, `IssueClickURL` / `IssuePixelURL` (using `base_url`, `email_id`, `target`, `key_hex`) produces **`url` and `token` byte-identical** to the JSON fields. | Add subtests per vector `name`; Act = one `Issue…` call; Assert = string equality to `url` and `token`. |
| **vec-002** | P0 | For each row in `vectors/testdata/audit_entry_hash.json`, `audit.Preimage` and `audit.EntryHash` match the file’s expected preimage and hash hex. | Same package as existing vector tests or `audit` tests reading the JSON. |

---

## Package: `attest`

**Risk:** Wrong PCR or nonce handling → unauthorized enclave acceptance; malformed challenges accepted or good requests rejected.

### `ParseChallengeRequest` (`attest/attest.go`)

| ID | Priority | Contract (one sentence) | Arrange | Act | Assert |
|----|----------|---------------------------|---------|-----|--------|
| **attest-chal-001** | P0 | Valid JSON with base64 challenge decodes to ≥32 bytes and returns trimmed challenge string. | Minimal JSON `{"challenge":"<valid-b64>"}` where decoded length is 32. | `ParseChallengeRequest(raw)` | `err == nil`; `req.Challenge` equals trimmed form; remainder bytes as documented. |
| **attest-chal-002** | P0 | Rejects when base64 decodes to fewer than 32 bytes. | Payload where decoded length is 31, encoded length within 512. | `ParseChallengeRequest` | Error non-nil; no panic. |
| **attest-chal-003** | P0 | Rejects when UTF-8 byte length of base64 string exceeds 512. | Construct string of length 513 that is still invalid or valid b64 per implementation. | `ParseChallengeRequest` | Error non-nil. |
| **attest-chal-004** | P0 | Accepts extra JSON fields (forward compatibility). | JSON with unknown top-level key + valid challenge. | `ParseChallengeRequest` | `err == nil`. |
| **attest-chal-005** | P1 | Whitespace inside JSON string value is part of base64 decode input (or trimmed per spec — match **current** `attest.go` behavior exactly). | Challenge value with leading/trailing spaces in JSON. | `ParseChallengeRequest` | Document outcome in test name once locked. |

**Split rows** — do not merge 001–005 into one loop with branches on “scenario type” unless the arrange block is shared and only `raw` and `wantErr` differ.

### `ParsePCRAllowlistJSON` (`attest/pcr_allowlist.go`)

| ID | Priority | Contract | Assert |
|----|----------|----------|--------|
| **attest-pcr-001** | P0 | Empty input string returns `([]PCRSet)(nil), nil`. | `len==0` and `err==nil`. |
| **attest-pcr-002** | P0 | Invalid JSON returns error. | |
| **attest-pcr-003** | P0 | PCR index **> 31** or **< 0** returns error. | |
| **attest-pcr-004** | P0 | Odd-length hex or non-hex returns error. | |
| **attest-pcr-005** | P0 | Empty inner PCR map returns error (if that is current behavior). | Read `pcr_allowlist.go` and lock. |

### `ParseAndVerify` (`attest/verify.go`, dev vs production)

| ID | Priority | Contract | Notes |
|----|----------|----------|-------|
| **attest-vfy-001** | P0 | Dev path: `maxAge == 0` does not return `ErrTooOld` for old timestamps (when other checks pass). | Use existing mock doc patterns from `verify_test.go`. |
| **attest-vfy-002** | P0 | Dev path: `allow == nil` skips PCR allowlist matching. | |
| **attest-vfy-003** | P0 | Production: empty `allow` slice returns `ErrNoAllowlist` (or current sentinel). | Already partially covered — extend if gaps remain. |
| **attest-vfy-004** | P0 | Production: non-empty allowlist, PCR map not equal to any allowed set → `ErrPCRMismatch`. | |
| **attest-vfy-005** | P1 | `ErrorCode(err)` returns stable non-empty string for each sentinel error type (table: sentinel → code). | Only if `ErrorCode` is part of the supported API. |

### Nitro / COSE (`attest/nitro_verify.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **attest-nitro-001** | P1 | Document which scenarios need **golden COSE blobs** vs skipped until test fixtures exist. Prefer one test per failure class: chain failure, signature failure, wrong ES alg. |

---

## Package: `auth`

**Risk:** Signature bypass, wrong canonical body, blob MAC confusion across products.

### Keys and signing (`auth/auth.go`)

| ID | Priority | Contract | Assert |
|----|----------|----------|--------|
| **auth-sign-001** | P0 | `SignRequest` with hex key not decoding to exactly 32 bytes returns `coreerrors.CodeInvalidField` (or documented code). | `coreerrors.CodeOf(err)` |
| **auth-sign-002** | P0 | `SignRequest` with invalid hex returns same. | |
| **auth-sign-003** | P1 | `SignRequest` with valid key + `SignOptions` fixed `Now`/`Nonce` produces deterministic `Signature` matching HMAC over `Canonical` bytes. | Compare to known vector or recompute HMAC in test. |

### `ParseHeaders` / `VerifySignature`

| ID | Priority | Contract |
|----|----------|----------|
| **auth-hdr-001** | P0 | Missing `X-Vault-Timestamp` → `CodeMissingTimestamp`. |
| **auth-hdr-002** | P0 | Missing `X-Vault-Nonce` → `CodeMissingNonce`. |
| **auth-hdr-003** | P0 | Missing `X-Vault-Sig` → `CodeMissingSignature`. |
| **auth-hdr-004** | P0 | Signature hex with **odd** length → `CodeInvalidSignature` (or current code). |
| **auth-hdr-005** | P0 | Values are **TrimSpace**d before validation; build headers with surrounding spaces. | Assert successful parse with trimmed values. |
| **auth-hdr-006** | P1 | Parsed signature is lowercased if implementation lowercases — assert exact equality after parse. |

Use **separate** subtests per missing header (different Arrange), not one table with `missing: "timestamp|nonce|sig"` unless the arrange is truly identical.

### `ValidateTimestamp`

| ID | Priority | Contract |
|----|----------|----------|
| **auth-ts-001** | P0 | Timestamp more than `skewWindow` **in the past** → `CodeStaleTimestamp`. |
| **auth-ts-002** | P0 | Timestamp more than `skewWindow` **in the future** → same or `CodeInvalidTimestamp` — **assert whichever the code does today** and lock. |
| **auth-ts-003** | P0 | `skewWindow <= 0` uses **default 5m** behavior (document with fixed `now`). |
| **auth-ts-004** | P1 | All comparisons use the provided `now` — no wall-clock in test body. |

### `VerifyBlobMap` / `VerifyBlobPayload`

| ID | Priority | Contract |
|----|----------|----------|
| **auth-blob-001** | P0 | Map without `blob_mac` key → `CodeBlobMACMissing`. |
| **auth-blob-002** | P0 | Wrong MAC → `CodeBlobMACVerificationFailed`. |
| **auth-blob-003** | P0 | `blob_mac` value not a JSON string → error with appropriate code. |
| **auth-blob-004** | P0 | `VerifyBlobPayload` with invalid JSON bytes → `CodeInvalidJSON` (or wrapped). |

### Canonical request

| ID | Priority | Contract |
|----|----------|----------|
| **auth-can-001** | P1 | Same logical request with `\n` vs `\r\n` in body produces **different** signatures (if body bytes differ). | Two `SignRequest` acts, compare signatures. |

**Existing:** `vectors/testdata/transit_signature.json` — any change to `CanonicalRequest` must update vectors and this test.

---

## Package: `httpauth`

**Risk:** Unconfigured secret accidentally allows traffic; distinguishable errors leak information.

**Stable bodies** (from `httpauth/bearer.go`):  
- Unauthorized: `{"error":"unauthorized"}`  
- Unconfigured: `{"error":"unconfigured"}`  
**Stable header:** `Content-Type: application/json`

| ID | Priority | Middleware | Contract |
|----|----------|------------|----------|
| **httpauth-001** | P0 | `BearerTokenMiddleware` | `expected == ""` → status **503**, body **exactly** `uniformResponseUnconfigured`, `Content-Type` application/json, **next not called**. |
| **httpauth-002** | P0 | `HeaderTokenMiddleware("X-Token", "")` | Same as 001. |
| **httpauth-003** | P0 | `BearerTokenMiddleware("secret")` | No `Authorization` header → 401 + unauthorized body, next not called. |
| **httpauth-004** | P0 | Bearer | `Authorization: Token xyz` (no `Bearer ` prefix) → token compared is full header value after TrimPrefix — expect **401** (unless token accidentally matches). |
| **httpauth-005** | P1 | Bearer | `Authorization: Bearer <correct>` → 200 from next handler. |

Use `httptest.ResponseRecorder`; Act = one `handler.ServeHTTP(rec, req)`.

---

## Package: `httphdr`

| ID | Priority | Contract |
|----|----------|----------|
| **hdr-001** | P2 | After middleware, response includes `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy` with values matching `security.go`. |
| **hdr-002** | P2 | Inner handler runs (e.g. sets body “ok”). |

---

## Package: `nethttpx` (SSRF)

**Risk:** SSRF to metadata endpoints or internal networks.

### `IsBlockedIP` / `shouldBlockForMode` (via exported `IsBlockedIP` + `DialContextForPublic` / `ValidatePublicURL`)

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-ip-001** | P0 | `IsBlockedIP(nil) == true`. |
| **ssrf-ip-002** | P1 | Boundary IPs: just outside `172.16.0.0/12` (e.g. 172.15.x) not blocked; inside blocked. |
| **ssrf-ip-003** | P1 | `169.254.169.254` blocked in both modes (IMDS). |

### `ValidatePublicURL` (`nethttpx/ssrf.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-url-001** | P0 | `production=true`, `http://…` → error containing `production url must use https`. |
| **ssrf-url-002** | P0 | `production=false`, `http://example.com` → `nil` if DNS resolves to only public IPs (**flaky** if real DNS — prefer **integration** or resolver injection; see Open design notes). |
| **ssrf-url-003** | P0 | Host `localhost` → error `localhost not allowed` (no DNS). |
| **ssrf-url-004** | P0 | Literal IP `127.0.0.1` → `errors.Is(ErrBlockedAddress)` in production. |
| **ssrf-url-005** | P1 | `https://user@example.com` — assert behavior (host parsing strips userinfo per `url`); must not panic. |

### DNS “every address checked”

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-dns-001** | P0 | When resolver returns multiple IPs and **one** is blocked, `ValidatePublicURL` returns `ErrBlockedAddress`. | **Requires** fake resolver or refactor; document in test file header. |

### `DialContextForPublic`

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-dial-001** | P0 | Conn with `RemoteAddr` not `*TCPAddr`/`*UDPAddr` → connection closed, error `unsupported address type`. | Use `net.Pipe` or custom `net.Conn` with fake `RemoteAddr()`. |
| **ssrf-dial-002** | P0 | TCP conn to peer IP in blocked range → `ErrBlockedAddress`, conn closed. | May use loopback listener + **blocked** IP only if you can synthesize RemoteAddr — otherwise document as integration. |
| **ssrf-dial-003** | P1 | Dev mode: `127.0.0.1` allowed; production: blocked. |

---

## Package: `replay`

**Risk:** Wrong replay classification → duplicate side effects or incorrect blocking.

### `AttemptCounter` (`replay/replay.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **replay-ac-001** | P0 | `rdb` non-nil stub: first call returns `(1, false, nil)`; increment returns increasing counts. |
| **replay-ac-002** | P0 | `max == 0`: never `blocked == true` regardless of count. |
| **replay-ac-003** | P0 | `max > 0`: `blocked` true iff `count > max` (not `>=`). |
| **replay-ac-004** | P0 | Stub returns error → propagate unchanged. |

### In-memory path + `Reset`

| ID | Priority | Contract |
|----|----------|----------|
| **replay-mem-001** | P1 | `ttl == 0`: counter increments persist until `Reset` (no time-based expiry). |
| **replay-mem-002** | P1 | `ttl > 0`: after simulated time past expiry, increment starts fresh — **only if** clock injectable; else document as future refactor. |

### Concurrency

| ID | Priority | Contract |
|----|----------|----------|
| **replay-conc-001** | P0 | N goroutines each call `AttemptCounter` once with same key, `rdb==nil` → final count == N. |

### `ClassifyExisting`

| ID | Priority | Contract |
|----|----------|----------|
| **replay-cls-001** | P1 | `storedFingerprint == ""` → `OutcomeNoState`. |
| **replay-cls-002** | P1 | Fingerprints differ, request non-empty → `OutcomeConflict` (match `replay.go` exactly). |
| **replay-cls-003** | P1 | Empty request fingerprint, non-empty stored → **not** conflict (per existing edge test — extend if needed). |

---

## Package: `ratelimit`

| ID | Priority | Area | Contract |
|----|----------|------|----------|
| **rl-001** | P0 | `IncrementExpiringCounter` | `rdb == nil` → `ErrNoRedis`. |
| **rl-002** | P0 | Same | Stub returns `io.ErrClosedPipe` (or arbitrary) → same error from wrapper. |
| **rl-003** | P0 | `TrustedProxyRealIP` | Table: peer IP in trusted CIDR, `X-Forwarded-For` chain → `RemoteAddr` on request reflects **rightmost untrusted** or documented semantics — **read `realip.go` and lock one row per behavior.** |
| **rl-004** | P1 | `TrustedProxyRealIP` | `nets == nil` or empty → no change to address (see implementation). |
| **rl-005** | P1 | `ClientBucketKey` | Document panic or add test for `nil` request after design decision. |
| **rl-006** | P1 | `NewIPLimiter(0,0)` | Uses default rate and idle TTL per `iplimiter.go`. |

---

## Package: `audit`

| ID | Priority | Area | Contract |
|----|----------|------|----------|
| **audit-001** | P0 | `VerifyChain` | Fake `Queryer` returns zero rows → `nil` error (or documented “empty ok”). |
| **audit-002** | P0 | `VerifyChain` | First row has non-NULL `prev_hash` → linkage violation error. |
| **audit-003** | P0 | `VerifyChain` | Tampered `entry_hash` → error. |
| **audit-004** | P0 | `EntryHash` | Matches `vectors/testdata/audit_entry_hash.json` (**vec-002**). |
| **audit-005** | P1 | `NormalizeEvent` | Nil `EventID` gets new UUID; zero `CreatedAt` set to UTC “now” — use fixed clock if added to API; else assert non-zero and UTC location. |
| **audit-006** | P0 | Integration | `writer_test.go` patterns; run with `PG_TEST_DSN` only. |

---

## Package: `bootstrap`

| ID | Priority | Contract |
|----|----------|----------|
| **boot-001** | P0 | `ParseBootstrapResponse`: odd-length hex ciphertext → error. |
| **boot-002** | P0 | Wrong nonce length → error. |
| **boot-003** | P0 | `DecryptAuthKey`: wrong AAD → GCM open fails. |
| **boot-004** | P1 | `Session.Request()` after `ParseSetupResponse` round-trips session id bytes. |

---

## Package: `enclaveauth`

| ID | Priority | Contract |
|----|----------|----------|
| **enc-001** | P0 | `Refresh`: N concurrent `g.WaitGroup` callers; `fn` invoked **exactly once**; all receive same `(string, error)`. |
| **enc-002** | P0 | `fn` returns error → all callers receive **that** error. |
| **enc-003** | P1 | Second caller with cancelled context: assert whether `Refresh` returns immediately or waits — **match `singleflight` + your wrapper**; document in test name. |

---

## Package: `httpx`

| ID | Priority | Contract |
|----|----------|----------|
| **httpx-001** | P0 | Handler runs longer than `dt`, never calls `WriteHeader`: client sees **504**, body `{"error":"gateway_timeout"}`, `Content-Type` application/json. |
| **httpx-002** | P0 | Same timeout: subsequent `Write` on the timeout writer used by handler returns `http.ErrHandlerTimeout` (assert via handler that captures writer). |
| **httpx-003** | P1 | Handler calls `WriteHeader(200)` then sleeps: on timeout, **no** second 504 from wrapper (real `ResponseWriter` may still race — assert `tw.err` / documented behavior). |
| **httpx-004** | P1 | `skip(r)==true`: handler runs **synchronously** without deadline (use `context` inspection or “no 504 within short dt” with fast handler). |
| **httpx-005** | P1 | Cancel parent `context` with `Cancel` (not deadline): document whether 504 appears — **see Open design notes**. |

---

## Package: `observe/safelog`

| ID | Priority | Contract |
|----|----------|----------|
| **log-001** | P1 | Key in denylist → value replaced with `REDACTED` literal. |
| **log-002** | P1 | String value matching email regex → redacted. |
| **log-003** | P2 | `WithAttrs` / groups — redaction still applies to nested keys per implementation. |

---

## Package: `tracking`

| ID | Priority | Contract |
|----|----------|----------|
| **trk-001** | P0 | **vec-001** (issue/verify parity). |
| **trk-002** | P1 | Pixel token fails `VerifyClickRequest`; click token fails `VerifyPixelRequest` for same bytes (domain separation). |

---

## Package: `config`

| ID | Priority | Contract |
|----|----------|----------|
| **cfg-001** | P0 | `RequireStrict("TEST_STRICT")` with env unset → strict true, nil error. |
| **cfg-002** | P0 | `RequireStrict` with env `maybe` → error mentions env key and `unrecognised value`. |
| **cfg-003** | P0 | `RequirePGURLSSL` + `InProduction()` true: empty DSN errors; `sslmode=disable` substring errors (casefold). |
| **cfg-004** | P1 | `RequireRediss`: `redis://` in prod → error; `rediss://` ok; empty URL ok. |

Use `t.Setenv` in tests; isolate env per test.

---

## Package: `errors`

| ID | Priority | Contract |
|----|----------|----------|
| **err-001** | P2 | `CodeOf(wrap(os.ErrNotExist, …))` returns wrapped `*Error` code. |
| **err-002** | P2 | Plain `errors.New("x")` → `CodeOf` is `""`. |

---

## Command: `cmd/audit-verify`

| ID | Priority | Contract |
|----|----------|----------|
| **cli-001** | P1 | Missing `--dsn` → exit code **2** (test via `exec` or refactor `main` to `run(os.Args) error`). |
| **cli-002** | P1 | Invalid `--org` UUID → exit **2**. |
| **cli-003** | P1 | DB connection failure → exit **1**. |

**Note:** Prefer extracting `run(args []string) int` for testing without subprocess; document in `main.go` if done.

---

## Implementation order (suggested)

1. **vec-001 / vec-002** — goldens lock cross-repo contracts early.
2. **auth-hdr-*, auth-blob-*, auth-ts-*** — transit security surface.
3. **httpauth-001–005** — middleware contracts are tiny and fast.
4. **attest-pcr-*, attest-chal-*** — pure parsing.
5. **ssrf-url-001, ssrf-ip-001, ssrf-dial-001** — no DNS where possible.
6. **replay-ac-*, replay-conc-001** — stubs + memory.
7. **httpx-001–002** — timeout semantics.
8. **audit-001–003** — fake `Queryer`.
9. Remaining P1/P2 by package priority.

---

## Existing tests to preserve

Do not remove or weaken: `vectors/vectors_test.go`, `replay/replay_test.go`, `auth/auth_test.go`, `nethttpx/ssrf_test.go`, `audit/writer_test.go` (integration), `bootstrap/bootstrap_test.go`, `tracking/click_test.go`, `httpx/timeout_test.go`, `config/prodgate_test.go`, `observe/safelog/handler_test.go`, `attest/verify_test.go`, `enclaveauth/rebootstrap_test.go`, `httpauth/bearer_test.go`, `httphdr/security_test.go`, `ratelimit/limiter_test.go`.

New tests should **extend** coverage; use IDs in this document in `t.Run` names or comments where helpful (e.g. `// attest-chal-003`).
