# Unit and integration tests to add (server-core)

This document lists **deliberate, high-signal** tests for `github.com/erron-ai/server-core`, prioritized by risk to downstream correctness. It was produced by cross-reviewing package sources, existing `*_test.go` files, and `vectors/testdata/`. Goals:

- Lock **cryptographic and canonicalization** contracts (auth, attest, bootstrap, tracking, audit hashing).
- Lock **security boundaries** (SSRF, replay, rate limits, HTTP middleware).
- Cover **error paths and boundaries** that are easy to break silently (nil inputs, skew windows, empty allowlists).
- Add **regression tests** where behavior is subtle (timeout writer, singleflight, advisory locks).

**Legend:** P0 = correctness or security critical; P1 = strong regression value; P2 = operational / polish. **P0-blocked** = same intent as P0 but **not** runnable as a deterministic unit test until a noted prerequisite (refactor, fixture, or integration env) exists.

**Scope:** This backlog is for **local and manual** test development. It does **not** prescribe continuous integration, scheduled jobs, or pipeline gates.

---

## How to implement this backlog

These rules keep tests **refactor-safe** and **readable six months later**.

1. **One behavior per test (or per `t.Run` subtest).** Before writing assertions, finish this sentence: *Under \<preconditions\>, \<exported API\> must \<observable outcome\>.* If you cannot, split the case or narrow the unit.
2. **Design against the public API.** Assert on return values, `errors.Is` / `coreerrors.CodeOf`, HTTP status and **exact** stable JSON bodies where this document lists them. Avoid asserting on unexported helpers unless the contract is explicitly “middleware never leaks timing” style — prefer observable outcomes.
3. **Single Act.** The Act step is **one** call to the function under test, or **one** `ServeHTTP` through middleware, unless the documented contract is explicitly end-to-end (then name the test for that combined contract).
4. **Exception — comparing two outputs.** A test whose contract is “**two calls produce different (or equal) results**” (e.g. two `SignRequest` with different body bytes) uses **two Act steps** by necessity. Name the test for that **relationship** (e.g. `TestSignRequest_BodyLineEndingAffectsSignature`) — do not pretend it is a single-call unit.
5. **Arrange / Act / Assert.** Arrange only what the Act needs; no extra calls before Act except constructors and fakes.
6. **Tables.** Use a table when arrange is **identical** except for input and expected output. If setup differs (different fake, env, clock, or middleware wiring), use a **separate** `Test…` or a top-level `t.Run` with its own arrange — avoid `if kind == …` inside a shared loop.
7. **Naming.** Prefer `TestParseChallengeRequest_RejectsBase64DecodingTo31Bytes` over `TestParseChallengeRequest_Case7`. The name states the **expected** behavior.
8. **Errors.** Prefer `errors.Is(err, attest.Err…)` or `coreerrors.CodeOf(err) == coreerrors.Code…` over substring matching on `err.Error()`. Where the implementation only returns `fmt.Errorf("nethttpx: …")`, **prefer** adding a `var Err… = errors.New(...)` and `errors.Is` in production code; until then, substring or `strings.Contains` is an acceptable **interim** regression guard, called out explicitly in the test comment.
9. **Time, network, DB.** Unit tests use **injected** times (`auth.SignOptions.Now`, fixed `now` in `ValidateTimestamp` tests), **fake** Redis/`pgx` stubs, and **fake** host resolvers where the production code hard-codes `net.LookupIP` (see **Open design notes**). Do not use `time.Sleep` for correctness assertions unless the test is explicitly marked **integration / slow** and uses generous bounds.
10. **Concurrency.** When testing parallel behavior, assert a **numeric invariant** (e.g. final count == N, `fn` invocation count == 1), not “no race” as a vague goal.

### Spec lock vs regression snapshot

- **Spec lock:** The behavior is **normative** (docs, threat model, or cross-language vectors). A test failure means **fix the code** unless the spec changed.
- **Regression snapshot:** The behavior is **“whatever the code does today”** until a product decision is recorded (see **Open design notes**). A test failure may mean **fix the code** or **update the test** after an intentional change.
- Label regression-snapshot tests in a comment: `// regression: locked until SPEC-…` or link to an issue.

### Test environment matrix

| Tier | When | Typical deps |
|------|------|----------------|
| **Unit** | Default `go test` | No network, no real DB, no real DNS; fakes and `t.Setenv` per test. |
| **Integration** | `PG_TEST_DSN` set, or `//go:build integration` | Real Postgres, optional real DNS — **not** implied for every P0 row. |

Items that need **DNS** or **resolver injection** are **not** unit-tier until refactored or explicitly run as integration.

### IDs

Row IDs (`attest-chal-001`, etc.) are **optional** for cross-referencing; they are not a substitute for clear test names. Prefer descriptive `t.Run` names over ID-only comments.

---

## Open design notes (block or unblock tests)

| Topic | Why it matters | Resolution before locking tests |
|--------|----------------|-----------------------------------|
| **`nethttpx.ValidatePublicURL` + DNS** | Implementation uses `net.LookupIP(host)` with no injection. “Mixed A/AAAA” cannot be asserted deterministically without network control or a **refactor** (e.g. `Resolver interface { LookupIP(ctx, host) ([]net.IP, error) }`). | Either add an injectable resolver for tests **or** document this row as **manual / integration only** with a fixed hosts file or test hostname. |
| **`auth` nonce casing** | Docs say 24 **lowercase** hex chars; `hex.DecodeString` accepts uppercase. | `ValidateNonce` only checks length + decode — **regression** or tighten enforcement in code. |
| **`ratelimit.ClientBucketKey(nil)`** | May panic. | Decide: **document panic** in package doc **or** return error / empty key (API change). |
| **`observe/safelog.NewRedactingHandler(nil)`** | Returns `nil`; `slog` with nil handler panics. | Document “must not pass nil” **or** return `nop` handler. |
| **`httpx.Timeout` + `context.Canceled`** | 504 path runs only when `ctx.Err() == context.DeadlineExceeded && !tw.wroteHeader`. Client disconnect is usually `Canceled`, not `DeadlineExceeded`. | Decide expected behavior (no 504 vs 504) and add one test that locks it. |

---

## Explicitly out of scope (until decided otherwise)

- **Nitro / COSE** (`attest/nitro_verify.go`): no concrete golden COSE blobs in-repo — add **attest-nitro-*** only after fixtures exist; do not block other work on placeholder IDs.
- **DNS-dependent `ValidatePublicURL` success paths** without resolver injection: **integration** or **P0-blocked**, not default unit `go test`.
- **Full `cmd/audit-verify` main** without extracting `run(args []string) int` (or similar): exit-code tests stay **P1** behind refactor or `exec` subprocess tests.

---

## Cross-cutting

| ID | Priority | Contract | Implementation hint |
|----|----------|----------|---------------------|
| **vec-001** | P1 | For each vector row in `vectors/testdata/click_v1.json`, `IssueClickURL` (for `kind: click`) or `IssuePixelURL` (for `kind: pixel`) using `base_url`, `email_id`, `target`, `key_hex` produces **`url` and `token` equal** to the JSON fields. Prefer **semantic equality** (parsed URL + query keys/values) if raw string escaping differs between Go and how the JSON was authored; use **byte-identical** only if generators match exactly. | Subtests per vector `name`; **one** `Issue…` Act per subtest; assert against expected `url`/`token`. |
| **vec-002** | P0 | For each row in `vectors/testdata/audit_entry_hash.json`, `audit.Preimage` and `audit.EntryHash` match the file. | Implement in `vectors/` or `audit` tests — **do not duplicate** a second standalone audit-only golden row (see **audit**). |

---

## Package: `attest`

**Risk:** Wrong PCR or nonce handling → unauthorized enclave acceptance; malformed challenges accepted or good requests rejected.

### `ParseChallengeRequest` (`attest/attest.go`)

| ID | Priority | Contract (one sentence) | Notes |
|----|----------|---------------------------|-------|
| **attest-chal-001** | P0 | Valid JSON with base64 challenge decodes to ≥32 bytes and returns trimmed challenge string. | |
| **attest-chal-002** | P0 | Rejects when base64 decodes to fewer than 32 bytes. | |
| **attest-chal-003** | P0 | Rejects when UTF-8 byte length of base64 string exceeds 512. | |
| **attest-chal-004** | P1 | Accepts extra JSON fields (forward compatibility for **input**). | P0 inflation if treated as equal to security; **P1** is enough. |
| **attest-chal-005** | P1 | Whitespace inside JSON string value: **regression** — lock current `attest.go` behavior exactly; name the test after the outcome. | |

**Split rows** — do not merge into one loop with branches on “scenario type” unless the arrange block is shared and only `raw` and `wantErr` differ.

### `ParsePCRAllowlistJSON` (`attest/pcr_allowlist.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **attest-pcr-001** | P0 | Empty input string returns `([]PCRSet)(nil), nil`. |
| **attest-pcr-002** | P0 | Invalid JSON returns error. |
| **attest-pcr-003** | P0 | PCR index **> 31** or **< 0** returns error. |
| **attest-pcr-004** | P0 | Odd-length hex or non-hex returns error. |
| **attest-pcr-005** | P0 | Empty inner PCR map returns error (`empty pcr set in allowlist`). |

### `ParseAndVerify` (`attest/verify.go`, dev vs production)

| ID | Priority | Contract | Notes |
|----|----------|----------|-------|
| **attest-vfy-001** | P0 | Dev path: `maxAge == 0` does not return `ErrTooOld` for old timestamps (when other checks pass). | Use existing mock doc patterns from `verify_test.go`. |
| **attest-vfy-002** | P0 | Dev path: `allow == nil` skips PCR allowlist matching. | |
| **attest-vfy-003** | P0 | Production: empty `allow` slice returns `ErrNoAllowlist` (or current sentinel). | |
| **attest-vfy-004** | P0 | Production: non-empty allowlist, PCR map not equal to any allowed set → `ErrPCRMismatch`. | |
| **attest-vfy-005** | P1 | `ErrorCode(err)` returns stable non-empty string for each sentinel error type (table: sentinel → code). | Only if `ErrorCode` is part of the supported API. |

### Nitro / COSE (`attest/nitro_verify.go`)

**Out of scope** until golden COSE blobs exist. When added: one test per failure class (chain, signature, wrong alg) — do not use a placeholder ID without fixtures.

---

## Package: `auth`

**Risk:** Signature bypass, wrong canonical body, blob MAC confusion across products.

### Keys and signing (`auth/auth.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **auth-sign-001** | P0 | `SignRequest` with invalid hex **or** key not decoding to exactly 32 bytes returns `coreerrors.CodeInvalidField` (table: `wrongLenHex`, `invalidHex`) | Merge into one table-driven test. |

| **auth-sign-002** | P1 | `SignRequest` with valid key + `SignOptions` fixed `Now`/`Nonce` produces deterministic `Signature` matching HMAC over `Canonical` bytes. | Compare to vector or recompute. |

### `ParseHeaders` / `VerifySignature`

| ID | Priority | Contract |
|----|----------|----------|
| **auth-hdr-001** | P0 | Missing `X-Vault-Timestamp`, `X-Vault-Nonce`, or `X-Vault-Sig` → `CodeMissingTimestamp`, `CodeMissingNonce`, or `CodeMissingSignature` respectively. | **Three subtests** (arrange differs per missing header); one table only if you use identical `Header` construction with a `missing` field. |
| **auth-hdr-002** | P0 | Signature hex with **odd** length → `CodeInvalidSignature` (or current code). | |
| **auth-hdr-003** | P0 | Values are **TrimSpace**d before validation; build headers with surrounding spaces. | Assert successful parse with trimmed values. |
| **auth-hdr-004** | P1 | Parsed signature normalization: assert exact equality after parse. | |

### `ValidateTimestamp`

Implementation uses **`CodeInvalidField`** with message `"stale request timestamp"` for **both** too-old and too-far-future (symmetric window). Tests should lock **that**, not `CodeStaleTimestamp` unless the code changes.

| ID | Priority | Contract |
|----|----------|----------|
| **auth-ts-001** | P0 | Timestamp more than `skewWindow` **in the past** → `CodeInvalidField` (stale). |
| **auth-ts-002** | P0 | Timestamp more than `skewWindow` **in the future** → same code (**separate subtest** from 001 — same arrange pattern, different `timestamp`). |
| **auth-ts-003** | P0 | `skewWindow <= 0` uses **default 5m** — use fixed `now`, no wall clock. |
| **auth-ts-004** | P1 | All comparisons use the provided `now` when non-zero. | |

### `VerifyBlobMap` / `VerifyBlobPayload`

| ID | Priority | Contract |
|----|----------|----------|
| **auth-blob-001** | P0 | Map without `blob_mac` key → `CodeBlobMACMissing`. |
| **auth-blob-002** | P0 | Wrong MAC → `CodeBlobMACVerificationFailed`. |
| **auth-blob-003** | P0 | `blob_mac` value not a JSON string → error with appropriate code. |
| **auth-blob-004** | P0 | `VerifyBlobPayload` with invalid JSON bytes → JSON error from `json.Unmarshal` (not necessarily `coreerrors`). | |

### Canonical request

| ID | Priority | Contract |
|----|----------|----------|
| **auth-can-001** | P1 | Same logical request with `\n` vs `\r\n` in body produces **different** signatures when body bytes differ. | **Two Act steps** — see **Exception — comparing two outputs** above. |

**Existing:** `vectors/testdata/transit_signature.json` — any change to `CanonicalRequest` must update vectors and this test.

---

## Package: `httpauth`

**Risk:** Unconfigured secret accidentally allows traffic; distinguishable errors leak information.

**Stable bodies** (from `httpauth/bearer.go`):  
- Unauthorized: `{"error":"unauthorized"}`  
- Unconfigured: `{"error":"unconfigured"}`  
**Stable header:** `Content-Type: application/json`

| ID | Priority | Contract |
|----|----------|----------|
| **httpauth-001** | P0 | **Unconfigured secret:** `expected == ""` → **503**, body **exactly** unconfigured JSON, `Content-Type` application/json, **next not called** — for **both** `BearerTokenMiddleware("")` and `HeaderTokenMiddleware("X-Token", "")` (two `t.Run` subtests, same assertions). |
| **httpauth-002** | P0 | `BearerTokenMiddleware("secret")`, no `Authorization` → **401** + unauthorized body, next not called. |
| **httpauth-003** | P0 | `Authorization: Bearer <correct>` → 200 from next. | |
| **httpauth-004** | P0 | **TrimPrefix:** `Authorization: Bearer` without trailing space → `TrimPrefix` leaves full value; use `expected` secret **not** equal to that string so outcome is **401** (deterministic — e.g. `expected="secret"`, header `Authorization: Bearer` only). | |

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

**Defense-in-depth:** `ValidatePublicURL` at registration time does **not** replace post-dial checks in `DialContextForPublic` (DNS may change). A **unit test** cannot prove end-to-end TOCTOU safety; document that **products** must keep both call sites. Optional **P2** integration: register URL then dial — out of default unit scope.

### `IsBlockedIP` / `shouldBlockForMode`

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-ip-001** | P0 | `IsBlockedIP(nil) == true`. |
| **ssrf-ip-002** | P1 | Boundary IPs: e.g. 172.15.x not in `172.16.0.0/12`; 172.16.x inside. |
| **ssrf-ip-003** | P1 | `169.254.169.254` blocked. |

### `ValidatePublicURL` (`nethttpx/ssrf.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-url-001** | P0 | `production=true`, `http://…` → error substring `production url must use https` **or** `errors.Is` once a sentinel exists. |
| **ssrf-url-002** | P1 | `production=false`, `http://…` → **depends on real DNS** — **integration** or **resolver injection**; **not** default deterministic unit. Demoted from P0 to avoid “P0 that cannot run offline.” |
| **ssrf-url-003** | P0 | Host `localhost` → error `localhost not allowed` (no DNS). |
| **ssrf-url-004** | P0 | Literal IP `127.0.0.1` → `errors.Is(ErrBlockedAddress)` in production. |
| **ssrf-url-005** | P1 | `https://user@example.com` — assert non-panic and policy on resolved host (see `url.URL` behavior). |

### DNS “every address checked”

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-dns-001** | P0-blocked | Resolver returns multiple IPs, one blocked → `ValidatePublicURL` returns `ErrBlockedAddress`. **Requires** fake resolver or refactor. |

### `DialContextForPublic`

| ID | Priority | Contract |
|----|----------|----------|
| **ssrf-dial-001** | P0 | `RemoteAddr` not `*TCPAddr`/`*UDPAddr` → conn closed, error `unsupported address type`. | Fake `net.Conn`. |
| **ssrf-dial-002** | P0-blocked | Peer IP in blocked range after dial → `ErrBlockedAddress`, conn closed. | Needs conn with controlled `RemoteAddr()` mimicking blocked IP; **or** integration. |
| **ssrf-dial-003** | P1 | Dev: `127.0.0.1` allowed; production: blocked (via `shouldBlockForMode`). |

---

## Package: `replay`

**Risk:** Wrong replay classification → duplicate side effects or incorrect blocking.

### `AttemptCounter` (`replay/replay.go`)

| ID | Priority | Contract |
|----|----------|----------|
| **replay-ac-001** | P0 | `rdb` non-nil stub: increments return 1, 2, 3, … |
| **replay-ac-002** | P0 | `max == 0`: never `blocked == true`. |
| **replay-ac-003** | P0 | `max > 0`: `blocked` true iff `count > max` (not `>=`). First returned count is **1** after first increment (stub semantics). |
| **replay-ac-004** | P0 | Stub returns error → propagate unchanged. |

### In-memory path + `Reset`

| ID | Priority | Contract |
|----|----------|----------|
| **replay-mem-001** | P1 | `ttl == 0`: counter persists until `Reset` (no time-based expiry). |
| **replay-mem-002** | P1 | `ttl > 0`: expiry requires injectable clock **or** mark **future refactor**. |

### Concurrency

| ID | Priority | Contract |
|----|----------|----------|
| **replay-conc-001** | P0 | N goroutines each call `AttemptCounter` once with same key, `rdb==nil` → final count == N. |

### `ClassifyExisting`

| ID | Priority | Contract |
|----|----------|----------|
| **replay-cls-001** | P0 | `storedFingerprint == ""` → `OutcomeNoState` (wrong outcome can mis-route idempotency). |
| **replay-cls-002** | P0 | Fingerprints differ with non-empty request FP → `OutcomeConflict` (assert exact outcome per `replay.go`). |
| **replay-cls-003** | P1 | Empty request FP, non-empty stored → **not** conflict (edge case). |

---

## Package: `ratelimit`

Source: `ratelimit/realip.go` — middleware walks `X-Forwarded-For` **right to left** and picks the first IP that is **not** in `nets`; only runs when `len(nets) > 0` and direct **peer** IP parses and `containsIP(nets, peerIP)`.

| ID | Priority | Contract |
|----|----------|----------|
| **rl-001** | P0 | `IncrementExpiringCounter` with `rdb == nil` → `ErrNoRedis`. |
| **rl-002** | P0 | Stub returns error → propagates. |
| **rl-003** | P0 | `len(nets)==0`: `X-Forwarded-For` present, peer would be trusted — **no** rewrite (`RemoteAddr` unchanged). |
| **rl-004** | P0 | Peer in `nets`, empty `X-Forwarded-For` → no rewrite. |
| **rl-005** | P0 | Peer in `nets`, XFF `untrusted, trusted` (rightmost untrusted first) → `RemoteAddr` becomes `untrusted:0`. |
| **rl-006** | P1 | Peer in `nets`, all XFF IPs trusted → scan ends without rewrite. |
| **rl-007** | P1 | `ClientBucketKey` / `nil` request — document or guard per **Open design notes**. |
| **rl-008** | P1 | `NewIPLimiter(0,0)` uses defaults from `iplimiter.go`. |

---

## Package: `audit`

| ID | Priority | Area | Contract |
|----|----------|------|----------|
| **audit-001** | P0 | `VerifyChain` + fake `Queryer`: zero rows → `nil` (or documented empty). |
| **audit-002** | P0 | First row non-NULL `prev_hash` → linkage error. |
| **audit-003** | P0 | Tampered `entry_hash` → error. |
| **audit-004** | P1 | `NormalizeEvent`: nil `EventID` / `CreatedAt` behavior — **no** `NormalizeEvent` clock API today; **do not** block on “add fixed clock” unless you open a design ticket. Assert observable fields (non-nil ID, UTC location) with **regression** semantics. |
| **audit-005** | P0 | Integration: `writer_test.go` with `PG_TEST_DSN`. |

**Goldens:** `vectors/testdata/audit_entry_hash.json` — covered by **vec-002** only (no duplicate audit row).

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
| **enc-001** | P0 | `Refresh`: N concurrent callers; `fn` **once**; all share result/error. |
| **enc-002** | P0 | `fn` returns error → all callers receive it. |
| **enc-003** | P1 | Cancelled context on second caller — singleflight semantics; **regression** test name states observed behavior. |

---

## Package: `httpx`

| ID | Priority | Contract |
|----|----------|----------|
| **httpx-001** | P0 | Handler exceeds `dt`, no `WriteHeader`: **504** + `{"error":"gateway_timeout"}` + JSON content-type. |
| **httpx-002** | P0 | After timeout, handler `Write` on the **ResponseWriter passed to the handler** returns `http.ErrHandlerTimeout`. | Assert via handler body, not unexported `timeoutWriter` fields. |
| **httpx-003** | P1 | Handler calls `WriteHeader(200)` then blocks past deadline: **no second 504** from middleware (client may see 200 — **regression**); assert **observable** `Recorder`/`ResponseWriter` state, not internal `tw` fields. |
| **httpx-004** | P1 | `skip(r)==true`: no artificial deadline. |
| **httpx-005** | P1 | `context.Canceled` vs `DeadlineExceeded` — **Open design notes**. |

---

## Package: `observe/safelog`

| ID | Priority | Contract |
|----|----------|----------|
| **log-001** | P1 | Denylist key → `REDACTED`. |
| **log-002** | P1 | Email-shaped string → redacted. |
| **log-003** | P2 | Nested groups / attrs per implementation. |

---

## Package: `tracking`

| ID | Priority | Contract |
|----|----------|----------|
| **trk-001** | P1 | Pixel token fails `VerifyClickRequest`; click token fails `VerifyPixelRequest` (domain separation). |

*(Issuance vs vectors: **vec-001**.)*

---

## Package: `config`

| ID | Priority | Contract |
|----|----------|----------|
| **cfg-001** | P0 | `RequireStrict` unset → strict true. |
| **cfg-002** | P0 | Unrecognized value → error with env key. |
| **cfg-003** | P0 | `RequirePGURLSSL` in production: empty DSN; `sslmode=disable` rejected. |
| **cfg-004** | P1 | `RequireRediss`: `redis://` vs `rediss://` vs empty. |

Use `t.Setenv`; isolate per test.

---

## Package: `errors`

| ID | Priority | Contract |
|----|----------|----------|
| **err-001** | P2 | `CodeOf` on wrapped `*Error`. |
| **err-002** | P2 | Non-`errors.Error` chain → `""`. |

---

## Command: `cmd/audit-verify`

| ID | Priority | Contract |
|----|----------|----------|
| **cli-001** | P1 | Missing `--dsn` → exit **2** (after `run(args)` extraction or `exec`). |
| **cli-002** | P1 | Invalid `--org` UUID → **2**. |
| **cli-003** | P1 | DB connect failure → **1**. |

---

## Implementation order (suggested)

1. **vec-001 / vec-002** — goldens first.  
2. **auth-sign-001, auth-hdr-*, auth-blob-*, auth-ts-*** — transit.  
3. **httpauth-001–004** — small.  
4. **attest-pcr-*, attest-chal-001–003** — parsing.  
5. **ssrf-url-001, ssrf-url-003, ssrf-url-004, ssrf-ip-001, ssrf-dial-001** — no DNS.  
6. **replay-ac-*, replay-cls-001–002, replay-conc-001** — stubs.  
7. **rl-003–006** — real IP middleware (table from `realip.go`).  
8. **httpx-001–002** — timeout.  
9. **audit-001–003** — fake `Queryer`.  
10. P1, P2, **P0-blocked**, integration remainder.

---

## Existing tests to preserve

Do not remove or weaken tests **without** updating goldens or intentional spec changes. **Paths may change** — treat this list as **packages to extend**, not an immutable file manifest: `vectors/`, `replay/`, `auth/`, `nethttpx/`, `audit/`, `bootstrap/`, `tracking/`, `httpx/`, `config/`, `observe/safelog/`, `attest/`, `enclaveauth/`, `httpauth/`, `httphdr/`, `ratelimit/`.

---

## Review notes (internal)

This plan was critiqued for: single-act vs **auth-can-001** (addressed by **Exception — comparing two outputs**); P0 vs flaky DNS (`ssrf-url-002` demoted; **ssrf-dns-001** **P0-blocked**); duplicate rows merged; **ValidateTimestamp** codes aligned with **current** `auth.go` (`CodeInvalidField`); **rl-003** replaced with concrete **TrustedProxyRealIP** behaviors; **httpx** avoids asserting unexported `tw.err`; **vector** byte-identical vs semantic clarified; **audit** duplicate golden removed; **nitro** explicitly out of scope until fixtures.
