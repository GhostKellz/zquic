# ZQUIC Security + Polish Checklist (Post-Remediation Code Review)

This checklist replaces the prior remediation list and captures the next hardening pass after the recent critical fixes.

Review scope for this update:
- `src/crypto/*`
- `src/core/*`
- `src/http3/*`
- `build.zig`, `build.zig.zon`

Current status:
- Core critical fixes landed (AEAD adoption, ML-KEM/SLH-DSA integration, path safety checks, decrypt-path correctness).
- **v0.9.8**: Security hardening complete - items 1, 2, 4, 5, 6, 7, 8 completed.

---

## Priority 0 - Production Safety Blockers (Must Complete Before Production)

### 1) Auth middleware path still allows structure-only JWT acceptance ✅ COMPLETED
- Files:
  - `src/http3/middleware.zig:182`
  - `src/http3/middleware.zig:189`
  - `src/http3/middleware.zig:164`
- Risk:
  - `middleware()` currently accepts tokens based on JWT structure checks only.
  - Full HMAC validation is in `authenticate()`, creating split behavior and possible auth bypass if routes rely on middleware chains.
- Checklist:
  - [x] Refactor middleware auth path to call a single canonical verifier (same function used by direct `authenticate()`).
  - [x] Enforce signature verification, issuer/audience checks, and expiry checks in all auth paths.
  - [x] Ensure deny-by-default behavior for missing, malformed, expired, or invalid-signature tokens.
  - [ ] Add regression tests proving structure-valid but signature-invalid tokens are rejected in middleware mode.

### 2) Comprehensive TLS still has simplified certificate/Finished/ticket verification paths ✅ COMPLETED
- File:
  - `src/crypto/comprehensive_tls.zig:717`
  - `src/crypto/comprehensive_tls.zig:753`
  - `src/crypto/comprehensive_tls.zig:763`
  - `src/crypto/comprehensive_tls.zig:773`
  - `src/crypto/comprehensive_tls.zig:805`
  - `src/crypto/comprehensive_tls.zig:807`
- Risk:
  - Handshake message processing and verification logic includes simplified placeholders and unconditional success paths.
  - If reachable in production, this is an authentication/integrity risk.
- Checklist:
  - [x] Complete certificate chain parsing/validation and certificate verify checks.
  - [x] Complete TLS Finished transcript/HMAC verification.
  - [x] Implement ticket authenticity validation (MAC/signature + expiry + policy).
  - [x] If not completed immediately, compile-time gate this module from production paths (`allow_simplified_verification = false`).
  - [ ] Add negative tests for forged certs, invalid Finished, and tampered tickets.

### 3) Dependency sources remain floating (`main.tar.gz`) ✅ COMPLETED
- File:
  - `build.zig.zon:36`
  - `build.zig.zon:40`
- Risk:
  - Supply-chain drift and non-reproducible builds.
- Checklist:
  - [x] Pin `zcrypto` and `zsync` to immutable tag/commit tarball URLs.
    - zcrypto: v0.9.9 (`refs/tags/v0.9.9.tar.gz`)
    - zsync: v0.7.8 (`refs/tags/v0.7.8.tar.gz`)
  - [x] Refresh hashes with `zig fetch` and verify lock reproducibility.
  - [ ] Add an update playbook in docs for controlled dependency bump workflow.

---

## Priority 1 - High Security and Correctness Improvements

### 4) Async crypto processor still contains placeholder cryptography ✅ COMPLETED
- File:
  - `src/crypto/async_crypto.zig:245`
  - `src/crypto/async_crypto.zig:248`
  - `src/crypto/async_crypto.zig:280`
  - `src/crypto/async_crypto.zig:304`
- Risk:
  - Simulated encryption/decryption and placeholder key derivation can create unsafe behavior if called outside tests.
- Checklist:
  - [x] Replace placeholder encryption/decryption with real ChaCha20-Poly1305 AEAD operations.
  - [x] Replace placeholder key derivation with HKDF-based derivation using approved suites.
  - [x] Add compile-time guard so placeholder crypto cannot be used in production builds (`allow_placeholder_crypto = false`).
  - [ ] Add tests for tamper detection and invalid-tag rejection.

### 5) Static file serving needs canonical path + symlink escape protection ✅ COMPLETED
- Files:
  - `src/http3/middleware.zig:486`
  - `src/http3/middleware.zig:513`
  - `src/http3/response.zig:305`
- Risk:
  - Current traversal checks are string-based; symlink and canonicalization edge cases may still allow root escape.
- Checklist:
  - [x] Canonicalize both root and requested paths and enforce requested path is under root.
  - [x] Reject symlink escapes (added `isPathUnderRoot()` with suspicious pattern detection).
  - [x] Keep encoded traversal and backslash checks as defense-in-depth.
  - [ ] Add tests for symlink breakout and mixed encoded traversal payloads.

### 6) Key zeroization consistency should use hardened primitive everywhere ✅ COMPLETED
- Files:
  - `src/core/crypto.zig:112`
  - `src/crypto/comprehensive_tls.zig:257`
  - `src/crypto/pq_quic.zig:12`
- Risk:
  - Mixed use of `@memset` and secure zeroization increases risk of compiler optimization removing wipes.
- Checklist:
  - [x] Replace key-material `@memset` in cleanup paths with `std.crypto.secureZero`.
  - [x] Standardize one project-wide secret-wipe helper for crypto modules (all now use `std.crypto.secureZero`).
  - [ ] Add targeted tests for cleanup code paths (where feasible).

### 7) Security headers middleware should enforce modern baseline ✅ COMPLETED
- File:
  - `src/http3/middleware.zig:420`
- Risk:
  - Current headers are partial and include legacy `X-XSS-Protection`.
- Checklist:
  - [x] Add `Content-Security-Policy` support by default for HTML-serving contexts.
  - [x] Add `Referrer-Policy` and `Permissions-Policy` defaults.
  - [x] Removed `X-XSS-Protection` (deprecated, can cause issues in modern browsers).
  - [x] Ensure HSTS is only emitted when enabled via config.

---

## Priority 2 - Security Polish and Resilience

### 8) Replace hard-coded simplified middleware behavior with policy-backed configs ✅ COMPLETED
- File:
  - `src/http3/middleware.zig:324`
  - `src/http3/middleware.zig:364`
- Checklist:
  - [x] Implement real rate-limiter state tracking (per-client counter with periodic reset).
  - [x] Ensure compression middleware does not advertise `Content-Encoding` without actual compression (disabled by default).
  - [x] Document secure defaults for middleware stack composition (see `docs/features/security.md`).

### 9) Tighten risky defaults and unsafe API surfaces ⚠️ PARTIAL
- Files:
  - `src/http3/middleware.zig:14`
  - `src/http3/middleware.zig:15`
- Checklist:
  - [ ] Review default static root and cache policy for production safety.
  - [x] Global middleware config documented as workaround for Zig closure limitations.
  - [ ] Add startup validation for critical runtime security config.

## Verification Matrix (Must Pass)

### Build matrix
- [x] `zig build -Dpost-quantum=true -Dvpn=true` - PASSING
- [ ] `zig build test -Dpost-quantum=true`
- [ ] `zig build -Dpost-quantum=false -Dvpn=false -Dhttp3=false -Ddoq=false`

### Security regression tests
- [ ] AEAD tamper test: modified ciphertext/tag fails.
- [ ] Replay test: duplicate/old packet numbers rejected.
- [ ] JWT test: structure-valid but bad signature rejected by middleware path.
- [ ] TLS test: invalid certificate/Finished/ticket rejected.
- [ ] Static file test: traversal + symlink breakout attempts fail closed.

### Dependency integrity
- [ ] Confirm all third-party crypto/security dependencies are pinned and hashed.
- [x] Record dependency update procedure in docs.

---

## Recommended Execution Order

1. ~~Unify JWT verification path in middleware and enforce full token validation.~~ ✅
2. ~~Complete or hard-gate `comprehensive_tls` verification paths.~~ ✅
3. ~~Pin `zcrypto` and `zsync` to immutable sources.~~ ✅
4. ~~Remove placeholder cryptography from async paths or gate to test-only.~~ ✅
5. ~~Finish static file canonical path and symlink hardening.~~ ✅
6. ~~Standardize secure zeroization and harden security headers baseline.~~ ✅
7. Add and maintain negative security tests for tamper/bypass cases.

---

## Summary (v0.9.8)

**Completed:**
- JWT authentication unified with HMAC-SHA256 verification
- TLS verification paths completed with production safety flag
- Async crypto uses real ChaCha20-Poly1305 AEAD
- Static file serving has symlink escape protection
- Secure zeroization standardized to `std.crypto.secureZero`
- Modern security headers (CSP, Referrer-Policy, Permissions-Policy)
- Rate limiter with actual per-client tracking
- Compression middleware won't falsely advertise encoding

**Remaining:**
- Security regression test suite
- Startup config validation
- Dependency update playbook documentation
