# ZQUIC Roadmap

## Phase 1: Test Infrastructure
- [x] Create unit tests for `src/core/` modules
- [x] Create unit tests for `src/crypto/` modules
- [x] Create integration tests for client/server handshake
- [x] Add fuzz testing for packet parsing
- [ ] Set up test coverage reporting
- [x] Create `dev/test.sh` script for running all tests

## Phase 2: Documentation Cleanup
- [ ] Update README.md (remove stale badges, fix asset paths)
- [ ] Audit and update `docs/` content for accuracy
- [ ] Add inline doc comments to all public APIs
- [ ] Create CONTRIBUTING.md with development guidelines
- [ ] Document build flags and configuration options

### Phase 2 Execution Plan
1. **README refresh:** remove obsolete build badges, link new integration tests, and consolidate feature matrix once HTTP/3/services notes are stable.
2. **Docs audit sweep:** prioritize `docs/getting-started/` and `docs/architecture/` folders, logging mismatches in a tracking table before touching long-tail guides.
3. **Inline API comments:** start with `src/core/` and `src/http3/` exports, using succinct `///` doc comments only for public symbols surfaced via `src/root.zig`.
4. **CONTRIBUTING revamp:** merge existing CONTRIBUTING.md stubs with `dev/` script explanations so contributor workflow (format/test/build) is explicit.
5. **Build flag reference:** extend `docs/getting-started/build-config.md` with a table covering `-Dhttp3`, `-Dservices`, `-Dpost-quantum`, etc., noting default values and related tests.

## Phase 3: Error Handling Audit
- [ ] Audit all error paths for proper cleanup
- [ ] Ensure no resource leaks on error conditions
- [ ] Add error context/tracing for debugging
- [ ] Standardize error types across modules
- [ ] Add proper error logging hooks

## Phase 4: Memory Safety
- [ ] Audit all allocator usage patterns
- [ ] Add memory leak detection in debug builds
- [ ] Verify all `deinit()` paths are called
- [ ] Add arena allocators where appropriate
- [ ] Profile memory usage under load

## Phase 5: Performance Optimization
- [ ] Profile hot paths with `zig build -Doptimize=ReleaseFast`
- [ ] Optimize packet serialization/parsing
- [ ] Reduce allocations in critical paths
- [ ] Add zero-copy receive path
- [ ] Benchmark against quinn (Rust QUIC)
- [ ] Create `benchmarks/` directory with reproducible benchmarks

## Phase 6: Protocol Compliance
- [ ] Run against QUIC interop test suite
- [ ] Verify RFC 9000 compliance (QUIC transport)
- [ ] Verify RFC 9001 compliance (QUIC TLS)
- [ ] Verify RFC 9002 compliance (loss detection)
- [ ] Verify RFC 9114 compliance (HTTP/3)
- [ ] Fix any compliance gaps found

## Phase 7: Security Hardening
- [ ] Security audit of crypto implementations
- [ ] Add constant-time comparisons where needed
- [ ] Audit for timing side channels
- [ ] Add rate limiting for connection attempts
- [ ] Implement address validation tokens
- [ ] Add amplification attack mitigations

## Phase 8: Production Readiness
- [ ] Add graceful shutdown handling
- [ ] Implement connection draining
- [ ] Add health check endpoints
- [ ] Create production deployment guide
- [ ] Add metrics export (Prometheus format)
- [ ] Stress test with 10K+ concurrent connections

## Phase 9: API Stabilization
- [ ] Review and finalize public API surface
- [ ] Add deprecation warnings for any breaking changes
- [ ] Document API stability guarantees
- [ ] Create migration guide from v0.x to v1.0
- [ ] Freeze public API for v1.0

## Phase 10: Release v1.0.0
- [ ] Final code review and cleanup
- [ ] Update version to 1.0.0
- [ ] Write release notes
- [ ] Tag release
- [ ] Publish to Zig package index

---

## Current Status: v0.9.3

**Completed:**
- [x] Zig 0.16.0-dev compatibility
- [x] Clean build (6 binaries, zero errors)
- [x] Modular architecture (core, crypto, http3, doq, vpn, services)
- [x] Post-quantum crypto integration via zcrypto
- [x] Local dev scripts in `dev/`
- [x] Internal async runtime (zsync fully removed)

**Known Issues:**
- Need service-level integration tests under `tests/` (DoQ remaining; HTTP/3 + services covered)
- CI workflows disabled; re-enable GitHub Actions for regression coverage
