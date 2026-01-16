# ZQUIC Roadmap

## Phase 1: Test Infrastructure ✓
- [x] Create unit tests for `src/core/` modules
- [x] Create unit tests for `src/crypto/` modules
- [x] Create integration tests for client/server handshake
- [x] Add fuzz testing for packet parsing
- [ ] Set up test coverage reporting (kcov or similar)
- [x] Create `dev/test.sh` script for running all tests

## Phase 2: Documentation Cleanup (In Progress)
- [x] Update README.md (version refs updated to v0.9.5)
- [ ] Audit and update `docs/` content for accuracy
- [ ] Add inline doc comments to all public APIs
- [x] Create CONTRIBUTING.md with development guidelines
- [x] Document build flags and configuration options (`docs/getting-started/build-config.md`)

## Phase 3: Error Handling Audit ✓ (v0.9.5)
- [x] Audit all error paths for proper cleanup (added errdefer chains)
- [x] Ensure no resource leaks on error conditions (errdefer on create/alloc)
- [x] Add error context/tracing for debugging (logging with IDs and error codes)
- [ ] Standardize error types across modules
- [x] Add proper error logging hooks (all catch {} blocks now log)

## Phase 4: Memory Safety ✓ (v0.9.5)
- [x] Audit all allocator usage patterns (errdefer added throughout)
- [x] Add memory leak detection in debug builds (`dev/perf_memory.sh`)
- [x] Verify all `deinit()` paths are called (reviewed in hardening)
- [ ] Add arena allocators where appropriate
- [x] Profile memory usage under load (`dev/perf_all.sh`)

## Phase 5: Performance Optimization ✓ (v0.9.5)
- [x] Profile hot paths with `zig build -Doptimize=ReleaseFast` (`dev/perf_bench.sh`)
- [ ] Optimize packet serialization/parsing
- [x] Reduce allocations in critical paths (O(n²) → O(n) fixes)
- [x] Add zero-copy receive path (stream.zig read_start offset)
- [ ] Benchmark against quinn (Rust QUIC)
- [x] Create `benchmarks/` directory with reproducible benchmarks (`dev/perf_*.sh`)

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

## Phase 8: Production Readiness (Partial ✓)
- [ ] Add graceful shutdown handling
- [ ] Implement connection draining
- [ ] Add health check endpoints
- [ ] Create production deployment guide
- [x] Add metrics export (Prometheus format) - `src/monitoring/prometheus_exporter.zig`
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

## Current Status: v0.9.5

**Completed in v0.9.5 (Production Hardening):**
- [x] Eliminated all `catch unreachable` (38 occurrences fixed)
- [x] Eliminated all silent `catch {}` (13 blocks now have logging)
- [x] Added errdefer chains for memory safety
- [x] Fixed O(n²) orderedRemove → O(n) batch processing
- [x] Fixed O(n²) compact() → O(n) two-pointer algorithm
- [x] Fixed O(n) memmove → O(1) read_start offset
- [x] Added safe Time utilities in `src/utils/time.zig`
- [x] Added performance testing scripts (`dev/perf_*.sh`)
- [x] Removed GPU check from CI (vmhost2 has no GPU)

**Previously Completed:**
- [x] Zig 0.16.0-dev.2193+ compatibility
- [x] Clean build (6 binaries, zero errors)
- [x] Modular architecture (core, crypto, http3, doq, vpn, services)
- [x] Post-quantum crypto integration via zcrypto (ML-KEM-768 + SLH-DSA)
- [x] Local dev scripts in `dev/` (19 scripts total)
- [x] Internal async runtime (zsync fully removed)
- [x] CI workflows operational on self-hosted runner (vmhost2)
- [x] CONTRIBUTING.md with full contributor workflow
- [x] Build flag documentation in `docs/getting-started/build-config.md`

**Integration Tests:**
- [x] `tests/handshake_integration_test.zig`
- [x] `tests/http3_integration_test.zig`
- [x] `tests/doq_integration_test.zig`
- [x] `tests/services_integration_test.zig`
- [x] `tests/zcrypto_integration_test.zig`
- [x] `tests/packet_fuzz_test.zig`

**Next Priority:**
- Inline doc comments for public APIs (`src/root.zig` exports)
- Test coverage reporting setup (kcov or similar)
- Docs content audit (`docs/getting-started/`, `docs/architecture/`)
- Protocol compliance testing (RFC 9000/9001/9002/9114)
- Security hardening audit
