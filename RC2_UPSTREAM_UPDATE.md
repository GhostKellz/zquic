Here’s a copy-pasteable **`TODO.md`** for **ZQUIC v0.9.1-RC2** tailored to your RC1 state. It focuses on upstream-friendliness (stdlib-style APIs, small error sets, interop/Conformance), while preserving your modular build story.

---

# TODO — ZQUIC v0.9.1-RC2 “Streamer / Upstream-Ready”

**Date target:** 2025-Q4
**From:** v0.9.0-RC1 (completed 2025-09-24)
**Theme:** Make ZQUIC compelling as a candidate for `std.net.quic` / `std.http3` by tightening APIs, adding interop/fuzz suites, and documenting a minimal “Streamer” surface (Reader/Writer-first, zero hidden allocs).

---

## 0) Release Scope

* **Non-goals:** New features (keep PQ/VPN/Services stable).
* **Goals:** API polish, std-style naming/error sets, explicit allocator flow, conformance, size/perf proofs, and a clean RFC doc.

---

## 1) API Polish — “Streamer” Surface

**Objective:** Present a tiny, std-shaped QUIC/H3 API that mirrors `std.io.Reader/Writer` and `std.http` patterns.

* [ ] **Public types (minimal):**

  ```zig
  pub const QuicListener = struct { ... };
  pub const QuicConn     = struct { ... };
  pub const BidiStream   = struct { reader: Reader, writer: Writer };
  pub const UniStream    = struct { reader: Reader } // or writer
  pub const Datagram     = []const u8;
  ```
* [ ] **H3 minimal types:**

  ```zig
  pub const H3Server          = struct { ... };
  pub const H3Request         = struct { method: []const u8, path: []const u8, headers: Headers, body: Reader };
  pub const H3ResponseWriter  = struct { headers: Headers, body: Writer, fn send(status: u16) !void };
  pub const H3Client          = struct { /* pooled control streams */ };
  ```
* [ ] **No hidden allocations** in public methods; document who frees what.
* [ ] **Std-style error sets** only (audit every public fn):

  * `error.Temporary, error.Timeout, error.Closed, error.ConnectionReset, error.Canceled, error.ResourceExhausted, error.Protocol`
* [ ] **Naming pass:** lowerCamel functions, UpperCamel types; consistent `init/deinit`.

**Deliverable:** `docs/api-minimal.md` with the above surfaces + usage snippets.

---

## 2) Layering & Build Flags (keep RC1 wins, clarify defaults)

* [ ] Ensure **core** (QUIC) is independent of `http3/` and PQ TLS.
* [ ] Default flags for upstream demo:

  * `-Dhttp3=false` (off by default)
  * `-Dpq=false`
  * `-Ddoq=false` `-Dservices=false` `-Dvpn=false`
  * `-Ddatagrams=true`
  * `-Dio_uring=true` (Linux), `-Dkqueue=true` (BSD/macOS)
* [ ] Presets (documented):

  * `-Dprofile=minimal` (QUIC only)
  * `-Dprofile=web` (QUIC + H3)
  * `-Dprofile=enterprise` (all RC1 features)
* [ ] Size table regenerated for each preset (ReleaseFast & ReleaseSmall).

---

## 3) TLS Provider Shim (stdlib-friendly)

* [ ] Introduce `TlsProvider` trait used by QUIC core only:

  ```zig
  pub const TlsProvider = struct {
      client: fn (*const ClientConfig) !TlsClient,
      server: fn (*const ServerConfig) !TlsServer,
  };
  ```
* [ ] Provide one built-in binding (`-Dtls=zcrypto`) and document how to plug a different provider.
* [ ] Gate PQ algorithms behind `-Dpq`.

---

## 4) HTTP/3 API Trim & QPACK

* [ ] **H3 request/response** kept minimal (no server push).
* [ ] QPACK split into `qpack/encoder.zig` and `qpack/decoder.zig`; dynamic table sizes configurable; document defaults.
* [ ] GOAWAY + graceful shutdown examples (client & server).

---

## 5) Interop & Conformance

**Goal:** Green against major stacks; publish a matrix.

* [ ] `interop/` with scripts to test vs **ngtcp2**, **quiche**, **msquic**:

  * Handshake (1-RTT / 0-RTT), stream echo (uni/bidi), datagram echo,
  * H3 GET/POST, headers with QPACK dyn tables, GOAWAY.
* [ ] CI job (Docker) runs interop on Linux; publish badges/table in README.
* [ ] RFC checklists (RFC 9000/9001/9002, RFC 9114, RFC 9204) mapped to tests in `docs/conformance.md`.

---

## 6) Fuzzing & Property Testing

* [ ] **Packet decoder fuzz** (AFL/LibFuzzer harness).
* [ ] **QPACK decoder fuzz** (malformed headers, dyn table abuse).
* [ ] **Property tests** using GhostSpec:

  * Packet loss/reorder/duplication models (no deadlocks, bounded memory).
  * Flow control invariants (no window underflows/overflows).
* [ ] 24h CI soak (ASAN/UBSAN) with seeds persisted.

---

## 7) Performance & “Streamer” Benchmarks

* [ ] Micro-bench on loopback (ReleaseFast):

  * `open/close`, `bidi 64k`, `4k msgs`, `datagram 1200B`,
  * H3 GET 1k/64k payloads.
* [ ] Publish p50/p95/p99 latency & throughput; include CPU/time per module.
* [ ] Memory profiles: connection & stream arena footprints under load.
* [ ] Zero-copy verification for hot paths (document “copy points” table).

---

## 8) Testing & Golden Traces

* [ ] Expand **golden traces** for recovery/loss/CC:

  * PTO fire, TLP, cwnd growth/slow-start, key update rotate.
* [ ] Re-use your new `recovery.zig` & `packet_space.zig` to emit deterministic traces in `tests/golden/`.
* [ ] Include a `make trace` helper that regenerates & verifies.

---

## 9) Examples (updated to Streamer API)

* [ ] `examples/quic_echo_server.zig` / `quic_echo_client.zig` (Reader/Writer).
* [ ] `examples/datagram_echo.zig`.
* [ ] `examples/h3_server.zig` / `h3_client.zig` (GET/POST, GOAWAY).
* [ ] `examples/0rtt_client.zig` (if TLS provider supports 0-RTT).
* [ ] Each example builds under **minimal** (QUIC only) or **web** (H3).

---

## 10) Docs & Upstream Pitch

* [ ] `docs/upstream-rfc.md`:

  * Proposed `std.net.quic` API (taken from Streamer surface),
  * Proposed `std.http3` minimal API,
  * Maintenance scope: what **does not** belong in std (PQ, DoQ, Proxy, VPN),
  * Interop & fuzz evidence, perf/size tables.
* [ ] `docs/build-profiles.md` (exact flags, sizes, constraints).
* [ ] `docs/migration-rc1-rc2.md` (what changed since RC1).

---

## 11) CI / Gatekeeping

* [ ] Matrix: Linux x86\_64/aarch64, macOS aarch64, FreeBSD.
* [ ] API guard: fail CI on public-API or error-set changes without version bump.
* [ ] Fuzz targets build in CI; nightly soak job.
* [ ] Interop job publishes HTML summary artifact.

---

## 12) Versioning & Release Checklist

* [ ] Bump to **v0.9.1-RC2**.
* [ ] Release notes must include:

  * Streamer API summary (minimal surfaces),
  * Error-set standardization,
  * Interop matrix results,
  * Size & latency tables for **minimal/web/enterprise**,
  * Link to `docs/upstream-rfc.md`.
* [ ] Tag reproducible builds for presets; upload example binaries.

---

## Acceptance Criteria

* [ ] `zig build -Dprofile=minimal` → QUIC-only lib (no H3/PQ code) with examples running.
* [ ] `zig build -Dprofile=web -Dhttp3=true` → H3 server/client pass interop GET/POST + GOAWAY.
* [ ] Fuzzers (packet/QPACK) run 24h with **0 crashes**.
* [ ] Public APIs expose **only** Streamer surfaces; error sets match spec.
* [ ] Docs (RFC + conformance + profiles) are complete and referenceable.

---

## Suggested Commit Plan

1. `api(streamer): introduce minimal public surfaces & std-style errors`
2. `tls: add TlsProvider shim; wire zcrypto provider behind -Dtls=zcrypto`
3. `http3: trim API; split qpack encoder/decoder`
4. `build: defaults to minimal; add profiles & size table target`
5. `interop: add ngtcp2/quiche/msquic runners + CI`
6. `fuzz: packet & qpack harness; nightly soak`
7. `bench: micro-bench suite; docs/perf tables`
8. `docs: upstream-rfc.md, conformance.md, build-profiles.md`
9. `release: v0.9.1-rc2`

---

### Notes

* RC1 already nailed **Zig 0.16** fixes, allocator hygiene, error centralization, and modular core—keep those intact.
* Keep **PQ / VPN / Services** fully functional but **off by default**; upstream reviewers care about lean core + proof of correctness.
* Ensure `zrpc-transport-quic` consumes only the Streamer surface (no private hooks) to demonstrate clean layering to the Zig team.

---

