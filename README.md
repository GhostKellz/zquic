<h1 align="center">ZQUIC</h1>

<p align="center">
  <strong>QUIC Transport for Zig</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Zig-F7A41D?style=for-the-badge&logo=zig&logoColor=white" alt="Zig">
  <img src="https://img.shields.io/badge/QUIC-v1-2496ED?style=for-the-badge" alt="QUIC v1">
  <img src="https://img.shields.io/badge/HTTP%2F3-enabled-2496ED?style=for-the-badge" alt="HTTP/3">
  <img src="https://img.shields.io/badge/Post--Quantum-ML--KEM-76B900?style=for-the-badge" alt="Post-Quantum">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License">
</p>

ZQUIC is a **modular, high-performance QUIC transport stack** built entirely in Zig 0.17.0-dev. It ships with a native async runtime (no external deps), stable QUIC/HTTP3 cryptography, explicit experimental post-quantum hooks via `zcrypto`, SSH/QUIC secret injection support, and HTTP/3, DoQ, VPN, and service layers tuned for Ghost workloads.

> ✅ Builds cleanly with Zig 0.17.0-dev on Linux/macOS/Windows and passes the `dev/test.sh` suite.

## 🎯 Purpose & Vision

**ZQUIC provides a modular networking foundation for Zig applications:**

- 🧩 **Pick-your-build**: Core QUIC only for embedded targets or full HTTP/3 + services for servers
- 🛡️ **Explicit crypto posture**: Stable X25519/AEAD defaults with opt-in experimental ML-KEM and ML-DSA-65 via `zcrypto`
- ⚡ **Native async runtime**: Poll-based event loop, timer wheel, and connection pool in-tree
- 🌐 **Complete stack**: QUIC core, HTTP/3 server, DNS-over-QUIC, Ghost services, and VPN layers
- 📊 **Operational insight**: Built-in monitoring hooks and Prometheus-friendly metrics emitters
- 📦 **Clean tooling**: Straightforward `zig build` targets plus `dev/` scripts for local workflows

## 🧩 Modular Build System

| Build Type | Key Flags | Typical Size | Notes |
|------------|-----------|--------------|-------|
| **Minimal Core** | `-Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false` | ~1.3 MB | Event loop + core QUIC only |
| **Web Stack** | `-Dhttp3=true -Ddoq=true` | ~3.5 MB | HTTP/3 server, DoQ resolver |
| **Enterprise** | `-Dservices=true -Dvpn=true -Dmonitoring=true` | ~5.5 MB | Adds services, VPN, monitoring |
| **With PQ Crypto** | `-Dpost-quantum=true -Dexperimental-crypto=true` | +~0.5 MB | Experimental ML-KEM and ML-DSA-65 support |

```bash
# Minimal embedded target
zig build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Doptimize=ReleaseSmall

# HTTP/3 + DoQ server (stable crypto)
zig build -Dhttp3=true -Ddoq=true -Dservices=false -Dvpn=false -Doptimize=ReleaseFast

# Default build (HTTP/3, DoQ enabled; PQ disabled)
zig build

# With experimental post-quantum crypto
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

## ✨ Core Features

### 🔐 **Cryptography**
- **Ed25519** and **Secp256k1** signatures (stable)
- **X25519** key exchange (stable)
- **AES-256-GCM** and **ChaCha20-Poly1305** AEAD (stable)
- **Blake3** and **SHA256** hashing (stable)
- **Zero-RTT resumption**: Ultra-low latency with anti-replay protection

### 🧪 **Post-Quantum Cryptography** *(Experimental)*
- **Hybrid TLS 1.3**: ML-KEM-768 + X25519 key exchange
- **ML-DSA-65** post-quantum digital signatures (FIPS 204)
- Requires `-Dpost-quantum=true -Dexperimental-crypto=true`

### 🔑 **SSH/QUIC Integration**
- **SSH secret injection**: Bypass TLS handshake using SSH-derived secrets ([draft-denis-ssh-quic](https://datatracker.ietf.org/doc/draft-denis-ssh-quic/))
- **Secure key handling**: Secrets passed by pointer, automatic zeroing on cleanup
- **Bidirectional encryption**: Proper local/remote key separation for client ↔ server traffic
- **TLS fallback**: `SshQuicContext` supports both SSH-injected and standard TLS modes
- **Zero-copy secrets**: `initFromPtrs()` avoids unnecessary stack copies of sensitive material

```zig
// Example: Initialize QUIC with SSH-derived secrets
var secrets = zquic.SshQuic.SshQuicSecrets.init(client_secret, server_secret);
defer secrets.zeroize(); // Secure cleanup

var ctx = try zquic.SshQuic.SshQuicContext.initWithSshSecrets(
    allocator,
    is_server,
    &secrets,
);
defer ctx.deinit();

// Ready to encrypt/decrypt without TLS handshake
const ciphertext = try ctx.encrypt(plaintext, packet_number, allocator);
```

### 🌐 **Advanced Transport Stack**
- **Full QUIC v1 compliance**: connection management, streams, flow control
- **BBR/CUBIC congestion control**: crypto-optimized for trading workloads
- **Connection pooling**: high-performance multiplexing for crypto protocols
- **HTTP/3 server**: production-ready with advanced middleware
- **Consistent middleware execution**: router fallback invokes global middleware (logging, static assets, auth) even when no route matches, so 404s still pass through your filters.
- **QUIC-over-UDP VPN (experimental)**: `docs/features/quic_vpn.md` + new demos show how to tunnel mesh traffic as a concept alternative to Tailscale/NetBird.
- **Zero-copy packet processing**: optimized for 100K+ TPS
- **IPv6-first networking**: dual-stack with modern internet protocols

### 🏗️ **High-Level Services**
- **QUIC Bridge**: gRPC-over-QUIC relay for service communication
- **QUIC Proxy**: Post-quantum reverse proxy and load balancer
- **DNS-over-QUIC**: Secure DNS resolver for modern applications
- **FFI integration**: Production bindings for cross-language projects
- **WASM integration**: Runtime communication over QUIC transport

### 📊 **Production Monitoring & Telemetry**
- **Real-time metrics**: performance monitoring and analytics
- **Prometheus integration**: dedicated exporter surfaces HTTP/3, DoQ, and VPN metrics ready for `/metrics`
- **Alerting system**: configurable thresholds for high-throughput workloads
- **Connection health**: advanced diagnostics for network infrastructure
- **Protocol analytics**: detailed breakdown of DoQ/HTTP3/gRPC usage

### ⚡ **Performance & Reliability**
- **100K+ transactions/second** transport capability
- **<1ms latency** for critical path operations with Zero-RTT
- **Sub-10ms** connection establishment with hybrid PQ-TLS
- **Zero-copy operations** throughout the entire stack
- **Deterministic memory management** with predictable allocation patterns
- **Advanced congestion control** optimized for high-throughput networking

## 📚 Documentation

- **`docs/getting-started/quick-start.md`** – bootstrap instructions
- **`docs/getting-started/build-config.md`** – flag reference kept in sync with `build.zig`
- **`docs/architecture/overview.md`** – async runtime + protocol layering notes
- **`docs/architecture/async-runtime.md`** – explains the in-tree async runtime that replaced zsync
- **`docs/examples/`** – walkthroughs mirroring the binaries prepared by `zig build`
- **`docs/features/README.md` & `docs/features/quic_vpn.md`** – catalogue of major modules plus the experimental QUIC VPN deep dive
- **`docs/integrations/prometheus.md`** – how to attach the exporter and what metrics to expect
- **`docs/integrations/zcrypto.md`** – tuning notes for PQ TLS + VPN helpers
- **`examples/*.zig`** – runnable samples that match the documentation

## 🔍 Why Zig?

- **Manual memory management** for performance + predictability
- **Compile-time safety** with low runtime cost
- **Works well** in high-performance and embedded networking environments
- **No hidden allocations** or runtime overhead
- **Cross-platform** support with consistent behavior

## 🚀 Quick Start

### Zig Integration
```bash
zig fetch --save https://github.com/ghostkellz/zquic/archive/main.tar.gz
```

### Installation

```bash
git clone https://github.com/ghostkellz/zquic
cd zquic
zig build        # produces all enabled binaries under zig-out/bin/
```

Keep the dependency metadata intact (`build.zig.zon` pins dependencies) and build with the latest Zig 0.17.0-dev toolchain. Use `zig build -Dtarget=<triple>` for cross compilation.

### Local Development Loop

```bash
# Format and lint quickly
./dev/fmt.sh

# Full build + test sweep (unit + integration + fuzz)
./dev/test.sh

# Smoke test HTTP/3 or DoQ locally
./dev/smoke_test.sh
# QUIC VPN routing smoke (experimental)
./dev/vpn_smoke.sh
```

Prefer individual commands? Run `zig build integration-tests` for handshake coverage or `zig build fuzz-tests` for the packet parser harness.

The `dev/` scripts wrap the raw `zig` commands and provide the configuration we use in CI (re-enabling CI workflows is tracked separately).

## 🎯 Production Readiness Status


### ✅ Production Checklist

| Component | Status | Notes |
|-----------|--------|-------|
| Core QUIC | ✅ | Streams, flow control, congestion modules covered by unit tests |
| Post-Quantum Crypto | ⚠️ Experimental | Hybrid ML-KEM-768/1024 + X25519 via `zcrypto` (requires `-Dpost-quantum=true -Dexperimental-crypto=true`) |
| HTTP/3 & DoQ | ✅ | Examples compile by default, exercised via `dev/smoke_test.sh` |
| Async Runtime | ✅ | Native event loop + timer wheel; no external dependencies |
| Monitoring Hooks | ✅ | Metrics surfaces in `src/monitoring/*` wired into runtime |
| Dev Tooling | ✅ | `dev/*.sh` scripts for build, fmt, smoke, and validation |

### 🚀 Key Achievements
- 6 shipping binaries under `zig-out/bin/`
- Clean Zig 0.17.0-dev builds across Linux/macOS/Windows
- Internal async runtime + connection pool validated via new tests
- Documentation refreshed to match current feature flags

### 📈 Performance Targets
- ReleaseFast builds target 100K+ TPS workloads
- <1 ms Zero-RTT handshakes when PQ is enabled
- Deterministic memory behavior verified through integration tests and leak checks

### Basic Usage (Zig)

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configure HTTP/3 server
    const config = zquic.Http3.ServerConfig{
        .max_connections = 10000,
        .enable_compression = true,
        .enable_cors = true,
        .enable_security_headers = true,
    };

    // Initialize HTTP/3 server
    var server = try zquic.Http3.Http3Server.init(allocator, config);
    defer server.deinit();

    // Add routes via the router
    try server.router.get("/", homeHandler);
    try server.router.get("/api/status", statusHandler);
    try server.router.post("/api/data", submitHandler);

    // Start server
    try server.start();
    std.debug.print("HTTP/3 server running on QUIC\n", .{});
}

fn homeHandler(_: *zquic.Http3.Request, res: *zquic.Http3.Response) !void {
    try res.setStatus(.ok);
    try res.setBody("Welcome to ZQUIC");
}

fn statusHandler(_: *zquic.Http3.Request, res: *zquic.Http3.Response) !void {
    try res.setStatus(.ok);
    try res.setBody("{\"status\": \"online\"}");
}

fn submitHandler(req: *zquic.Http3.Request, res: *zquic.Http3.Response) !void {
    _ = req;
    try res.setStatus(.created);
    try res.setBody("{\"created\": true}");
}
```

## 🏗️ Architecture Snapshot

- **`src/async/`** – native event loop, timer wheel, and runtime orchestration
- **`src/core/`** – QUIC transport (connection, stream, packet, recovery, flow control)
- **`src/crypto/`** – TLS 1.3 + PQ handshake glue over `zcrypto`
- **`src/http3/`** – frame parsing, router, middleware, and advanced server
- **`src/doq/`** – DNS-over-QUIC client/server implementations
- **`src/services/`** – GhostBridge, Wraith, CNS resolver, and VPN adapters
- **`src/monitoring/`** – metrics hooks for Prometheus/exporters
- **`examples/`** – runnable demos built during `zig build`

## 🔧 Local Development Workflow

1. `./dev/deps.sh` – ensure Zig toolchain + deps are ready
2. `./dev/build_all.sh` – compile every target with current feature flags
3. `./dev/test.sh` – runs `zig build test`, `zig build integration-tests`, and `zig build fuzz-tests` (network-dependent tests emit warnings)
4. `./dev/smoke_test.sh` – launch sample client/server pairs for manual validation
5. `zig fmt src/ docs/ examples/` – formatting gate before opening PRs

## 🤝 Contributing

Please read `CONTRIBUTING.md` for coding standards, testing expectations, and PR workflow. At a minimum run `./dev/test.sh` and ensure new code paths include unit or integration coverage.

## 📄 License

Apache 2.0 — built to power the post-quantum future with modern Zig applications.
