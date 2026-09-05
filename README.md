<h1 align="center">ZQUIC</h1>

<p align="center"><strong>Experimental QUIC transport components for Zig</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/Zig-F7A41D?style=for-the-badge&logo=zig&logoColor=white" alt="Zig">
  <img src="https://img.shields.io/badge/QUIC-v1-2496ED?style=for-the-badge" alt="QUIC v1">
  <img src="https://img.shields.io/badge/HTTP%2F3-bounded-2496ED?style=for-the-badge" alt="HTTP/3">
  <img src="https://img.shields.io/badge/Post--Quantum-experimental-76B900?style=for-the-badge" alt="Post-Quantum">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License">
</p>

ZQUIC is a modular Zig codebase for QUIC packet protection, connection and
stream state, recovery, HTTP/3 and DoQ components, and opt-in cryptographic
experiments. Version 0.9.17 adds a bounded server probe that completes a TLS
1.3 and fixed HTTP/3 `GET /` exchange against quiche, ngtcp2/gtlsclient, and
aioquic. That evidence is intentionally narrower than a production-ready or
generally interoperable QUIC stack.

## Build

Use the Zig version declared by `minimum_zig_version` in `build.zig.zon` or a
compatible newer development build.

```bash
zig build
zig build test --summary all
zig build integration-tests --summary all
zig build fuzz-tests --summary all
```

Common profiles:

```bash
# Minimal core build
zig build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Dexamples=false

# Optional services, VPN, and monitoring
zig build -Dservices=true -Dvpn=true -Dmonitoring=true

# Experimental post-quantum paths
zig build test -Dpost-quantum=true -Dexperimental-crypto=true
```

The source archive for a tagged release can be added to another Zig project
with:

```bash
zig fetch --save https://github.com/ghostkellz/zquic/archive/refs/tags/v0.9.17.tar.gz
```

## Public Surface

`@import("zquic")` exposes module-oriented core APIs:

- `Connection.Connection` and `Connection.SuperConnection`;
- `Packet`, `Stream`, `FlowControl`, and `Congestion` modules;
- `PacketCrypto` plus bounded TLS 1.3/RFC 9001 helpers;
- feature-gated `Http3`, `DoQ`, services, VPN, monitoring, and post-quantum
  modules; and
- UDP, multiplexer, transport, and native async-runtime components.

Minimal connection usage:

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn example(allocator: std.mem.Allocator) !void {
    var connection = try zquic.Connection.Connection.init(
        allocator,
        .client,
        .{},
    );
    defer connection.deinit();

    const stream = try connection.createStream(.client_bidirectional);
    _ = try stream.write("hello", false);
}
```

See the [Core API Reference](docs/api/core.md) for ownership and maturity
boundaries.

## Release Validation

The local release matrix is:

```bash
./dev/validate.sh
./dev/consumer_smoke_test.sh
./dev/docker_validate.sh release
./dev/docker_validate.sh interop-zquic-server
```

The interop target has stricter opt-in gates for complete handshake,
application decryption, ACK/recovery evidence, and exact HTTP/3 response bodies.
See [Interop Methodology](docs/interop/methodology.md) for the evidence levels
and exact variables.

Zig runs normally with its default cache unless a caller or CI environment
explicitly configures one. Docker validation maps build output to the invoking
UID/GID so it does not leave root-owned project files.

## Current Boundaries

- The live server and HTTP/3 success path is a fixed interop probe, not a
  production accept loop or general router.
- Production-complete X.509 chain/revocation policy and certificate lifecycle
  are not provided by the bounded TLS engine.
- The HTTP/3 client surface fails closed; dynamic QPACK, broad request handling,
  graceful close, and GOAWAY remain outside the probe.
- Post-quantum, VPN, services, and SSH/QUIC integrations are experimental or
  draft-gated and are disabled from stable defaults where applicable.
- Performance claims require reproducible benchmark evidence; this README does
  not claim throughput or latency figures.

## Documentation

- [Documentation Index](docs/README.md)
- [Build Configuration](docs/getting-started/build-config.md)
- [Architecture Overview](docs/architecture/overview.md)
- [Crypto Module Maturity](docs/features/crypto-maturity.md)
- [RFC 9001 Crypto Audit](docs/features/rfc9001-crypto-audit.md)
- [QUIC Interop Evidence](docs/features/quic-interop.md)
- [Security](docs/features/security.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

ZQUIC is licensed under Apache-2.0. See [LICENSE](LICENSE).
