# ZQUIC Documentation

Modular QUIC, HTTP/3, DNS-over-QUIC, and experimental post-quantum networking
library written in Zig.

## Getting Started

- [Quick Start](getting-started/quick-start.md) - Build zquic and run the first examples
- [Build Configuration](getting-started/build-config.md) - Feature flags, build profiles, and dependency usage
- [Examples](getting-started/examples.md) - Shipped example binaries and smoke-test commands

## Reference

- [Core API](api/core.md) - Connection, packet, and stream primitives
- [zcrypto Integration](integrations/zcrypto.md) - zcrypto v1.0.5 contract and crypto feature gates
- [Prometheus Integration](integrations/prometheus.md) - Metrics exporter integration

## Features

- [Feature Overview](features/README.md) - Current feature map and release posture
- [Security](features/security.md) - Cryptographic security and hardening notes
- [Crypto Module Maturity](features/crypto-maturity.md) - Supported, draft, and experimental crypto surfaces
- [SSH/QUIC Integration](features/ssh_quic.md) - SSH secret injection for QUIC
- [QUIC VPN](features/quic_vpn.md) - Experimental QUIC-over-UDP VPN notes
- [Services](features/services.md) - GhostBridge, Wraith, CNS, and ZVM maturity boundaries
- [HTTP/3 And DoQ Compliance](features/http3-doq-compliance.md) - RFC 9114/RFC 9250 audit notes
- [Future Features](future-features.md) - Scoped features intentionally deferred from this release line

## Internals

- [System Overview](architecture/overview.md) - Architecture, packet flow, and module boundaries
- [Async Runtime Architecture](architecture/async-runtime.md) - Native runtime internals
- [Async Runtime Notes](ASYNC.md) - Runtime model and local async development notes

## Security

- [Security Policy](../SECURITY.md) - Reporting policy, supported versions, and hardening checklist
- [Accepted Advisories](advisories/accepted.md) - Knowingly accepted advisories
- [Resolved Advisories](advisories/resolved.md) - Advisories cleared by dependency or code updates

## Quick Links

| Profile | Command |
|---------|---------|
| Default | `zig build` |
| Minimal | `zig build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Dexamples=false` |
| Tests | `zig build test --summary all` |
| Integration | `zig build integration-tests --summary all` |
| Fuzz | `zig build fuzz-tests --summary all` |
| Experimental PQ | `zig build -Dpost-quantum=true -Dexperimental-crypto=true` |

## Build Profiles

| Profile | Flags | Notes |
|---------|-------|-------|
| Core | `-Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false` | Transport-only surface |
| Web Stack | default `-Dhttp3=true -Ddoq=true` | HTTP/3 and DoQ enabled |
| Services | `-Dservices=true -Dmonitoring=true` | GhostBridge/Wraith/service modules |
| VPN | `-Dvpn=true -Dservices=true` | Experimental VPN helper surface |
| PQ | `-Dpost-quantum=true -Dexperimental-crypto=true` | Experimental ML-KEM/ML-DSA paths |

Default builds use stable `zcrypto v1.0.5` primitives and keep post-quantum
cryptography disabled. PQ and hybrid crypto paths are explicit experimental
opt-ins.

Current package target: `v0.9.14`.
