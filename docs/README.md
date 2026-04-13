# ZQUIC Documentation

Welcome to ZQUIC documentation. This guide covers the modular QUIC transport library for Zig 0.16.0-dev.

## Overview

ZQUIC provides a production-ready QUIC (RFC 9000) and HTTP/3 (RFC 9114) implementation in pure Zig with:

- **Modular builds**: Core-only (~1.3 MB) to full-stack (~5.5 MB)
- **Stable crypto**: AES-GCM, ChaCha20-Poly1305, X25519, Ed25519 via zcrypto v1.0.1
- **Experimental PQ crypto**: ML-KEM-768 hybrid key exchange (requires explicit flags)
- **Native async runtime**: No external dependencies
- **SSH/QUIC integration**: Bypass TLS handshake using SSH-derived secrets

## Documentation Structure

### Getting Started
- **[Quick Start](getting-started/quick-start.md)** - Installation and first steps
- **[Build Configuration](getting-started/build-config.md)** - Feature flags and build options
- **[Async Runtime Notes](ASYNC.md)** - Runtime model and local async development notes

### Architecture
- **[System Overview](architecture/overview.md)** - High-level architecture and design principles
- **[Async Runtime Architecture](architecture/async-runtime.md)** - Native runtime internals and design

### API Reference
- **[Core API](api/core.md)** - Connection, Packet, Stream management

### Integrations
- **[zcrypto](integrations/zcrypto.md)** - zcrypto v1.0.1 integration guide
- **[Prometheus](integrations/prometheus.md)** - Metrics exporter integration

### Features
- **[Security](features/security.md)** - Cryptographic security and best practices
- **[SSH/QUIC Integration](features/ssh_quic.md)** - SSH secret injection for QUIC
- **[Feature Overview](features/README.md)** - Current feature map and release posture
- **[QUIC VPN](features/quic_vpn.md)** - Experimental QUIC-over-UDP VPN notes

### Guides
- **[Future Features](future-features.md)** - Scoped features intentionally deferred past v0.9.9

## Quick Navigation

**New to ZQUIC?** Start with [Quick Start](getting-started/quick-start.md)

**Need API docs?** Check [Core API](api/core.md)

**Building a server?** Start with [Quick Start](getting-started/quick-start.md) and [Feature Overview](features/README.md)

**zcrypto integration?** Read [zcrypto Guide](integrations/zcrypto.md)

**Future PQ multiplexer work?** Read [Future Features](future-features.md)

## Build Profiles

| Profile | Flags | Size |
|---------|-------|------|
| Minimal | `-Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false` | ~1.3 MB |
| Web Stack | `-Dhttp3=true -Ddoq=true` | ~3.5 MB |
| Enterprise | `-Dservices=true -Dvpn=true -Dmonitoring=true` | ~5.5 MB |
| With PQ | Add `-Dpost-quantum=true -Dexperimental-crypto=true` | +0.5 MB |

---
