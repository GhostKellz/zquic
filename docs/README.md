# ZQUIC Documentation

Welcome to the ZQUIC v0.9.8 documentation! This guide covers the complete modular QUIC transport library for Zig 0.16.0-dev.

## What's New in v0.9.8

**Security Hardening Release**

- **Cryptographic Fixes**: Replaced all placeholder/XOR encryption with real ChaCha20-Poly1305 AEAD
- **JWT Security**: Unified authentication with full HMAC-SHA256 signature verification
- **Path Traversal Protection**: Enhanced static file serving with symlink escape detection
- **Secure Zeroization**: Standardized `std.crypto.secureZero()` across all crypto modules
- **Modern Security Headers**: Added CSP, Referrer-Policy, Permissions-Policy support
- **TLS Verification**: Complete certificate chain, CertificateVerify, and Finished validation
- **Post-Quantum Crypto**: Real ML-KEM-768 and SLH-DSA-128s via zcrypto
- **Zig 0.16.0-dev.2790**: Full compatibility with latest Zig development builds

## What's New in v0.9.6

**SSH/QUIC Integration & Zig 0.16.0 Compatibility**

- **SSH/QUIC Secret Injection**: Bypass TLS handshake using SSH-derived secrets ([draft-denis-ssh-quic](https://datatracker.ietf.org/doc/draft-denis-ssh-quic/))
- **Zig 0.16.0-dev.2535+**: Full compatibility with latest Zig development builds
- **Secure Key Handling**: Automatic zeroing of sensitive key material
- **Time Utilities**: Platform-independent `zquic.Time` module exported for application use

## What's New in v0.9.5

**Production Hardening Release** - Major stability and performance improvements:

- **Error Handling**: Eliminated all `catch unreachable` patterns (38 occurrences fixed)
- **Logging**: All silent error handlers now have appropriate logging
- **Memory Safety**: Added `errdefer` chains to prevent leaks
- **Performance**: O(n) algorithms replacing O(n^2) in hot paths
- **Graceful Shutdown**: RFC 9000-compliant connection draining
- **Arena Allocators**: Per-packet/request memory management
- **Test Coverage**: New `dev/coverage.sh` script with kcov support

## 📚 Documentation Structure

### Getting Started
- **[Quick Start](getting-started/quick-start.md)** - Installation and first steps
- **[Build Configuration](getting-started/build-config.md)** - Feature flags and build options
- **[Basic Examples](getting-started/examples.md)** - Simple usage patterns

### Architecture
- **[System Overview](architecture/overview.md)** - High-level architecture and design principles
- **[Modular Design](architecture/modular.md)** - Component organization and modularity
- **[Performance](architecture/performance.md)** - Performance characteristics and optimizations

### API Reference
- **[Core API](api/core.md)** - Connection, Packet, Stream management
- **[Crypto API](api/crypto.md)** - TLS 1.3 and post-quantum cryptography
- **[HTTP/3 API](api/http3.md)** - HTTP/3 server and frame handling
- **[Services API](api/services.md)** - High-level services (Bridge, Proxy, DoQ)

### Features
- **[Security](features/security.md)** - Cryptographic security, hardening, and best practices (v0.9.8)
- **[Post-Quantum Crypto](features/post-quantum.md)** - ML-KEM-768 + X25519 hybrid TLS
- **[SSH/QUIC Integration](features/ssh_quic.md)** - SSH secret injection for QUIC (v0.9.6)
- **[HTTP/3 Server](features/http3.md)** - Production HTTP/3 with QPACK
- **[DNS-over-QUIC](features/doq.md)** - Secure DNS resolution
- **[QUIC VPN](features/quic_vpn.md)** - Experimental QUIC-based mesh tunneling
- **[Async Processing](features/async.md)** - Native runtime and worker pools (no external deps)

### Examples
- **[Client Examples](examples/client.md)** - QUIC client implementations
- **[Server Examples](examples/server.md)** - HTTP/3 and DoQ servers
- **[Integration Examples](examples/integration.md)** - Cross-language integration

### Guides
- **[Migration Guide](guides/migration.md)** - Upgrading from previous versions
- **[Production Deployment](guides/production.md)** - Production setup and best practices
- **[Performance Tuning](guides/performance.md)** - Optimization techniques

## 🚀 Quick Navigation

**New to ZQUIC?** Start with [Quick Start](getting-started/quick-start.md)

**Need API docs?** Check [Core API](api/core.md) or [HTTP/3 API](api/http3.md)

**Building a server?** See [Server Examples](examples/server.md)

**SSH/QUIC integration?** Read [SSH/QUIC Secret Injection](features/ssh_quic.md)

**Post-quantum crypto?** Read [Post-Quantum Features](features/post-quantum.md)

**Production deployment?** Follow [Production Guide](guides/production.md)

## 🏆 Release Highlights
- 6 working binaries installed under `zig-out/bin/`
- Zero-copy packet processing
- Enterprise-grade memory management
- High-performance async operations via in-house runtime
- Unified `dev/test.sh` pipeline (unit + integration + fuzz)

---
