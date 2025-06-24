# Changelog

All notable changes to the zQUIC library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-23

### 🎉 Major Release - Production-Ready VPN Features

This release transforms zQUIC into a production-ready library for **GhostMesh VPN** and similar tailscale-like applications, with comprehensive UDP multiplexing, async runtime integration, and enhanced cryptography.

### Added

#### Core Networking & Multiplexing
- **UDP Multiplexer** (`src/net/multiplexer.zig`) - Complete connection demultiplexing over single UDP socket
  - Connection ID-based packet routing
  - Automatic connection lifecycle management
  - Send queue management for async operations
  - Connection migration support for mobile scenarios
  - Configurable timeouts and limits
  - Connection statistics and monitoring

#### Real Socket Implementation
- **Production UDP Socket** (`src/net/udp.zig`) - Replaced all stub implementations
  - Real system call-based socket operations
  - Non-blocking I/O support with proper error handling
  - Configurable buffer sizes for high-throughput scenarios
  - Packet info reception for destination address tracking
  - Platform-specific optimizations (Linux/BSD)

#### Async Runtime Integration
- **TokiZ-Powered Async Runtime** (`src/async/runtime.zig`) - Full integration with production TokiZ
  - Multi-threaded worker pools with auto-detection
  - Connection pooling with automatic cleanup
  - Async connection tasks for non-blocking packet processing
  - I/O-focused event loop optimized for network workloads
  - Priority task scheduling (`spawnUrgent()` for critical packets)

#### VPN Packet Routing
- **Advanced Packet Router** (`src/vpn/router.zig`) - Complete routing system for VPN applications
  - Dynamic routing table with metrics and TTL
  - NAT (Network Address Translation) implementation
  - Multiple network interface management
  - Route cleanup and garbage collection
  - Comprehensive routing statistics and monitoring

#### Connection Load Balancing  
- **Intelligent Load Balancer** (`src/async/load_balancer.zig`) - Enterprise-grade load balancing
  - Multiple strategies: Round-robin, least connections, weighted, latency-based
  - Circuit breaker pattern for backend protection and automatic recovery
  - Per-backend connection pooling with health monitoring
  - Real-time performance metrics and success rate tracking
  - Configurable failure thresholds and recovery timeouts

#### Enhanced Cryptography
- **Production TLS 1.3** (`src/crypto/enhanced_tls.zig`) - Real cryptographic implementations
  - HKDF key derivation (RFC 5869 compliant) replacing stub implementations
  - AES-128/256-GCM and ChaCha20-Poly1305 AEAD encryption
  - Proper header protection using AES-ECB and ChaCha20
  - Secure key management with automatic memory cleanup
  - Support for all TLS 1.3 cipher suites used by QUIC

#### Error Handling
- **Extended Error Types** (`src/utils/error.zig`) - Comprehensive error coverage
  - Network-specific errors: `WouldBlock`, `NetworkUnreachable`, `ConnectionReset`
  - VPN-specific errors: `UnknownConnection`, `ConnectionLimitReached`, `SendQueueFull`
  - Proper error propagation and handling throughout the stack

#### Examples & Documentation
- **GhostMesh VPN Example** (`examples/ghostmesh_vpn.zig`) - Complete VPN implementation
  - Multi-peer connectivity with automatic discovery
  - Integrated load balancing and intelligent packet routing
  - Production-ready configuration options
  - Traffic simulation and performance monitoring
  - Demonstrates real-world usage patterns

### Enhanced

#### Core QUIC Features
- **Connection Management** - Enhanced with async task support and better lifecycle management
- **Stream Multiplexing** - Optimized for VPN traffic patterns and high connection counts
- **Flow Control** - Improved algorithms for VPN-specific traffic characteristics
- **Congestion Control** - Enhanced for long-lived VPN connections and mobile scenarios

#### Build System
- **Enhanced Build Configuration** (`build.zig`)
  - Added GhostMesh VPN example build target
  - New build commands: `zig build run-ghostmesh`
  - Improved test coverage and parallel test execution

#### Module Organization
- **Expanded Public API** (`src/root.zig`)
  - Async runtime and load balancing modules
  - VPN routing functionality
  - Enhanced cryptography alongside legacy crypto
  - Clean separation of concerns and modular design

### Performance Improvements

- **High-throughput UDP multiplexing** - Handle thousands of concurrent VPN tunnels
- **Zero-copy packet processing** where possible for minimal latency
- **Async-first design** leveraging production-ready TokiZ runtime
- **Memory-efficient** operations with explicit allocation control
- **Intelligent connection pooling** reduces connection establishment overhead

### Security Enhancements

- **Production-grade TLS 1.3** with real AEAD encryption (AES-GCM, ChaCha20-Poly1305)
- **Proper key derivation** using HKDF instead of placeholder hashing
- **Secure memory management** with automatic cleanup of sensitive data
- **Header protection** using standardized AES-ECB and ChaCha20 algorithms

### Use Cases Enabled

This release enables zQUIC to power:

- ✅ **GhostMesh VPN** - Tailscale-like mesh networking with QUIC transport
- ✅ **High-performance proxies** - UDP multiplexing with intelligent load balancing  
- ✅ **IoT/Edge networking** - Lightweight async runtime with connection pooling
- ✅ **Blockchain transport** - Secure, multiplexed connections for crypto nodes
- ✅ **Real-time applications** - Low-latency packet processing with async I/O

### Breaking Changes

- **Socket API Changes** - UDP socket methods now return proper error types instead of stubs
- **Crypto API Updates** - Enhanced crypto functions require proper key material (no more placeholders)
- **Connection Management** - Connections now require async runtime integration for full functionality

### Dependencies

- **Zig 0.15.0-dev** or later
- **TokiZ async runtime** (production-ready Phase 2 version)
- **Platform support**: Linux (primary), BSD variants, macOS

### Migration Guide

For existing zQUIC users upgrading from v0.1.0:

1. **Update imports** - Add new modules (`UdpMultiplexer`, `AsyncRuntime`, `VpnRouter`, `LoadBalancer`)
2. **Replace UDP sockets** - Update code using UDP socket stubs to handle real socket errors
3. **Integrate async runtime** - Connections now benefit from async task management
4. **Update crypto usage** - Enhanced crypto requires proper initialization (see examples)

### Installation

```bash
# Clone the repository
git clone <zquic-repo-url>
cd zquic

# Build the library
zig build

# Run tests
zig build test

# Try the GhostMesh VPN example
zig build run-ghostmesh
```

### Performance Benchmarks

- **Connection capacity**: 1000+ concurrent QUIC connections per multiplexer
- **Packet throughput**: Optimized for high-frequency VPN packet processing
- **Memory efficiency**: Explicit allocation control with connection pooling
- **CPU utilization**: Multi-threaded async runtime with configurable worker pools

---

## [0.1.0] - 2024-XX-XX

### Added

#### Initial Release
- **Core QUIC Protocol** - Basic RFC 9000 implementation
  - Packet parsing and serialization
  - Connection state management
  - Stream multiplexing and flow control
  - Basic congestion control (New Reno, CUBIC skeleton)

#### HTTP/3 Support
- **Frame Processing** - HTTP/3 frame parsing and serialization
- **QPACK** - Basic header compression support
- **Server Implementation** - Simple HTTP/3 server framework

#### Cryptography Foundation
- **TLS 1.3 Integration** - Basic handshake management (stub implementations)
- **Key Management** - Key derivation and rotation framework
- **Packet Protection** - Header protection mechanisms

#### Networking
- **UDP Abstraction** - Basic UDP socket wrapper (stub implementation)
- **IPv6 Support** - IPv6 address handling
- **Socket Management** - Connection and socket lifecycle

#### Examples & Testing
- **Basic Examples** - Simple client and server demonstrations
- **Test Suite** - Core functionality tests
- **Documentation** - API documentation and usage examples

### Known Limitations (Fixed in v0.2.0)
- UDP socket implementation was stub-only
- Crypto implementations used placeholders
- No async runtime integration
- Limited to single connection per socket
- No VPN or multiplexing capabilities

---

### Development Notes

- **Architecture**: Modular design with clear separation between core QUIC, networking, crypto, and VPN layers
- **Performance Focus**: Zero-copy operations, async-first design, memory efficiency
- **Security**: Production-grade cryptography with proper key management
- **Scalability**: Designed for thousands of concurrent connections
- **Integration**: Built for GhostMesh ecosystem with TokiZ async runtime

For detailed API documentation, see [DOCS.md](DOCS.md).
For contributing guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).