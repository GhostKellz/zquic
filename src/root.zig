//! ZQUIC — High-Performance QUIC/HTTP3 Library for Zig
//!
//! A modular QUIC (RFC 9000) and HTTP/3 (RFC 9114) implementation written in
//! pure Zig. Designed for flexibility from minimal embedded clients to
//! full-featured server runtimes with opt-in post-quantum experiments.
//!
//! ## Quick Start
//!
//! ```zig
//! const zquic = @import("zquic");
//!
//! // Create a QUIC connection
//! var conn = try zquic.Connection.init(allocator, .client, .{});
//! defer conn.deinit();
//!
//! // Create a stream for data transfer
//! var stream = try conn.createStream(.client_bidirectional);
//! _ = try stream.write("Hello, QUIC!", false);
//! ```
//!
//! ## Feature Modules
//!
//! Features are enabled/disabled at build time via `zig build` options:
//!
//! | Feature | Build Flag | Size | Description |
//! |---------|------------|------|-------------|
//! | Core QUIC | Always included | ~1MB | RFC 9000 transport, streams, crypto |
//! | HTTP/3 | `-Dhttp3=true` | +1MB | RFC 9114 web server support |
//! | DoQ | `-Ddoq=true` | +0.5MB | DNS-over-QUIC (RFC 9250) |
//! | Services | `-Dservices=true` | +2MB | GhostBridge gRPC, Wraith proxy |
//! | VPN | `-Dvpn=true` | +0.5MB | Mesh VPN routing |
//! | Post-Quantum | `-Dpost-quantum=true -Dexperimental-crypto=true` | +1.5MB | ML-KEM-768 (experimental) |
//! | Monitoring | `-Dmonitoring=true` | +0.2MB | Prometheus metrics |
//!
//! ## Architecture
//!
//! ```
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Application Layer                       │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐│
//! │  │ HTTP/3  │ │   DoQ   │ │Services │ │   VPN   │ │Monitoring││
//! │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘│
//! ├───────┴──────────┴──────────┴──────────┴──────────┴────────┤
//! │                       Core QUIC Layer                        │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
//! │  │Connection│ │  Stream  │ │  Crypto  │ │ Flow/Congestion  ││
//! │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘│
//! ├──────────────────────────────────────────────────────────────┤
//! │                      Network Layer                           │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────────────────────────┐ │
//! │  │   UDP    │ │Multiplexer│ │      Async Runtime         │ │
//! │  └──────────┘ └──────────┘ └──────────────────────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Thread Safety
//!
//! - Connection and Stream operations use atomic state for lock-free metrics
//! - Buffer pools are thread-safe with mutex protection
//! - The async runtime supports multi-threaded worker pools
//!
//! ## Error Handling
//!
//! All fallible operations return `Error.ZquicError` which provides:
//! - Network errors: `NetworkError`, `ConnectionReset`, `WouldBlock`
//! - Protocol errors: `ProtocolViolation`, `FlowControlError`
//! - Resource errors: `OutOfMemory`, `ConnectionLimitReached`
//!
//! ## Version Information
//!
//! - Library version: build.zig.zon version
//! - QUIC version: RFC 9000 (v1)
//! - Zig compatibility: 0.17.0-dev.27+

const std = @import("std");
const build_options = @import("build_options");

// ============================================================================
// Core QUIC Module (Always Available)
// ============================================================================

/// Core QUIC implementation module containing all fundamental types.
/// This module is always available regardless of build configuration.
pub const core = @import("core.zig");

// ============================================================================
// Primary Type Exports
// ============================================================================

/// QUIC connection manager handling handshakes, streams, and packet I/O.
///
/// A Connection represents a single QUIC connection between two endpoints.
/// It manages multiple streams, handles cryptographic handshakes, and
/// provides flow control and congestion management.
///
/// ## Example
/// ```zig
/// var conn = try Connection.init(allocator, .client, .{});
/// defer conn.deinit();
///
/// // Create streams for data transfer
/// var stream = try conn.createStream(.client_bidirectional);
/// ```
pub const Connection = core.Connection;

/// QUIC packet structure for parsing and serialization.
///
/// Handles all QUIC packet types: Initial, Handshake, 0-RTT, and 1-RTT.
/// Provides methods for encoding/decoding packet headers and payloads.
pub const Packet = core.Packet;

/// Bidirectional or unidirectional data stream within a connection.
///
/// Streams provide ordered, reliable byte delivery over QUIC. Each stream
/// has independent flow control and can be created/closed independently.
///
/// ## Stream Types
/// - `client_bidirectional`: Client-initiated, two-way communication
/// - `server_bidirectional`: Server-initiated, two-way communication
/// - `client_unidirectional`: Client-initiated, one-way to server
/// - `server_unidirectional`: Server-initiated, one-way to client
pub const Stream = core.Stream;

/// Stream and connection-level flow control manager.
///
/// Implements QUIC flow control (RFC 9000 Section 4) to prevent
/// buffer overflow and ensure fair bandwidth allocation.
pub const FlowControl = core.FlowControl;

/// Congestion control algorithms (New Reno, CUBIC, BBR).
///
/// Manages send rate to avoid network congestion. Supports multiple
/// algorithms optimized for different workloads (trading, bulk transfer).
pub const Congestion = core.Congestion;

/// TLS 1.3 cryptographic operations for QUIC.
///
/// Handles key derivation, packet protection, and header encryption
/// using AES-GCM or ChaCha20-Poly1305 cipher suites.
pub const Crypto = core.Crypto;

/// Enhanced cryptographic layer with post-quantum support.
///
/// Extends base crypto with experimental hybrid key exchange
/// (X25519 + ML-KEM-768) and ML-DSA-65 signatures.
pub const EnhancedCrypto = core.EnhancedCrypto;

/// TLS 1.3 handshake state machine for QUIC.
///
/// Models the cryptographic handshake process including:
/// - ClientHello/ServerHello exchange
/// - Key schedule computation
/// - Certificate message storage in experimental paths
/// - 0-RTT early data handling
///
/// Production-complete certificate validation is not provided by this surface.
pub const Handshake = core.Handshake;

/// Cryptographic key management and rotation.
///
/// Handles traffic secrets, key updates, and proper cleanup
/// of sensitive key material.
pub const Keys = core.Keys;

/// SSH/QUIC integration for SSH-derived secret injection.
///
/// Allows SSH-derived secrets to replace the TLS handshake in explicit
/// draft SSH/QUIC integration paths.
pub const SshQuic = core.SshQuic;

/// Low-level UDP socket operations.
///
/// Platform-specific UDP implementation with non-blocking I/O,
/// configurable buffer sizes, and packet info reception.
pub const Udp = core.Udp;

/// UDP connection multiplexer for handling multiple QUIC connections.
///
/// Demultiplexes incoming packets to the correct connection based
/// on connection IDs. Supports connection migration and pooling.
pub const UdpMultiplexer = core.UdpMultiplexer;

/// Generic socket abstraction layer.
pub const Socket = core.Socket;

/// Zig 0.17-compatible IP address helpers and types.
pub const NetAddress = core.NetAddress;

/// IPv6 address handling utilities.
pub const IPv6 = core.IPv6;

/// Async runtime for non-blocking I/O operations.
///
/// Provides event loop, timer management, and connection pooling
/// for high-performance async networking.
pub const AsyncRuntime = core.AsyncRuntime;

/// Connection load balancer with multiple strategies.
///
/// Supports round-robin, least-connections, weighted, and
/// latency-based load balancing with circuit breaker protection.
pub const LoadBalancer = core.LoadBalancer;

/// Memory allocator utilities and arena support.
pub const Allocator = core.Allocator;

/// Unified error types for all ZQUIC operations.
///
/// Categories include:
/// - Network: `NetworkError`, `ConnectionReset`, `WouldBlock`
/// - Protocol: `ProtocolViolation`, `FlowControlError`, `StreamError`
/// - Resource: `OutOfMemory`, `ConnectionLimitReached`, `SendQueueFull`
pub const Error = core.Error;

/// Time utilities for portable clock access.
///
/// Provides platform-independent time functions compatible with the current Zig 0.17 dev toolchain,
/// including `nowSeconds()`, `nowMicros()`, `nowNanos()`, and `sleep()`.
pub const Time = core.Time;

/// Packet encryption and decryption operations.
pub const PacketCrypto = core.PacketCrypto;

/// Result of packet processing with parsed headers and payload.
pub const ProcessedPacket = core.ProcessedPacket;

/// High-performance bulk packet processor for batch operations.
pub const BulkPacketProcessor = core.BulkPacketProcessor;

/// Memory pool for packet buffer allocation to reduce allocator pressure.
pub const PacketMemoryPool = core.PacketMemoryPool;

// ============================================================================
// Feature Modules (Conditionally Available)
// ============================================================================

/// HTTP/3 server and client implementation (RFC 9114).
///
/// Requires: `-Denable_http3=true`
///
/// Provides:
/// - HTTP/3 server with middleware support
/// - QPACK header compression
/// - Request/response handling
/// - Static file serving
pub const http3 = if (build_options.enable_http3) @import("http3.zig") else struct {};

/// DNS-over-QUIC implementation (RFC 9250).
///
/// Requires: `-Denable_doq=true`
///
/// Provides encrypted DNS resolution over QUIC transport.
pub const doq = if (build_options.enable_doq) @import("doq.zig") else struct {};

/// VPN routing and mesh networking support.
///
/// Requires: `-Denable_vpn=true`
///
/// Provides:
/// - Packet routing with NAT
/// - Network interface management
/// - Mesh topology support
pub const vpn = if (build_options.enable_vpn) @import("vpn.zig") else struct {};

/// GhostBridge gRPC and Wraith reverse proxy services.
///
/// Requires: `-Denable_services=true`
///
/// Provides:
/// - GhostBridge: gRPC-over-QUIC relay
/// - Wraith: High-performance reverse proxy
pub const services = if (build_options.enable_services) @import("services.zig") else struct {};

/// Post-quantum cryptography integration via zcrypto.
///
/// Requires: `-Denable_post_quantum=true`
///
/// Provides:
/// - ML-KEM-768 key encapsulation
/// - ML-DSA-65 digital signatures
/// - Hybrid key exchange (classical + PQ)
pub const post_quantum = if (build_options.enable_post_quantum) @import("post_quantum.zig") else struct {};

/// Prometheus metrics and performance monitoring.
///
/// Requires: `-Denable_monitoring=true`
///
/// Provides:
/// - Connection/stream metrics
/// - Latency histograms
/// - Prometheus export endpoint
pub const monitoring = if (build_options.enable_monitoring) @import("monitoring.zig") else struct {};

/// Performance helpers for connection pooling and zero-copy packet processing.
pub const performance = @import("performance.zig");

/// Zero-RTT and PQ resumption ticket helpers.
pub const zero_rtt_resumption = @import("crypto/zero_rtt_resumption.zig");

/// Transport helpers for UDP multiplexing and connection routing.
pub const transport = @import("transport.zig");

// ============================================================================
// Convenience Aliases
// ============================================================================

/// HTTP/3 module alias (when enabled).
pub const Http3 = if (build_options.enable_http3) http3 else struct {};

/// DoQ module alias (when enabled).
pub const DoQ = if (build_options.enable_doq) doq else struct {};

/// GhostBridge service alias (when enabled).
pub const Services = if (build_options.enable_services) services.GhostBridge else struct {};

/// Post-quantum crypto alias (when enabled).
pub const PostQuantum = if (build_options.enable_post_quantum) post_quantum.PostQuantum else struct {};

/// Post-quantum cipher suite selection.
pub const PQCipherSuite = if (build_options.enable_post_quantum) post_quantum.PQCipherSuite else struct {};

/// Post-quantum key exchange operations.
pub const PQKeyExchange = if (build_options.enable_post_quantum) post_quantum.PQKeyExchange else struct {};

/// Post-quantum QUIC context for hybrid connections.
pub const PQQuicContext = if (build_options.enable_post_quantum) post_quantum.PQQuicContext else struct {};

/// Post-quantum authentication and signatures.
pub const PQAuthentication = if (build_options.enable_post_quantum) post_quantum.PQAuthentication else struct {};

/// CPU-specific optimizations for crypto operations.
pub const Optimizations = if (build_options.enable_post_quantum) post_quantum.Optimizations else struct {};

/// Runtime CPU feature detection and optimizer selection.
pub const CpuOptimizer = if (build_options.enable_post_quantum) post_quantum.CpuOptimizer else struct {};

/// SIMD-optimized Blake3 hashing.
pub const OptimizedBlake3 = if (build_options.enable_post_quantum) post_quantum.OptimizedBlake3 else struct {};

/// SIMD-optimized ChaCha20-Poly1305 AEAD.
pub const OptimizedChaCha20Poly1305 = if (build_options.enable_post_quantum) post_quantum.OptimizedChaCha20Poly1305 else struct {};

/// Optimized bulk packet processor with SIMD.
pub const OptimizedPacketProcessor = if (build_options.enable_post_quantum) post_quantum.OptimizedPacketProcessor else struct {};

/// VPN packet router (when enabled).
pub const VpnRouter = if (build_options.enable_vpn) vpn.VpnRouter else struct {};

/// GhostBridge configuration (when enabled).
pub const BridgeConfig = if (build_options.enable_services) services.BridgeConfig else struct {};

/// Legacy alias for post_quantum module.
pub const pq = post_quantum;

/// Kyber/ML-KEM key encapsulation (when available).
pub const kyber = if (build_options.enable_post_quantum and @hasDecl(post_quantum, "kyber")) post_quantum.kyber else struct {};

/// Dilithium/ML-DSA signatures (when available).
pub const dilithium = if (build_options.enable_post_quantum and @hasDecl(post_quantum, "dilithium")) post_quantum.dilithium else struct {};

// ============================================================================
// ZCrypto Exports
// ============================================================================

const zcrypto = @import("zcrypto");

/// X25519 Diffie-Hellman key exchange.
pub const x25519 = if (@hasDecl(zcrypto, "kex")) zcrypto.kex.X25519 else struct {};

/// Ed25519 digital signatures.
pub const ed25519 = if (@hasDecl(zcrypto, "kex")) zcrypto.kex.Ed25519 else struct {};

// ============================================================================
// Version Information
// ============================================================================

/// Library version string (e.g., "0.9.5").
pub const version = core.version;

/// Supported QUIC protocol version.
pub const quic_version = core.quic_version;

// ============================================================================
// Build Configuration
// ============================================================================

/// Build-time feature configuration information.
///
/// Use this to check which features are available at runtime:
/// ```zig
/// if (zquic.build_config.http3_enabled) {
///     // HTTP/3 code path
/// }
/// ```
pub const build_config = struct {
    /// True if HTTP/3 support is compiled in.
    pub const http3_enabled = build_options.enable_http3;

    /// True if DNS-over-QUIC support is compiled in.
    pub const doq_enabled = build_options.enable_doq;

    /// True if VPN routing support is compiled in.
    pub const vpn_enabled = build_options.enable_vpn;

    /// True if GhostBridge/Wraith services are compiled in.
    pub const services_enabled = build_options.enable_services;

    /// True if post-quantum cryptography is fully enabled (requires both flags).
    pub const post_quantum_enabled = build_options.enable_post_quantum and build_options.enable_experimental_crypto;

    /// True if experimental crypto features are enabled.
    pub const experimental_crypto_enabled = build_options.enable_experimental_crypto;

    /// True if Prometheus monitoring is compiled in.
    pub const monitoring_enabled = build_options.enable_monitoring;

    /// Print build configuration to debug output.
    pub fn printConfig() void {
        std.debug.print("zquic v{s} build configuration:\n", .{version});
        std.debug.print("  HTTP/3: {}\n", .{http3_enabled});
        std.debug.print("  DoQ: {}\n", .{doq_enabled});
        std.debug.print("  VPN: {}\n", .{vpn_enabled});
        std.debug.print("  Services: {}\n", .{services_enabled});
        std.debug.print("  Post-Quantum: {} (experimental)\n", .{post_quantum_enabled});
        std.debug.print("  Monitoring: {}\n", .{monitoring_enabled});
    }
};

// ============================================================================
// Library Lifecycle
// ============================================================================

/// Initialize the ZQUIC library.
///
/// Call this once at application startup before using any ZQUIC types.
/// Initializes internal state, thread pools, and crypto subsystems.
///
/// ## Parameters
/// - `allocator`: Memory allocator for all ZQUIC operations
///
/// ## Errors
/// - `OutOfMemory`: Failed to allocate required resources
/// - `InitializationError`: Internal initialization failed
///
/// ## Example
/// ```zig
/// var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
/// defer _ = debug_allocator.deinit();
///
/// try zquic.init(debug_allocator.allocator());
/// defer zquic.deinit();
/// ```
pub fn init(allocator: std.mem.Allocator) Error.ZquicError!void {
    try core.init(allocator);
}

/// Deinitialize the ZQUIC library.
///
/// Call this at application shutdown to clean up resources.
/// All connections should be closed before calling this.
pub fn deinit() void {
    core.deinit();
}

/// Get a list of enabled feature names.
///
/// Returns a compile-time constant slice of feature name strings
/// based on the build configuration.
///
/// ## Example
/// ```zig
/// for (zquic.getEnabledFeatures()) |feature| {
///     std.debug.print("Enabled: {s}\n", .{feature});
/// }
/// ```
pub fn getEnabledFeatures() []const []const u8 {
    const features = comptime blk: {
        var list: []const []const u8 = &[_][]const u8{};
        if (build_options.enable_http3) list = list ++ &[_][]const u8{"http3"};
        if (build_options.enable_doq) list = list ++ &[_][]const u8{"doq"};
        if (build_options.enable_vpn) list = list ++ &[_][]const u8{"vpn"};
        if (build_options.enable_services) list = list ++ &[_][]const u8{"services"};
        // PQ requires both post-quantum AND experimental-crypto flags
        if (build_options.enable_post_quantum and build_options.enable_experimental_crypto) {
            list = list ++ &[_][]const u8{"post-quantum (experimental)"};
        }
        if (build_options.enable_monitoring) list = list ++ &[_][]const u8{"monitoring"};
        break :blk list;
    };
    return features;
}

// ============================================================================
// Tests
// ============================================================================

test "zquic modular library initialization" {
    try init(std.testing.allocator);
    defer deinit();

    const features = getEnabledFeatures();
    try std.testing.expect(features.len >= 0);
}

test {
    // Import all conditionally available modules for testing
    _ = @import("core/packet_space.zig");
    _ = @import("core/recovery.zig");
    _ = @import("core/stream.zig");
    _ = @import("core/flow_control.zig");
    _ = @import("core/stream_flow_control.zig");
    _ = @import("core/congestion.zig");
    _ = @import("core/connection_migration.zig");
    _ = @import("utils/sync.zig");
    _ = @import("net/sys.zig");
    _ = @import("async/event_loop.zig");
    _ = @import("async/runtime.zig");
    _ = @import("async/load_balancer.zig");
    if (build_options.enable_http3) _ = http3;
    if (build_options.enable_doq) _ = doq;
    if (build_options.enable_vpn) _ = vpn;
    if (build_options.enable_services) _ = services;
    if (build_options.enable_post_quantum) _ = post_quantum;
    if (build_options.enable_monitoring) _ = monitoring;
    _ = transport;
}
