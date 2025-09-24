//! ZQUIC — Modular QUIC/HTTP3 Library for Zig v0.9.0
//!
//! zquic is a high-performance, modular QUIC (HTTP/3 transport layer)
//! implementation written in pure Zig. Designed for flexibility:
//! from minimal embedded QUIC clients to full-featured enterprise servers.
//!
//! Features are enabled/disabled at build time for optimal binary size:
//! - Core QUIC: Always included (~1MB)
//! - HTTP/3: Web server support (+1MB)
//! - DoQ: DNS-over-QUIC (+0.5MB)
//! - Services: GhostBridge/Wraith (+2MB)
//! - VPN: zcrypto VPN features (+0.5MB)
//! - Post-Quantum: zcrypto PQ features (+1.5MB)
//! - Monitoring: Performance tracking (+0.2MB)

const std = @import("std");
const build_options = @import("build_options");

// Core QUIC module (always available)
pub const core = @import("core.zig");

// Re-export core components for convenience
pub const Connection = core.Connection;
pub const Packet = core.Packet;
pub const Stream = core.Stream;
pub const FlowControl = core.FlowControl;
pub const Congestion = core.Congestion;
pub const Crypto = core.Crypto;
pub const EnhancedCrypto = core.EnhancedCrypto;
pub const Handshake = core.Handshake;
pub const Keys = core.Keys;
pub const Udp = core.Udp;
pub const UdpMultiplexer = core.UdpMultiplexer;
pub const Socket = core.Socket;
pub const IPv6 = core.IPv6;
pub const AsyncRuntime = core.AsyncRuntime;
pub const LoadBalancer = core.LoadBalancer;
pub const Allocator = core.Allocator;
pub const Error = core.Error;
pub const PacketCrypto = core.PacketCrypto;
pub const ProcessedPacket = core.ProcessedPacket;
pub const BulkPacketProcessor = core.BulkPacketProcessor;
pub const PacketMemoryPool = core.PacketMemoryPool;

// Feature modules (conditionally available based on build configuration)
pub const http3 = if (build_options.enable_http3) @import("http3.zig") else struct {};
pub const doq = if (build_options.enable_doq) @import("doq.zig") else struct {};
pub const vpn = if (build_options.enable_vpn) @import("vpn.zig") else struct {};
pub const services = if (build_options.enable_services) @import("services.zig") else struct {};
pub const post_quantum = if (build_options.enable_post_quantum) @import("post_quantum.zig") else struct {};
// FFI support removed for v0.9.0-RC1 to reduce complexity
pub const monitoring = if (build_options.enable_monitoring) @import("monitoring.zig") else struct {};

// HTTP/3 convenience exports (when enabled)
pub const Http3 = if (build_options.enable_http3) http3 else struct {};

// DoQ convenience exports (when enabled)
pub const DoQ = if (build_options.enable_doq) doq else struct {};

// Services convenience exports (when enabled)
pub const Services = if (build_options.enable_services) services.GhostBridge else struct {};

// Post-Quantum convenience exports (when enabled)
pub const PostQuantum = if (build_options.enable_post_quantum) post_quantum.PostQuantum else struct {};
pub const PQCipherSuite = if (build_options.enable_post_quantum) post_quantum.PQCipherSuite else struct {};
pub const PQKeyExchange = if (build_options.enable_post_quantum) post_quantum.PQKeyExchange else struct {};
pub const PQQuicContext = if (build_options.enable_post_quantum) post_quantum.PQQuicContext else struct {};
pub const PQAuthentication = if (build_options.enable_post_quantum) post_quantum.PQAuthentication else struct {};

// Assembly optimizations (when post-quantum is enabled)
pub const Optimizations = if (build_options.enable_post_quantum) post_quantum.Optimizations else struct {};
pub const CpuOptimizer = if (build_options.enable_post_quantum) post_quantum.CpuOptimizer else struct {};
pub const OptimizedBlake3 = if (build_options.enable_post_quantum) post_quantum.OptimizedBlake3 else struct {};
pub const OptimizedChaCha20Poly1305 = if (build_options.enable_post_quantum) post_quantum.OptimizedChaCha20Poly1305 else struct {};
pub const OptimizedPacketProcessor = if (build_options.enable_post_quantum) post_quantum.OptimizedPacketProcessor else struct {};

// VPN convenience exports (when enabled)
pub const VpnRouter = if (build_options.enable_vpn) vpn.VpnRouter else struct {};

// FFI support removed for v0.9.0-RC1 to reduce complexity
// Use zcrypto module directly for cryptographic operations

// Legacy compatibility aliases
pub const BridgeConfig = if (build_options.enable_services) services.BridgeConfig else struct {};
pub const pq = post_quantum; // Legacy alias for post_quantum

// Convenience exports for common algorithms (when post-quantum enabled)
pub const kyber = if (build_options.enable_post_quantum and @hasDecl(post_quantum, "kyber")) post_quantum.kyber else struct {};
pub const dilithium = if (build_options.enable_post_quantum and @hasDecl(post_quantum, "dilithium")) post_quantum.dilithium else struct {};

// These are always available through zcrypto
const zcrypto = @import("zcrypto");
pub const x25519 = if (@hasDecl(zcrypto, "kex")) zcrypto.kex.X25519 else struct {};
pub const ed25519 = if (@hasDecl(zcrypto, "kex")) zcrypto.kex.Ed25519 else struct {};

// Version information
pub const version = core.version;
pub const quic_version = core.quic_version;

// Build configuration information
pub const build_config = struct {
    pub const http3_enabled = build_options.enable_http3;
    pub const doq_enabled = build_options.enable_doq;
    pub const vpn_enabled = build_options.enable_vpn;
    pub const services_enabled = build_options.enable_services;
    pub const post_quantum_enabled = build_options.enable_post_quantum;
    pub const monitoring_enabled = build_options.enable_monitoring;
    pub const async_zsync_enabled = build_options.enable_async_zsync;

    pub fn printConfig() void {
        std.debug.print("zquic v{s} build configuration:\n", .{version});
        std.debug.print("  HTTP/3: {}\n", .{http3_enabled});
        std.debug.print("  DoQ: {}\n", .{doq_enabled});
        std.debug.print("  VPN: {}\n", .{vpn_enabled});
        std.debug.print("  Services: {}\n", .{services_enabled});
        std.debug.print("  Post-Quantum: {}\n", .{post_quantum_enabled});
        std.debug.print("  Monitoring: {}\n", .{monitoring_enabled});
        std.debug.print("  Async (zsync): {}\n", .{async_zsync_enabled});
    }
};

/// Initialize the ZQUIC library with a given allocator
pub fn init(allocator: std.mem.Allocator) Error.ZquicError!void {
    // Initialize core first
    try core.init(allocator);

    // Initialize feature modules as needed
    // (Most modules don't need initialization, but this provides extension points)
}

/// Deinitialize the ZQUIC library
pub fn deinit() void {
    // Deinitialize in reverse order
    core.deinit();
}

/// Get a summary of enabled features
pub fn getEnabledFeatures() []const []const u8 {
    comptime {
        var features: []const []const u8 = &.{};
        if (build_options.enable_http3) features = features ++ &.{"http3"};
        if (build_options.enable_doq) features = features ++ &.{"doq"};
        if (build_options.enable_vpn) features = features ++ &.{"vpn"};
        if (build_options.enable_services) features = features ++ &.{"services"};
        if (build_options.enable_post_quantum) features = features ++ &.{"post-quantum"};
        if (build_options.enable_monitoring) features = features ++ &.{"monitoring"};
        if (build_options.enable_async_zsync) features = features ++ &.{"async-zsync"};
        return features;
    }
}

test "zquic modular library initialization" {
    try init(std.testing.allocator);
    defer deinit();

    // Test that we can get feature list
    const features = getEnabledFeatures();
    std.testing.expect(features.len >= 0);
}

test {
    // Import all conditionally available modules for testing
    if (build_options.enable_http3) _ = http3;
    if (build_options.enable_doq) _ = doq;
    if (build_options.enable_vpn) _ = vpn;
    if (build_options.enable_services) _ = services;
    if (build_options.enable_post_quantum) _ = post_quantum;
    if (build_options.enable_monitoring) _ = monitoring;
}
