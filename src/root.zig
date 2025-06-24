//! ZQUIC — Minimal QUIC/HTTP3 Library for Zig
//!
//! zquic is a lightweight, high-performance QUIC (HTTP/3 transport layer)
//! implementation written in pure Zig. Designed for use in embedded systems,
//! VPN stacks, decentralized services, and ultra-fast proxies.

const std = @import("std");

// Core QUIC protocol components
pub const Connection = @import("core/connection.zig");
pub const Packet = @import("core/packet.zig");
pub const Stream = @import("core/stream.zig");
pub const FlowControl = @import("core/flow_control.zig");
pub const Congestion = @import("core/congestion.zig");

// Crypto and TLS 1.3 support
pub const Crypto = @import("crypto/tls.zig");
pub const EnhancedCrypto = @import("crypto/enhanced_tls.zig");
pub const Handshake = @import("crypto/handshake.zig");
pub const Keys = @import("crypto/keys.zig");

// HTTP/3 enhanced implementation
pub const Http3 = struct {
    // Core HTTP/3 modules
    pub const Frame = @import("http3/frame.zig");
    pub const QpackDecoder = @import("http3/qpack.zig").QpackDecoder;
    pub const HeaderField = @import("http3/qpack.zig").HeaderField;
    
    // Enhanced HTTP/3 server components
    pub const Request = @import("http3/request.zig").Request;
    pub const Response = @import("http3/response.zig").Response;
    pub const StatusCode = @import("http3/response.zig").StatusCode;
    pub const Method = @import("http3/request.zig").Method;
    
    // Routing system
    pub const Router = @import("http3/router.zig").Router;
    pub const Route = @import("http3/router.zig").Route;
    pub const RouteParams = @import("http3/router.zig").RouteParams;
    pub const HandlerFn = @import("http3/router.zig").HandlerFn;
    
    // Middleware system
    pub const Middleware = @import("http3/middleware.zig");
    
    // Enhanced HTTP/3 server
    pub const Http3Server = @import("http3/server.zig").Http3Server;
    pub const ServerConfig = @import("http3/server.zig").ServerConfig;
    pub const ServerStats = @import("http3/server.zig").ServerStats;
};

// Network layer
pub const Udp = @import("net/udp.zig");
pub const UdpMultiplexer = @import("net/multiplexer.zig");
pub const Socket = @import("net/socket.zig");
pub const IPv6 = @import("net/ipv6.zig");

// Async runtime and load balancing
pub const AsyncRuntime = @import("async/runtime.zig");
pub const LoadBalancer = @import("async/load_balancer.zig");

// VPN functionality
pub const VpnRouter = @import("vpn/router.zig");

// Utilities
pub const Allocator = @import("utils/allocator.zig");
pub const Error = @import("utils/error.zig");

// Version information
pub const version = "1.0.0";
pub const quic_version = 0x00000001; // QUIC version 1 (RFC 9000)

/// Initialize the ZQUIC library with a given allocator
pub fn init(allocator: std.mem.Allocator) Error.ZquicError!void {
    // Initialize library-wide state if needed
    _ = allocator;
    // For now, this is a no-op but could initialize crypto backends, etc.
}

/// Deinitialize the ZQUIC library
pub fn deinit() void {
    // Clean up any global state
}

test "zquic library initialization" {
    try init(std.testing.allocator);
    defer deinit();
}
