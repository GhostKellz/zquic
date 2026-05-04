//! ZQUIC Core Module - Shared QUIC functionality
//!
//! This module contains the essential QUIC protocol implementation that is
//! always included in every zquic build. It provides the fundamental
//! components needed for QUIC connections, packet handling, and crypto.
//!
//! Feature-specific functionality is conditionally imported through feature modules.
//!
//! Architecture:
//! - Core QUIC protocol (always included)
//! - Basic connection/stream management
//! - Packet handling and framing
//! - Flow control (basic)
//! - Congestion control (basic)
//! - TLS integration (basic)

const std = @import("std");
const build_options = @import("build_options");
const zcrypto = @import("zcrypto");

// Core QUIC protocol components
pub const Connection = @import("core/connection.zig");
pub const Packet = @import("core/packet.zig");
pub const Stream = @import("core/stream.zig");
pub const FlowControl = @import("core/flow_control.zig");
pub const Congestion = @import("core/congestion.zig");

// Utilities
pub const Time = @import("utils/time.zig");

// Crypto and TLS 1.3 support
pub const Crypto = @import("crypto/tls.zig");
pub const EnhancedCrypto = @import("crypto/enhanced_tls.zig");
pub const Handshake = @import("crypto/handshake.zig");
pub const Keys = @import("crypto/keys.zig");
pub const SshQuic = @import("crypto/ssh_quic.zig");

/// Core connection states
pub const ConnectionState = enum {
    initial,
    handshake,
    established,
    closing,
    draining,
    closed,
};

/// Network layer
pub const Udp = @import("net/udp.zig");
pub const UdpMultiplexer = @import("net/multiplexer.zig");
pub const Socket = @import("net/socket.zig");
pub const IPv6 = @import("net/ipv6.zig");
pub const NetAddress = @import("net/address.zig");

/// Core encryption levels
pub const EncryptionLevel = enum {
    initial,
    early_data,
    handshake,
    application,
};

/// Core QUIC enhancements
pub const PacketCrypto = @import("core/packet_crypto.zig").PacketCrypto;
pub const ProcessedPacket = @import("core/packet_crypto.zig").ProcessedPacket;
pub const BulkPacketProcessor = @import("core/packet_crypto.zig").BulkPacketProcessor;
pub const PacketMemoryPool = @import("core/packet_crypto.zig").PacketMemoryPool;

/// Native async runtime (lightweight, no external deps)
pub const AsyncRuntime = @import("async/runtime.zig");

/// Connection role
pub const Role = enum {
    client,
    server,
};

pub const LoadBalancer = @import("async/load_balancer.zig");

/// Stream types
pub const StreamType = enum {
    client_bidirectional,
    server_bidirectional,
    client_unidirectional,
    server_unidirectional,
};

/// Stream states
pub const StreamState = enum(u8) {
    idle = 0,
    open = 1,
    half_closed_local = 2,
    half_closed_remote = 3,
    closed = 4,
};

pub const version = build_options.version;
pub const quic_version = 0x00000001; // QUIC version 1 (RFC 9000)

/// Initialize the ZQUIC core library
pub fn init(allocator: std.mem.Allocator) !void {
    _ = allocator;
    // Initialize core library-wide state if needed
}

/// Deinitialize the ZQUIC core library
pub fn deinit() void {
    // Clean up any global state
}

pub const Error = @import("utils/error.zig");
pub const Allocator = @import("utils/allocator.zig");

test "zquic core initialization" {
    try init(std.testing.allocator);
    deinit();
}
