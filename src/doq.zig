//! ZQUIC DNS-over-QUIC (DoQ) Feature Module
//!
//! Provides DNS-over-QUIC server and client functionality.
//! Only included when the 'doq' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Re-export DoQ functionality from core modules
pub const DoqServer = @import("doq/server.zig").DoQServer;
pub const DoqClient = @import("doq/client.zig").DoQClient;
pub const Message = @import("doq/message.zig");
pub const DnsMessage = @import("doq/message.zig").DnsMessage;
pub const DnsHeader = @import("doq/message.zig").DnsHeader;
pub const DnsRecordType = @import("doq/message.zig").DnsRecordType;
pub const DnsResponseCode = @import("doq/message.zig").DnsResponseCode;
pub const DnsQuestion = @import("doq/message.zig").DnsQuestion;
pub const DnsResourceRecord = @import("doq/message.zig").DnsResourceRecord;
pub const DoQServerConfig = @import("doq/server.zig").DoQServerConfig;
pub const ServerConfig = DoQServerConfig;

// DoQ specific types and utilities
pub const QueryType = enum(u16) {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    SRV = 33,
    PTR = 12,
};

pub const ResponseCode = enum(u8) {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
};

// DoQ configuration
pub const DoqConfig = struct {
    max_udp_payload_size: u16 = 4096,
    timeout_ms: u32 = 5000,
    enable_tcp_fallback: bool = true,
    max_concurrent_queries: u32 = 1000,
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: DoqConfig) !void {
    _ = allocator;
    _ = config;
    // Initialize DoQ specific state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up DoQ specific state
}
