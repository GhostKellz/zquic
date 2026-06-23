//! ZQUIC HTTP/3 Feature Module
//!
//! Provides HTTP/3 server and client functionality.
//! Only included when the 'http3' feature is enabled.

const std = @import("std");
const Error = @import("utils/error.zig");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Re-export HTTP/3 functionality from core modules
pub const Http3Server = @import("http3/server.zig").Http3Server;
pub const AdvancedHttp3Server = @import("http3/advanced_server.zig").AdvancedHttp3Server;
pub const AdvancedServerConfig = @import("http3/advanced_server.zig").AdvancedServerConfig;
pub const Http3Client = struct {
    /// HTTP/3 client support is intentionally explicit rather than exported as
    /// an implied working stack. Server, QPACK, and frame APIs are available;
    /// client connection orchestration will graduate behind this type.
    pub const supported = false;

    pub fn init() Error.ZquicError!Http3Client {
        return Error.ZquicError.NotSupported;
    }
};
pub const Request = @import("http3/request.zig").Request;
pub const Response = @import("http3/response.zig").Response;
pub const Router = @import("http3/router.zig").Router;
pub const Middleware = @import("http3/middleware.zig");
pub const ServerConfig = @import("http3/server.zig").ServerConfig;
pub const NextFn = @import("http3/router.zig").NextFn;

// HTTP/3 specific types and utilities
pub const StatusCode = @import("http3/response.zig").StatusCode;
pub const HeaderField = @import("http3/qpack.zig").HeaderField;
pub const QpackDecoder = @import("http3/qpack.zig").QpackDecoder;
pub const QpackEncoder = @import("http3/qpack.zig").QpackEncoder;
pub const Frame = @import("http3/frame.zig").Frame;
pub const FrameType = @import("http3/frame.zig").FrameType;
pub const FrameHeader = @import("http3/frame.zig").FrameHeader;
pub const SettingsFrame = @import("http3/frame.zig").SettingsFrame;
pub const GoawayFrame = @import("http3/frame.zig").GoawayFrame;
pub const CancelPushFrame = @import("http3/frame.zig").CancelPushFrame;

// HTTP/3 configuration
pub const Http3Config = struct {
    max_concurrent_streams: u32 = 100,
    max_header_list_size: u32 = 65536,
    enable_push: bool = false,
    enable_connect: bool = true,
    max_table_capacity: u32 = 4096,
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: Http3Config) !void {
    _ = allocator;
    _ = config;
    // Initialize HTTP/3 specific state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up HTTP/3 specific state
}

test {
    _ = @import("http3/frame.zig");
    _ = @import("http3/qpack.zig");
    _ = @import("http3/request.zig");
    _ = @import("http3/response.zig");
    _ = @import("http3/router.zig");
    _ = @import("http3/advanced_server.zig");
}

test "HTTP/3 client surface fails closed until implemented" {
    try std.testing.expect(!Http3Client.supported);
    try std.testing.expectError(Error.ZquicError.NotSupported, Http3Client.init());
}
