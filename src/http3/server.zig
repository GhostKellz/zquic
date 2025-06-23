//! HTTP/3 server implementation
//!
//! Basic HTTP/3 server functionality

const std = @import("std");
const Error = @import("../utils/error.zig");
const Frame = @import("frame.zig");
const QpackDecoder = @import("qpack.zig").QpackDecoder;

/// HTTP/3 server
pub const Http3Server = struct {
    allocator: std.mem.Allocator,
    qpack_decoder: QpackDecoder,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .qpack_decoder = QpackDecoder.init(allocator, 4096),
        };
    }

    pub fn deinit(self: *Self) void {
        self.qpack_decoder.deinit();
    }

    /// Process an HTTP/3 request (simplified)
    pub fn processRequest(self: *Self, headers_frame: []const u8) Error.ZquicError![]u8 {
        _ = headers_frame;

        // Simplified response
        const response = "HTTP/3 response";
        return try self.allocator.dupe(u8, response);
    }
};

test "http3 server initialization" {
    var server = Http3Server.init(std.testing.allocator);
    defer server.deinit();

    const response = try server.processRequest("GET / HTTP/3");
    defer std.testing.allocator.free(response);

    try std.testing.expect(response.len > 0);
}
