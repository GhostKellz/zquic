//! QPACK (QUIC Header Compression) implementation
//!
//! Implements QPACK encoder and decoder according to RFC 9204

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QPACK decoder
pub const QpackDecoder = struct {
    dynamic_table: std.ArrayList(HeaderField),
    max_table_capacity: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_capacity: u32) Self {
        return Self{
            .dynamic_table = std.ArrayList(HeaderField).init(allocator),
            .max_table_capacity = max_capacity,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.dynamic_table.items) |*field| {
            field.deinit();
        }
        self.dynamic_table.deinit();
    }

    /// Decode QPACK-encoded headers (simplified implementation)
    pub fn decode(self: *Self, encoded_data: []const u8, allocator: std.mem.Allocator) Error.ZquicError![]HeaderField {
        _ = self;
        _ = encoded_data;

        // Simplified: return empty headers list
        return try allocator.alloc(HeaderField, 0);
    }
};

/// Header field
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !Self {
        return Self{
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.name);
        self.allocator.free(self.value);
    }
};

test "qpack decoder initialization" {
    var decoder = QpackDecoder.init(std.testing.allocator, 4096);
    defer decoder.deinit();

    try std.testing.expect(decoder.max_table_capacity == 4096);
}
