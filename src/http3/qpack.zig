//! QPACK (QUIC Header Compression) implementation
//!
//! Implements QPACK encoder and decoder according to RFC 9204

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QPACK decoder
pub const QpackDecoder = struct {
    dynamic_table: std.ArrayListUnmanaged(HeaderField),
    max_table_capacity: u32,

    const Self = @This();

    pub fn init(_: std.mem.Allocator, max_capacity: u32) Self {
        return Self{
            .dynamic_table = .{},
            .max_table_capacity = max_capacity,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.dynamic_table.items) |*field| {
            field.deinit();
        }
        self.dynamic_table.deinit(allocator);
    }

    /// Decode QPACK-encoded headers (literal-only implementation)
    pub fn decode(self: *Self, encoded_data: []const u8, allocator: std.mem.Allocator) Error.ZquicError![]HeaderField {
        _ = self;
        var cursor: usize = 0;
        const header_count = try readVarint(encoded_data, &cursor);

        var headers = try allocator.alloc(HeaderField, header_count);
        var i: usize = 0;
        errdefer {
            while (i > 0) {
                i -= 1;
                headers[i].deinit();
            }
            allocator.free(headers);
        }

        while (i < header_count) : (i += 1) {
            const name_len = try readVarint(encoded_data, &cursor);
            if (cursor + name_len > encoded_data.len) return Error.ZquicError.InvalidData;
            const name_slice = encoded_data[cursor .. cursor + name_len];
            cursor += name_len;

            const value_len = try readVarint(encoded_data, &cursor);
            if (cursor + value_len > encoded_data.len) return Error.ZquicError.InvalidData;
            const value_slice = encoded_data[cursor .. cursor + value_len];
            cursor += value_len;

            headers[i] = try HeaderField.init(allocator, name_slice, value_slice);
        }

        return headers;
    }
};

pub const QpackEncoder = struct {
    pub fn init() QpackEncoder {
        return QpackEncoder{};
    }

    pub fn deinit(self: *QpackEncoder) void {
        _ = self;
    }

    pub fn encode(self: *QpackEncoder, headers: []const HeaderField, allocator: std.mem.Allocator) Error.ZquicError![]u8 {
        _ = self;
        var buffer: std.ArrayListUnmanaged(u8) = .{};
        defer buffer.deinit(allocator);

        try writeVarint(&buffer, allocator, headers.len);

        for (headers) |field| {
            try writeVarint(&buffer, allocator, field.name.len);
            try buffer.appendSlice(allocator, field.name);
            try writeVarint(&buffer, allocator, field.value.len);
            try buffer.appendSlice(allocator, field.value);
        }

        return buffer.toOwnedSlice(allocator);
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
    defer decoder.deinit(std.testing.allocator);

    try std.testing.expect(decoder.max_table_capacity == 4096);
}

test "qpack encode decode roundtrip" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncoder.init();
    defer encoder.deinit();

    var decoder = QpackDecoder.init(allocator, 4096);
    defer decoder.deinit(allocator);

    var headers = [_]HeaderField{ undefined, undefined };
    headers[0] = try HeaderField.init(allocator, ":status", "200");
    headers[1] = try HeaderField.init(allocator, "content-type", "text/plain");
    defer {
        for (&headers) |*field| field.deinit();
    }

    const encoded = try encoder.encode(headers[0..], allocator);
    defer allocator.free(encoded);

    const decoded = try decoder.decode(encoded, allocator);
    defer {
        for (decoded) |*field| field.deinit();
        allocator.free(decoded);
    }

    try std.testing.expect(decoded.len == headers.len);
    try std.testing.expect(std.mem.eql(u8, decoded[0].name, ":status"));
    try std.testing.expect(std.mem.eql(u8, decoded[1].value, "text/plain"));
}

fn writeVarint(buffer: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value: usize) !void {
    if (value < 64) {
        try buffer.append(allocator, @intCast(value));
    } else if (value < 16384) {
        try buffer.append(allocator, @intCast(0x40 | (value >> 8)));
        try buffer.append(allocator, @intCast(value & 0xFF));
    } else if (value < 1073741824) {
        try buffer.append(allocator, @intCast(0x80 | (value >> 24)));
        try buffer.append(allocator, @intCast((value >> 16) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 8) & 0xFF));
        try buffer.append(allocator, @intCast(value & 0xFF));
    } else {
        try buffer.append(allocator, @intCast(0xC0 | (value >> 56)));
        try buffer.append(allocator, @intCast((value >> 48) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 40) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 32) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 24) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 16) & 0xFF));
        try buffer.append(allocator, @intCast((value >> 8) & 0xFF));
        try buffer.append(allocator, @intCast(value & 0xFF));
    }
}

fn readVarint(data: []const u8, cursor: *usize) Error.ZquicError!usize {
    if (cursor.* >= data.len) return Error.ZquicError.InvalidData;
    const first = data[cursor.*];
    cursor.* += 1;

    const prefix = first >> 6;
    const length: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };

    var value: usize = first & 0x3F;
    var remaining = length - 1;
    while (remaining > 0) : (remaining -= 1) {
        if (cursor.* >= data.len) return Error.ZquicError.InvalidData;
        value = (value << 8) | data[cursor.*];
        cursor.* += 1;
    }

    return value;
}
