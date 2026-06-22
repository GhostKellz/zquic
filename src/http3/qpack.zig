//! QPACK (QUIC Header Compression) implementation
//!
//! Implements QPACK encoder and decoder according to RFC 9204

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QPACK decoder
pub const QpackDecoder = struct {
    dynamic_table: std.ArrayListUnmanaged(HeaderField),
    max_table_capacity: u32,
    max_header_count: usize = 256,
    max_header_block_size: usize = 64 * 1024,

    const Self = @This();

    pub fn init(_: std.mem.Allocator, max_capacity: u32) Self {
        return Self{
            .dynamic_table = .empty,
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
        if (encoded_data.len > self.max_header_block_size) {
            return Error.ZquicError.HeaderError;
        }
        var cursor: usize = 0;
        const header_count = try readVarint(encoded_data, &cursor);
        if (header_count > self.max_header_count) {
            return Error.ZquicError.HeaderError;
        }

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

            try validateHeaderName(name_slice);

            headers[i] = try HeaderField.init(allocator, name_slice, value_slice);
        }

        return headers;
    }
};

fn validateHeaderName(name: []const u8) Error.ZquicError!void {
    if (name.len == 0) return Error.ZquicError.HeaderError;
    for (name) |c| {
        if (std.ascii.isUpper(c) or c == 0 or c == '\r' or c == '\n') {
            return Error.ZquicError.HeaderError;
        }
    }
}

pub const QpackEncoder = struct {
    pub fn init() QpackEncoder {
        return QpackEncoder{};
    }

    pub fn deinit(self: *QpackEncoder) void {
        _ = self;
    }

    pub fn encode(self: *QpackEncoder, headers: []const HeaderField, allocator: std.mem.Allocator) Error.ZquicError![]u8 {
        _ = self;
        var buffer: std.ArrayListUnmanaged(u8) = .empty;
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

test "qpack rejects malformed header names and oversized counts" {
    const allocator = std.testing.allocator;
    var decoder = QpackDecoder.init(allocator, 4096);
    defer decoder.deinit(allocator);

    var bad_upper = [_]u8{
        1, // header count
        4,
        'H',
        'o',
        's',
        't',
        3,
        'x',
        'y',
        'z',
    };
    try std.testing.expectError(Error.ZquicError.HeaderError, decoder.decode(&bad_upper, allocator));

    var bad_empty = [_]u8{
        1, // header count
        0, // empty name
        3,
        'x',
        'y',
        'z',
    };
    try std.testing.expectError(Error.ZquicError.HeaderError, decoder.decode(&bad_empty, allocator));

    decoder.max_header_count = 1;
    var too_many = [_]u8{
        2,
        1,
        'a',
        1,
        'b',
        1,
        'c',
        1,
        'd',
    };
    try std.testing.expectError(Error.ZquicError.HeaderError, decoder.decode(&too_many, allocator));
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
