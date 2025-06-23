//! HTTP/3 frame handling
//!
//! Implements HTTP/3 frame parsing and serialization according to RFC 9114

const std = @import("std");
const Error = @import("../utils/error.zig");

/// HTTP/3 frame types
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
};

/// HTTP/3 frame header
pub const FrameHeader = struct {
    frame_type: FrameType,
    length: u64,

    const Self = @This();

    /// Parse frame header from bytes
    pub fn parse(data: []const u8) Error.ZquicError!struct { header: Self, consumed: usize } {
        if (data.len < 2) {
            return Error.ZquicError.Http3Error;
        }

        var offset: usize = 0;

        // Parse frame type (variable-length integer)
        const frame_type_result = parseVarintFrom(data, offset);
        const frame_type_val = frame_type_result.value;
        offset += frame_type_result.consumed;

        // Parse length (variable-length integer)
        if (offset >= data.len) {
            return Error.ZquicError.Http3Error;
        }

        const length_result = parseVarintFrom(data, offset);
        const length = length_result.value;
        offset += length_result.consumed;

        const frame_type: FrameType = switch (frame_type_val) {
            0x00 => .data,
            0x01 => .headers,
            0x03 => .cancel_push,
            0x04 => .settings,
            0x05 => .push_promise,
            0x07 => .goaway,
            0x0d => .max_push_id,
            else => return Error.ZquicError.Http3Error,
        };

        return .{
            .header = Self{
                .frame_type = frame_type,
                .length = length,
            },
            .consumed = offset,
        };
    }

    /// Serialize frame header to bytes
    pub fn serialize(self: *const Self, writer: anytype) !void {
        try writeVarint(writer, @intFromEnum(self.frame_type));
        try writeVarint(writer, self.length);
    }
};

/// HTTP/3 DATA frame
pub const DataFrame = struct {
    data: []const u8,

    const Self = @This();

    pub fn init(data: []const u8) Self {
        return Self{ .data = data };
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        const header = FrameHeader{
            .frame_type = .data,
            .length = self.data.len,
        };

        try header.serialize(writer);
        try writer.writeAll(self.data);
    }
};

/// HTTP/3 HEADERS frame
pub const HeadersFrame = struct {
    encoded_headers: []const u8,

    const Self = @This();

    pub fn init(encoded_headers: []const u8) Self {
        return Self{ .encoded_headers = encoded_headers };
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        const header = FrameHeader{
            .frame_type = .headers,
            .length = self.encoded_headers.len,
        };

        try header.serialize(writer);
        try writer.writeAll(self.encoded_headers);
    }
};

/// HTTP/3 SETTINGS frame
pub const SettingsFrame = struct {
    settings: std.ArrayList(struct { id: u64, value: u64 }),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .settings = std.ArrayList(struct { id: u64, value: u64 }).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.settings.deinit();
    }

    pub fn addSetting(self: *Self, id: u64, value: u64) !void {
        try self.settings.append(.{ .id = id, .value = value });
    }

    pub fn serialize(self: *const Self, writer: anytype, allocator: std.mem.Allocator) !void {
        // Calculate total length
        var total_length: usize = 0;
        for (self.settings.items) |entry| {
            total_length += varintLength(entry.id);
            total_length += varintLength(entry.value);
        }

        const header = FrameHeader{
            .frame_type = .settings,
            .length = total_length,
        };

        try header.serialize(writer);

        // Write settings
        for (self.settings.items) |entry| {
            try writeVarint(writer, entry.id);
            try writeVarint(writer, entry.value);
        }

        _ = allocator; // Not used in this simplified implementation
    }

    pub fn parse(data: []const u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        var settings = Self.init(allocator);
        var offset: usize = 0;

        while (offset < data.len) {
            if (offset + 1 >= data.len) break;

            const id_result = parseVarintFrom(data, offset);
            offset += id_result.consumed;

            if (offset >= data.len) break;

            const value_result = parseVarintFrom(data, offset);
            offset += value_result.consumed;

            try settings.addSetting(id_result.value, value_result.value);
        }

        return settings;
    }
};

/// HTTP/3 frame parser
pub const FrameParser = struct {
    buffer: std.ArrayList(u8),
    state: ParserState,
    current_frame_type: ?FrameType,
    current_frame_length: u64,
    bytes_remaining: u64,

    const ParserState = enum {
        waiting_for_header,
        waiting_for_payload,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .buffer = std.ArrayList(u8).init(allocator),
            .state = .waiting_for_header,
            .current_frame_type = null,
            .current_frame_length = 0,
            .bytes_remaining = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit();
    }

    /// Process incoming data and extract complete frames
    pub fn processData(self: *Self, data: []const u8, allocator: std.mem.Allocator) Error.ZquicError![]Frame {
        try self.buffer.appendSlice(data);

        var frames = std.ArrayList(Frame).init(allocator);

        while (true) {
            switch (self.state) {
                .waiting_for_header => {
                    if (self.buffer.items.len < 2) break; // Need at least 2 bytes for minimal header

                    const parse_result = FrameHeader.parse(self.buffer.items) catch break;

                    self.current_frame_type = parse_result.header.frame_type;
                    self.current_frame_length = parse_result.header.length;
                    self.bytes_remaining = parse_result.header.length;
                    self.state = .waiting_for_payload;

                    // Remove header bytes from buffer
                    const remaining = self.buffer.items[parse_result.consumed..];
                    std.mem.copyForwards(u8, self.buffer.items, remaining);
                    self.buffer.shrinkRetainingCapacity(self.buffer.items.len - parse_result.consumed);
                },
                .waiting_for_payload => {
                    if (self.buffer.items.len < self.bytes_remaining) break; // Not enough data

                    // Extract frame payload
                    const payload = try allocator.dupe(u8, self.buffer.items[0..self.bytes_remaining]);

                    // Create frame
                    const frame = Frame{
                        .frame_type = self.current_frame_type.?,
                        .payload = payload,
                    };

                    try frames.append(frame);

                    // Remove payload bytes from buffer
                    const remaining = self.buffer.items[self.bytes_remaining..];
                    std.mem.copyForwards(u8, self.buffer.items, remaining);
                    const bytes_to_remove: usize = @intCast(self.bytes_remaining);
                    self.buffer.shrinkRetainingCapacity(self.buffer.items.len - bytes_to_remove);

                    // Reset state
                    self.state = .waiting_for_header;
                    self.current_frame_type = null;
                    self.current_frame_length = 0;
                    self.bytes_remaining = 0;
                },
            }
        }

        return frames.toOwnedSlice();
    }
};

/// Generic HTTP/3 frame
pub const Frame = struct {
    frame_type: FrameType,
    payload: []const u8,

    const Self = @This();

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

/// Variable-length integer parsing (simplified)
fn parseVarintFrom(data: []const u8, offset: usize) struct { value: u64, consumed: usize } {
    if (offset >= data.len) return .{ .value = 0, .consumed = 0 };

    const first_byte = data[offset];
    const length = switch (first_byte >> 6) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };

    if (offset + length > data.len) return .{ .value = 0, .consumed = 0 };

    var value: u64 = first_byte & 0x3f; // Remove length bits

    var i: usize = 1;
    while (i < length) : (i += 1) {
        value = (value << 8) | data[offset + i];
    }

    return .{ .value = value, .consumed = length };
}

/// Write variable-length integer
fn writeVarint(writer: anytype, value: u64) !void {
    if (value < 64) {
        try writer.writeByte(@intCast(value));
    } else if (value < 16384) {
        try writer.writeByte(@intCast(0x40 | (value >> 8)));
        try writer.writeByte(@intCast(value & 0xff));
    } else if (value < 1073741824) {
        try writer.writeByte(@intCast(0x80 | (value >> 24)));
        try writer.writeByte(@intCast((value >> 16) & 0xff));
        try writer.writeByte(@intCast((value >> 8) & 0xff));
        try writer.writeByte(@intCast(value & 0xff));
    } else {
        try writer.writeByte(@intCast(0xc0 | (value >> 56)));
        try writer.writeByte(@intCast((value >> 48) & 0xff));
        try writer.writeByte(@intCast((value >> 40) & 0xff));
        try writer.writeByte(@intCast((value >> 32) & 0xff));
        try writer.writeByte(@intCast((value >> 24) & 0xff));
        try writer.writeByte(@intCast((value >> 16) & 0xff));
        try writer.writeByte(@intCast((value >> 8) & 0xff));
        try writer.writeByte(@intCast(value & 0xff));
    }
}

/// Calculate variable-length integer encoding length
fn varintLength(value: u64) usize {
    if (value < 64) return 1;
    if (value < 16384) return 2;
    if (value < 1073741824) return 4;
    return 8;
}

test "frame header parsing and serialization" {
    var buffer: [16]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    const header = FrameHeader{
        .frame_type = .data,
        .length = 100,
    };

    try header.serialize(stream.writer());

    const parse_result = try FrameHeader.parse(stream.getWritten());
    try std.testing.expect(parse_result.header.frame_type == .data);
    try std.testing.expect(parse_result.header.length == 100);
}

test "settings frame" {
    var settings = SettingsFrame.init(std.testing.allocator);
    defer settings.deinit();

    try settings.addSetting(1, 1000);
    try settings.addSetting(6, 4096);

    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    try settings.serialize(stream.writer(), std.testing.allocator);
    try std.testing.expect(stream.pos > 0);
}
