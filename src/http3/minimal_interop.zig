//! Bounded HTTP/3 wire primitives for the live interop probe.
//!
//! This deliberately supports only the zero-dynamic-table subset needed for
//! an external `GET /`: peer SETTINGS, static/literal request fields, and a
//! static `:status 200` response. It is not the general HTTP/3 server API.

const std = @import("std");

pub const max_stream_bytes = 4096;

pub const Error = error{
    WouldBlock,
    StreamTooLarge,
    ConflictingData,
    InvalidStream,
    InvalidSettings,
    InvalidHeaderBlock,
    DynamicReference,
    NotGetRoot,
};

pub const StreamReassembler = struct {
    data: [max_stream_bytes]u8 = undefined,
    received: [max_stream_bytes / 8]u8 = @splat(0),
    contiguous_len: usize = 0,
    received_end: usize = 0,
    final_size: ?usize = null,

    pub fn insert(self: *StreamReassembler, offset: u64, bytes: []const u8, fin: bool) Error!void {
        const start = std.math.cast(usize, offset) orelse return Error.StreamTooLarge;
        const end = std.math.add(usize, start, bytes.len) catch return Error.StreamTooLarge;
        if (end > max_stream_bytes) return Error.StreamTooLarge;
        if (self.final_size) |final_size| {
            if (end > final_size or (fin and end != final_size)) return Error.InvalidStream;
        }
        if (fin and self.received_end > end) return Error.InvalidStream;

        for (bytes, start..) |byte, index| {
            if (self.hasByte(index)) {
                if (self.data[index] != byte) return Error.ConflictingData;
            } else {
                self.data[index] = byte;
                self.markByte(index);
            }
        }

        if (fin) self.final_size = end;
        self.received_end = @max(self.received_end, end);
        while (self.contiguous_len < max_stream_bytes and self.hasByte(self.contiguous_len)) {
            self.contiguous_len += 1;
        }
        if (self.final_size) |final_size| {
            if (self.contiguous_len > final_size) return Error.InvalidStream;
        }
    }

    pub fn contiguous(self: *const StreamReassembler) []const u8 {
        return self.data[0..self.contiguous_len];
    }

    pub fn complete(self: *const StreamReassembler) bool {
        return if (self.final_size) |final_size| self.contiguous_len == final_size else false;
    }

    fn hasByte(self: *const StreamReassembler, index: usize) bool {
        return self.received[index / 8] & (@as(u8, 1) << @intCast(index % 8)) != 0;
    }

    fn markByte(self: *StreamReassembler, index: usize) void {
        self.received[index / 8] |= @as(u8, 1) << @intCast(index % 8);
    }
};

pub const Request = struct {
    method_get: bool,
    path_root: bool,
};

pub fn parseStreamType(stream_data: []const u8) Error!u64 {
    var cursor: usize = 0;
    return readVarint(stream_data, &cursor);
}

/// Validate a client control stream through its mandatory first SETTINGS
/// frame. Unknown settings are retained only as syntax evidence and ignored.
pub fn parseControlSettings(stream_data: []const u8) Error!void {
    var cursor: usize = 0;
    if (try readVarint(stream_data, &cursor) != 0) return Error.InvalidStream;
    if (try readVarint(stream_data, &cursor) != 0x04) return Error.InvalidSettings;
    const payload_len = try lengthAsUsize(try readVarint(stream_data, &cursor));
    const payload_end = std.math.add(usize, cursor, payload_len) catch return Error.InvalidSettings;
    if (payload_end > stream_data.len) return Error.WouldBlock;

    var seen: [16]u64 = undefined;
    var seen_count: usize = 0;
    while (cursor < payload_end) {
        const id = try readVarintWithin(stream_data, &cursor, payload_end, Error.InvalidSettings);
        _ = try readVarintWithin(stream_data, &cursor, payload_end, Error.InvalidSettings);
        for (seen[0..seen_count]) |existing| {
            if (existing == id) return Error.InvalidSettings;
        }
        if (seen_count == seen.len) return Error.InvalidSettings;
        seen[seen_count] = id;
        seen_count += 1;
    }
}

/// Parse the first request-stream HEADERS frame and prove it is `GET /`.
/// Unknown frame types are skipped as required by HTTP/3 extensibility; known
/// frames that are illegal before the initial HEADERS remain fatal.
pub fn parseGetRootRequest(stream_data: []const u8) Error!Request {
    var cursor: usize = 0;
    while (cursor < stream_data.len) {
        const frame_type = try readVarint(stream_data, &cursor);
        const payload_len = try lengthAsUsize(try readVarint(stream_data, &cursor));
        const payload_end = std.math.add(usize, cursor, payload_len) catch return Error.InvalidHeaderBlock;
        if (payload_end > stream_data.len) return Error.WouldBlock;

        if (frame_type == 0x01) {
            const request = try parseHeaderBlock(stream_data[cursor..payload_end]);
            if (!request.method_get or !request.path_root) return Error.NotGetRoot;
            return request;
        }

        // These core frame types are forbidden before request HEADERS. Every
        // other type is an extension and has to be ignored, including GREASE.
        switch (frame_type) {
            0x00, 0x03, 0x04, 0x05, 0x07, 0x0d => return Error.InvalidStream,
            else => cursor = payload_end,
        }
    }
    return Error.WouldBlock;
}

fn parseHeaderBlock(block: []const u8) Error!Request {
    var cursor: usize = 0;
    const required_insert_count = try readPrefixedInt(block, &cursor, 8);
    if (required_insert_count != 0) return Error.DynamicReference;
    if (cursor >= block.len) return Error.WouldBlock;
    // With a zero Required Insert Count, a negative Delta Base would compute a
    // base below zero. It also signals dynamic-table semantics this endpoint
    // deliberately does not implement.
    if (block[cursor] & 0x80 != 0) return Error.DynamicReference;
    const delta_base = try readPrefixedInt(block, &cursor, 7);
    if (delta_base != 0) return Error.DynamicReference;

    var state = RequestState{};
    while (cursor < block.len) {
        const first = block[cursor];
        if (first & 0x80 != 0) {
            const is_static = first & 0x40 != 0;
            const index = try readPrefixedInt(block, &cursor, 6);
            if (!is_static) return Error.DynamicReference;
            try applyStaticExact(index, &state);
        } else if (first & 0xc0 == 0x40) {
            const is_static = first & 0x10 != 0;
            const name_index = try readPrefixedInt(block, &cursor, 4);
            if (!is_static) return Error.DynamicReference;
            const value = try readStringLiteral(block, &cursor);
            try applyStaticName(name_index, value, &state);
        } else if (first & 0xe0 == 0x20) {
            const name_huffman = first & 0x08 != 0;
            const name_len = try lengthAsUsize(try readPrefixedInt(block, &cursor, 3));
            const name_end = std.math.add(usize, cursor, name_len) catch return Error.InvalidHeaderBlock;
            if (name_end > block.len) return Error.WouldBlock;
            // Without a Huffman decoder we cannot prove that an encoded name
            // is not a duplicate pseudo-header, so reject it rather than
            // silently weakening request validation.
            if (name_huffman) return Error.InvalidHeaderBlock;
            const name = block[cursor..name_end];
            cursor = name_end;
            const value = try readStringLiteral(block, &cursor);
            try applyLiteral(name, value, &state);
        } else {
            // Indexed and literal post-base forms necessarily reference the
            // dynamic table, which this zero-capacity endpoint forbids.
            return Error.DynamicReference;
        }
    }
    return state.request;
}

const RequestState = struct {
    request: Request = .{ .method_get = false, .path_root = false },
    method_seen: bool = false,
    path_seen: bool = false,

    fn setMethod(self: *RequestState, is_get: bool) Error!void {
        if (self.method_seen) return Error.InvalidHeaderBlock;
        self.method_seen = true;
        self.request.method_get = is_get;
    }

    fn setPath(self: *RequestState, is_root: bool) Error!void {
        if (self.path_seen) return Error.InvalidHeaderBlock;
        self.path_seen = true;
        self.request.path_root = is_root;
    }
};

fn applyStaticExact(index: u64, state: *RequestState) Error!void {
    switch (index) {
        1 => try state.setPath(true),
        15...21 => try state.setMethod(index == 17),
        else => {},
    }
}

fn applyStaticName(index: u64, value: ?[]const u8, state: *RequestState) Error!void {
    const plain = value orelse return;
    switch (index) {
        1 => try state.setPath(std.mem.eql(u8, plain, "/")),
        15...21 => try state.setMethod(std.mem.eql(u8, plain, "GET")),
        else => {},
    }
}

fn applyLiteral(name: []const u8, value: ?[]const u8, state: *RequestState) Error!void {
    const plain = value orelse return;
    if (std.mem.eql(u8, name, ":method")) try state.setMethod(std.mem.eql(u8, plain, "GET"));
    if (std.mem.eql(u8, name, ":path")) try state.setPath(std.mem.eql(u8, plain, "/"));
}

fn readStringLiteral(data: []const u8, cursor: *usize) Error!?[]const u8 {
    if (cursor.* >= data.len) return Error.WouldBlock;
    const huffman = data[cursor.*] & 0x80 != 0;
    const len = try lengthAsUsize(try readPrefixedInt(data, cursor, 7));
    const end = std.math.add(usize, cursor.*, len) catch return Error.InvalidHeaderBlock;
    if (end > data.len) return Error.WouldBlock;
    const value = data[cursor.*..end];
    cursor.* = end;
    return if (huffman) null else value;
}

fn readVarint(data: []const u8, cursor: *usize) Error!u64 {
    if (cursor.* >= data.len) return Error.WouldBlock;
    const encoded_len: usize = @as(usize, 1) << @intCast(data[cursor.*] >> 6);
    const end = std.math.add(usize, cursor.*, encoded_len) catch return Error.InvalidStream;
    if (end > data.len) return Error.WouldBlock;
    var value: u64 = data[cursor.*] & 0x3f;
    cursor.* += 1;
    var remaining = encoded_len - 1;
    while (remaining > 0) : (remaining -= 1) {
        value = (value << 8) | data[cursor.*];
        cursor.* += 1;
    }
    return value;
}

fn readVarintWithin(data: []const u8, cursor: *usize, end: usize, comptime invalid: Error) Error!u64 {
    const before = cursor.*;
    const value = readVarint(data[0..end], cursor) catch |err| return switch (err) {
        Error.WouldBlock => invalid,
        else => err,
    };
    if (cursor.* <= before or cursor.* > end) return invalid;
    return value;
}

fn readPrefixedInt(data: []const u8, cursor: *usize, comptime prefix_bits: u4) Error!u64 {
    if (cursor.* >= data.len) return Error.WouldBlock;
    const mask: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << prefix_bits) - 1;
    var value: u64 = data[cursor.*] & mask;
    cursor.* += 1;
    if (value < mask) return value;

    var shift: u6 = 0;
    while (true) {
        if (cursor.* >= data.len) return Error.WouldBlock;
        const byte = data[cursor.*];
        cursor.* += 1;
        if (shift >= 63) return Error.InvalidHeaderBlock;
        value = std.math.add(u64, value, @as(u64, byte & 0x7f) << shift) catch return Error.InvalidHeaderBlock;
        if (byte & 0x80 == 0) return value;
        shift += 7;
    }
}

fn lengthAsUsize(value: u64) Error!usize {
    return std.math.cast(usize, value) orelse Error.InvalidStream;
}

/// Server control stream type followed by an empty SETTINGS frame.
pub const server_control_bytes = [_]u8{ 0x00, 0x04, 0x00 };

/// HEADERS(:status=200, content-length=6) followed by DATA("zquic\n").
pub const get_root_response_bytes = [_]u8{
    0x01, 0x06, 0x00, 0x00, 0xd9, 0x54,
    0x01, '6',  0x00, 0x06, 'z',  'q',
    'u',  'i',  'c',  '\n',
};

test "minimal interop stream reassembly handles fragmentation and overlap" {
    var stream = StreamReassembler{};
    try stream.insert(3, "def", true);
    try std.testing.expectEqual(@as(usize, 0), stream.contiguous().len);
    try stream.insert(0, "abc", false);
    try std.testing.expectEqualStrings("abcdef", stream.contiguous());
    try std.testing.expect(stream.complete());
    try stream.insert(1, "bc", false);
    try std.testing.expectError(Error.ConflictingData, stream.insert(1, "zz", false));

    var invalid_final_size = StreamReassembler{};
    try invalid_final_size.insert(8, "late", false);
    try std.testing.expectError(Error.InvalidStream, invalid_final_size.insert(0, "short", true));
}

test "minimal interop parses control SETTINGS and static GET root" {
    try parseControlSettings(&[_]u8{ 0x00, 0x04, 0x02, 0x01, 0x00 });
    try std.testing.expectError(Error.InvalidSettings, parseControlSettings(&[_]u8{ 0x00, 0x04, 0x04, 0x01, 0x00, 0x01, 0x00 }));

    const request = try parseGetRootRequest(&[_]u8{ 0x01, 0x04, 0x00, 0x00, 0xd1, 0xc1 });
    try std.testing.expect(request.method_get);
    try std.testing.expect(request.path_root);
    const greased = try parseGetRootRequest(&[_]u8{ 0x21, 0x00, 0x01, 0x04, 0x00, 0x00, 0xd1, 0xc1 });
    try std.testing.expect(greased.method_get);
    try std.testing.expect(greased.path_root);
    try std.testing.expectError(Error.InvalidStream, parseGetRootRequest(&[_]u8{ 0x00, 0x00 }));
    try std.testing.expectError(Error.DynamicReference, parseGetRootRequest(&[_]u8{ 0x01, 0x03, 0x00, 0x00, 0x80 }));
    try std.testing.expectError(Error.DynamicReference, parseGetRootRequest(&[_]u8{ 0x01, 0x04, 0x00, 0x80, 0xd1, 0xc1 }));
    try std.testing.expectError(Error.InvalidHeaderBlock, parseGetRootRequest(&[_]u8{ 0x01, 0x05, 0x00, 0x00, 0xd1, 0xd1, 0xc1 }));
}

test "minimal interop response has static 200 headers data and exact lengths" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x04, 0x00 }, &server_control_bytes);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, '6', 0x00, 0x06, 'z', 'q', 'u', 'i', 'c', '\n' },
        &get_root_response_bytes,
    );
}
