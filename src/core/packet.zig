//! QUIC packet parsing and serialization
//!
//! Implements QUIC packet format according to RFC 9000

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QUIC packet types
pub const PacketType = enum(u8) {
    initial = 0x00,
    zero_rtt = 0x10,
    handshake = 0x20,
    retry = 0x30,
    version_negotiation = 0xf0,
    one_rtt = 0x40,
};

/// QUIC packet number space
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

/// Connection ID
pub const ConnectionId = struct {
    data: [20]u8,
    len: u8,

    const Self = @This();

    pub fn init(data: []const u8) Error.ZquicError!Self {
        if (data.len > 20) {
            return Error.ZquicError.InvalidArgument;
        }

        var cid = Self{
            .data = std.mem.zeroes([20]u8),
            .len = @intCast(data.len),
        };

        @memcpy(cid.data[0..data.len], data);
        return cid;
    }

    pub fn bytes(self: *const Self) []const u8 {
        return self.data[0..self.len];
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.bytes(), other.bytes());
    }
};

/// QUIC packet header
pub const PacketHeader = struct {
    packet_type: PacketType,
    version: ?u32, // null for short header packets
    dest_conn_id: ConnectionId,
    src_conn_id: ?ConnectionId, // null for short header packets
    packet_number: u64,
    packet_number_len: u8,
    token: ?[]const u8, // for Initial packets

    const Self = @This();

    /// Parse a QUIC packet header from bytes
    pub fn parse(data: []const u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        if (data.len == 0) {
            return Error.ZquicError.InvalidPacket;
        }

        var offset: usize = 0;
        const first_byte = data[offset];
        offset += 1;

        const header_form = (first_byte & 0x80) != 0;

        if (header_form) {
            // Long header packet
            return parseLongHeader(data, offset, first_byte, allocator);
        } else {
            // Short header packet
            return parseShortHeader(data, offset, first_byte, allocator);
        }
    }

    fn parseLongHeader(data: []const u8, offset: usize, first_byte: u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        _ = allocator;
        var pos = offset;

        if (pos + 4 > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        // Parse version
        const version = std.mem.readInt(u32, data[pos .. pos + 4], .big);
        pos += 4;

        // Parse destination connection ID length
        if (pos >= data.len) {
            return Error.ZquicError.InvalidPacket;
        }
        const dest_cid_len = data[pos];
        pos += 1;

        if (pos + dest_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const dest_conn_id = try ConnectionId.init(data[pos .. pos + dest_cid_len]);
        pos += dest_cid_len;

        // Parse source connection ID length
        if (pos >= data.len) {
            return Error.ZquicError.InvalidPacket;
        }
        const src_cid_len = data[pos];
        pos += 1;

        if (pos + src_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const src_conn_id = try ConnectionId.init(data[pos .. pos + src_cid_len]);
        pos += src_cid_len;

        const packet_type: PacketType = switch (first_byte & 0x30) {
            0x00 => .initial,
            0x10 => .zero_rtt,
            0x20 => .handshake,
            0x30 => .retry,
            else => return Error.ZquicError.InvalidPacket,
        };

        // For now, return a basic header (token and packet number parsing omitted for brevity)
        return Self{
            .packet_type = packet_type,
            .version = version,
            .dest_conn_id = dest_conn_id,
            .src_conn_id = src_conn_id,
            .packet_number = 0, // Would be parsed from protected header
            .packet_number_len = 1,
            .token = null,
        };
    }

    fn parseShortHeader(data: []const u8, offset: usize, first_byte: u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        _ = allocator;
        _ = first_byte;
        var pos = offset;

        // Parse destination connection ID (length is negotiated during handshake)
        // For simplicity, assume 8 bytes
        const dest_cid_len = 8;
        if (pos + dest_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const dest_conn_id = try ConnectionId.init(data[pos .. pos + dest_cid_len]);
        pos += dest_cid_len;

        return Self{
            .packet_type = .one_rtt,
            .version = null,
            .dest_conn_id = dest_conn_id,
            .src_conn_id = null,
            .packet_number = 0, // Would be parsed from protected header
            .packet_number_len = 1,
            .token = null,
        };
    }

    /// Serialize packet header to bytes
    pub fn serialize(self: *const Self, writer: anytype) !void {
        switch (self.packet_type) {
            .initial, .zero_rtt, .handshake, .retry => {
                // Long header
                var first_byte: u8 = 0x80; // Header form = 1
                first_byte |= switch (self.packet_type) {
                    .initial => 0x00,
                    .zero_rtt => 0x10,
                    .handshake => 0x20,
                    .retry => 0x30,
                    else => unreachable,
                };

                try writer.writeByte(first_byte);
                try writer.writeInt(u32, self.version.?, .big);
                try writer.writeByte(self.dest_conn_id.len);
                try writer.writeAll(self.dest_conn_id.bytes());

                if (self.src_conn_id) |src_cid| {
                    try writer.writeByte(src_cid.len);
                    try writer.writeAll(src_cid.bytes());
                } else {
                    try writer.writeByte(0);
                }
            },
            .one_rtt => {
                // Short header
                const first_byte: u8 = 0x40; // Header form = 0, Fixed bit = 1
                try writer.writeByte(first_byte);
                try writer.writeAll(self.dest_conn_id.bytes());
            },
            else => return Error.ZquicError.NotSupported,
        }
    }
};

/// QUIC packet
pub const Packet = struct {
    header: PacketHeader,
    payload: []const u8,

    const Self = @This();

    pub fn init(header: PacketHeader, payload: []const u8) Self {
        return Self{
            .header = header,
            .payload = payload,
        };
    }
};

test "connection id creation and comparison" {
    const cid1 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const cid2 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const cid3 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 5 });

    try std.testing.expect(cid1.eql(&cid2));
    try std.testing.expect(!cid1.eql(&cid3));
    try std.testing.expect(cid1.len == 4);
}

test "packet header serialization" {
    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    const dest_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const src_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    const header = PacketHeader{
        .packet_type = .initial,
        .version = 0x00000001,
        .dest_conn_id = dest_cid,
        .src_conn_id = src_cid,
        .packet_number = 0,
        .packet_number_len = 1,
        .token = null,
    };

    try header.serialize(stream.writer());
    try std.testing.expect(stream.pos > 0);
}
