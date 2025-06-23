//! QUIC stream management
//!
//! Implements QUIC streams according to RFC 9000

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Stream ID and direction utilities
pub const StreamId = struct {
    id: u64,

    const Self = @This();

    pub fn init(id: u64) Self {
        return Self{ .id = id };
    }

    /// Check if stream is client-initiated
    pub fn isClientInitiated(self: Self) bool {
        return (self.id & 0x01) == 0;
    }

    /// Check if stream is server-initiated
    pub fn isServerInitiated(self: Self) bool {
        return (self.id & 0x01) == 1;
    }

    /// Check if stream is bidirectional
    pub fn isBidirectional(self: Self) bool {
        return (self.id & 0x02) == 0;
    }

    /// Check if stream is unidirectional
    pub fn isUnidirectional(self: Self) bool {
        return (self.id & 0x02) == 2;
    }

    /// Get the stream type
    pub fn getType(self: Self) StreamType {
        const client_initiated = self.isClientInitiated();
        const bidirectional = self.isBidirectional();

        if (bidirectional) {
            return if (client_initiated) .client_bidirectional else .server_bidirectional;
        } else {
            return if (client_initiated) .client_unidirectional else .server_unidirectional;
        }
    }
};

/// Stream types
pub const StreamType = enum {
    client_bidirectional,
    server_bidirectional,
    client_unidirectional,
    server_unidirectional,
};

/// Stream states according to RFC 9000
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset_sent,
    reset_received,
};

/// Stream data buffer
pub const StreamBuffer = struct {
    data: std.ArrayList(u8),
    offset: u64,
    fin_received: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .data = std.ArrayList(u8).init(allocator),
            .offset = 0,
            .fin_received = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.data.deinit();
    }

    pub fn write(self: *Self, data: []const u8, offset: u64, fin: bool) Error.ZquicError!void {
        if (offset != self.offset + self.data.items.len) {
            // Out-of-order data - would need reordering buffer in real implementation
            return Error.ZquicError.ProtocolViolation;
        }

        try self.data.appendSlice(data);
        if (fin) {
            self.fin_received = true;
        }
    }

    pub fn read(self: *Self, buffer: []u8) usize {
        const to_read = @min(buffer.len, self.data.items.len);
        @memcpy(buffer[0..to_read], self.data.items[0..to_read]);

        // Remove read data (in real implementation, this would be more efficient)
        const remaining = self.data.items[to_read..];
        std.mem.copyForwards(u8, self.data.items, remaining);
        self.data.shrinkRetainingCapacity(self.data.items.len - to_read);

        self.offset += to_read;
        return to_read;
    }

    pub fn available(self: *const Self) usize {
        return self.data.items.len;
    }

    pub fn isComplete(self: *const Self) bool {
        return self.fin_received and self.data.items.len == 0;
    }
};

/// QUIC stream
pub const Stream = struct {
    id: StreamId,
    state: StreamState,
    send_buffer: StreamBuffer,
    recv_buffer: StreamBuffer,
    flow_control_limit: u64,
    flow_control_consumed: u64,
    max_stream_data: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, stream_id: u64) Self {
        return Self{
            .id = StreamId.init(stream_id),
            .state = .idle,
            .send_buffer = StreamBuffer.init(allocator),
            .recv_buffer = StreamBuffer.init(allocator),
            .flow_control_limit = 65536, // Default 64KB
            .flow_control_consumed = 0,
            .max_stream_data = 65536,
        };
    }

    pub fn deinit(self: *Self) void {
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
    }

    /// Write data to the stream
    pub fn write(self: *Self, data: []const u8, fin: bool) Error.ZquicError!usize {
        if (self.state != .open and self.state != .half_closed_remote) {
            return Error.ZquicError.StreamStateError;
        }

        // Check flow control
        if (self.flow_control_consumed + data.len > self.flow_control_limit) {
            return Error.ZquicError.FlowControlError;
        }

        try self.send_buffer.write(data, self.send_buffer.offset + self.send_buffer.data.items.len, fin);

        if (fin) {
            self.state = switch (self.state) {
                .open => .half_closed_local,
                .half_closed_remote => .closed,
                else => self.state,
            };
        }

        return data.len;
    }

    /// Read data from the stream
    pub fn read(self: *Self, buffer: []u8) usize {
        if (self.state != .open and self.state != .half_closed_local) {
            return 0;
        }

        return self.recv_buffer.read(buffer);
    }

    /// Receive data on the stream (called when STREAM frame is received)
    pub fn receiveData(self: *Self, data: []const u8, offset: u64, fin: bool) Error.ZquicError!void {
        if (self.state == .closed or self.state == .reset_received) {
            return Error.ZquicError.StreamStateError;
        }

        // Check flow control
        if (offset + data.len > self.max_stream_data) {
            return Error.ZquicError.FlowControlError;
        }

        try self.recv_buffer.write(data, offset, fin);

        if (fin) {
            self.state = switch (self.state) {
                .open => .half_closed_remote,
                .half_closed_local => .closed,
                else => self.state,
            };
        }
    }

    /// Reset the stream
    pub fn reset(self: *Self, error_code: u64) void {
        _ = error_code;
        self.state = .reset_sent;
        // In real implementation, would send RESET_STREAM frame
    }

    /// Check if stream is readable
    pub fn isReadable(self: *const Self) bool {
        return (self.state == .open or self.state == .half_closed_local) and
            self.recv_buffer.available() > 0;
    }

    /// Check if stream is writable
    pub fn isWritable(self: *const Self) bool {
        return self.state == .open or self.state == .half_closed_remote;
    }

    /// Check if stream is finished
    pub fn isFinished(self: *const Self) bool {
        return self.state == .closed or
            self.state == .reset_sent or
            self.state == .reset_received;
    }
};

test "stream id properties" {
    const client_bidi = StreamId.init(0);
    try std.testing.expect(client_bidi.isClientInitiated());
    try std.testing.expect(client_bidi.isBidirectional());
    try std.testing.expect(client_bidi.getType() == .client_bidirectional);

    const server_uni = StreamId.init(3);
    try std.testing.expect(server_uni.isServerInitiated());
    try std.testing.expect(server_uni.isUnidirectional());
    try std.testing.expect(server_uni.getType() == .server_unidirectional);
}

test "stream buffer operations" {
    var buffer = StreamBuffer.init(std.testing.allocator);
    defer buffer.deinit();

    try buffer.write("hello", 0, false);
    try buffer.write(" world", 5, true);

    var read_buf: [20]u8 = undefined;
    const read_len = buffer.read(&read_buf);

    try std.testing.expect(read_len == 11);
    try std.testing.expectEqualStrings("hello world", read_buf[0..read_len]);
    try std.testing.expect(buffer.isComplete());
}

test "stream basic operations" {
    var stream = Stream.init(std.testing.allocator, 0);
    defer stream.deinit();

    stream.state = .open;

    const written = try stream.write("test data", false);
    try std.testing.expect(written == 9);

    try stream.receiveData("received data", 0, true);
    try std.testing.expect(stream.state == .half_closed_remote);

    var read_buf: [20]u8 = undefined;
    const read_len = stream.read(&read_buf);
    try std.testing.expect(read_len == 13);
    try std.testing.expectEqualStrings("received data", read_buf[0..read_len]);
}
