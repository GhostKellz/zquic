//! QUIC flow control implementation
//!
//! Implements connection and stream-level flow control according to RFC 9000

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Flow control window for a stream or connection
pub const FlowControlWindow = struct {
    limit: u64,
    consumed: u64,
    advertised: u64,

    const Self = @This();

    pub fn init(initial_limit: u64) Self {
        return Self{
            .limit = initial_limit,
            .consumed = 0,
            .advertised = initial_limit,
        };
    }

    /// Check if we can send `size` bytes
    pub fn canSend(self: *const Self, size: u64) bool {
        return self.consumed + size <= self.limit;
    }

    /// Consume `size` bytes from the flow control window
    pub fn consume(self: *Self, size: u64) Error.ZquicError!void {
        if (!self.canSend(size)) {
            return Error.ZquicError.FlowControlError;
        }
        self.consumed += size;
    }

    /// Return available window space
    pub fn available(self: *const Self) u64 {
        return self.limit - self.consumed;
    }

    /// Update the flow control limit (when receiving MAX_DATA or MAX_STREAM_DATA)
    pub fn updateLimit(self: *Self, new_limit: u64) Error.ZquicError!void {
        if (new_limit < self.limit) {
            return Error.ZquicError.FlowControlError;
        }
        self.limit = new_limit;
    }

    /// Check if we should send a flow control update
    pub fn shouldSendUpdate(self: *const Self) bool {
        // Send update when we've consumed more than half of the advertised window
        return self.consumed > self.advertised / 2;
    }

    /// Generate a new flow control limit to advertise
    pub fn generateUpdate(self: *Self, max_window: u64) u64 {
        // Increase the window based on consumption patterns
        const new_limit = @min(self.consumed + max_window, std.math.maxInt(u64));
        self.advertised = new_limit;
        return new_limit;
    }
};

/// Connection-level flow control state
pub const ConnectionFlowControl = struct {
    send_window: FlowControlWindow,
    recv_window: FlowControlWindow,
    max_data: u64,

    const Self = @This();

    pub fn init(initial_max_data: u64, peer_max_data: u64) Self {
        return Self{
            .send_window = FlowControlWindow.init(peer_max_data),
            .recv_window = FlowControlWindow.init(initial_max_data),
            .max_data = initial_max_data,
        };
    }

    /// Check if we can send data at the connection level
    pub fn canSendData(self: *const Self, size: u64) bool {
        return self.send_window.canSend(size);
    }

    /// Consume connection-level flow control credit for sending
    pub fn consumeSendCredit(self: *Self, size: u64) Error.ZquicError!void {
        return self.send_window.consume(size);
    }

    /// Consume connection-level flow control credit for receiving
    pub fn consumeRecvCredit(self: *Self, size: u64) Error.ZquicError!void {
        return self.recv_window.consume(size);
    }

    /// Update peer's advertised MAX_DATA
    pub fn updatePeerMaxData(self: *Self, max_data: u64) Error.ZquicError!void {
        return self.send_window.updateLimit(max_data);
    }

    /// Check if we should send a MAX_DATA frame
    pub fn shouldSendMaxData(self: *const Self) bool {
        return self.recv_window.shouldSendUpdate();
    }

    /// Generate MAX_DATA value to send
    pub fn generateMaxData(self: *Self) u64 {
        return self.recv_window.generateUpdate(self.max_data);
    }
};

/// Stream-level flow control state
pub const StreamFlowControl = struct {
    send_window: FlowControlWindow,
    recv_window: FlowControlWindow,
    max_stream_data: u64,
    stream_id: u64,

    const Self = @This();

    pub fn init(stream_id: u64, initial_max_stream_data: u64, peer_max_stream_data: u64) Self {
        return Self{
            .send_window = FlowControlWindow.init(peer_max_stream_data),
            .recv_window = FlowControlWindow.init(initial_max_stream_data),
            .max_stream_data = initial_max_stream_data,
            .stream_id = stream_id,
        };
    }

    /// Check if we can send data on this stream
    pub fn canSendData(self: *const Self, size: u64) bool {
        return self.send_window.canSend(size);
    }

    /// Consume stream-level flow control credit for sending
    pub fn consumeSendCredit(self: *Self, size: u64) Error.ZquicError!void {
        return self.send_window.consume(size);
    }

    /// Consume stream-level flow control credit for receiving
    pub fn consumeRecvCredit(self: *Self, size: u64) Error.ZquicError!void {
        return self.recv_window.consume(size);
    }

    /// Update peer's advertised MAX_STREAM_DATA for this stream
    pub fn updatePeerMaxStreamData(self: *Self, max_stream_data: u64) Error.ZquicError!void {
        return self.send_window.updateLimit(max_stream_data);
    }

    /// Check if we should send a MAX_STREAM_DATA frame
    pub fn shouldSendMaxStreamData(self: *const Self) bool {
        return self.recv_window.shouldSendUpdate();
    }

    /// Generate MAX_STREAM_DATA value to send
    pub fn generateMaxStreamData(self: *Self) u64 {
        return self.recv_window.generateUpdate(self.max_stream_data);
    }
};

/// Stream flow control entry
const StreamEntry = struct {
    id: u64,
    fc: StreamFlowControl,
};

/// Combined flow control manager
pub const FlowController = struct {
    connection_fc: ConnectionFlowControl,
    stream_fc_map: std.ArrayList(StreamEntry),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, initial_max_data: u64, peer_max_data: u64) Self {
        return Self{
            .connection_fc = ConnectionFlowControl.init(initial_max_data, peer_max_data),
            .stream_fc_map = std.ArrayList(StreamEntry).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stream_fc_map.deinit();
    }

    /// Add flow control for a new stream
    pub fn addStream(self: *Self, stream_id: u64, initial_max_stream_data: u64, peer_max_stream_data: u64) Error.ZquicError!void {
        const stream_fc = StreamFlowControl.init(stream_id, initial_max_stream_data, peer_max_stream_data);
        try self.stream_fc_map.append(.{ .id = stream_id, .fc = stream_fc });
    }

    /// Check if we can send data (both connection and stream level)
    pub fn canSendStreamData(self: *Self, stream_id: u64, size: u64) bool {
        if (!self.connection_fc.canSendData(size)) {
            return false;
        }

        for (self.stream_fc_map.items) |*entry| {
            if (entry.id == stream_id) {
                return entry.fc.canSendData(size);
            }
        }

        return false;
    }

    /// Consume flow control credit for sending stream data
    pub fn consumeSendCredit(self: *Self, stream_id: u64, size: u64) Error.ZquicError!void {
        try self.connection_fc.consumeSendCredit(size);

        for (self.stream_fc_map.items) |*entry| {
            if (entry.id == stream_id) {
                entry.fc.consumeSendCredit(size) catch |err| {
                    // Rollback connection credit if stream credit failed
                    self.connection_fc.send_window.consumed -= size;
                    return err;
                };
                return;
            }
        }

        return Error.ZquicError.InvalidArgument;
    }

    /// Consume flow control credit for receiving stream data
    pub fn consumeRecvCredit(self: *Self, stream_id: u64, size: u64) Error.ZquicError!void {
        try self.connection_fc.consumeRecvCredit(size);

        for (self.stream_fc_map.items) |*entry| {
            if (entry.id == stream_id) {
                entry.fc.consumeRecvCredit(size) catch |err| {
                    // Rollback connection credit if stream credit failed
                    self.connection_fc.recv_window.consumed -= size;
                    return err;
                };
                return;
            }
        }

        return Error.ZquicError.InvalidArgument;
    }

    /// Get streams that need MAX_STREAM_DATA updates
    pub fn getStreamsNeedingUpdates(self: *Self, allocator: std.mem.Allocator) ![]u64 {
        var streams_needing_updates = std.ArrayList(u64).init(allocator);

        for (self.stream_fc_map.items) |*entry| {
            if (entry.fc.shouldSendMaxStreamData()) {
                try streams_needing_updates.append(entry.id);
            }
        }

        return streams_needing_updates.toOwnedSlice();
    }
};

test "flow control window basic operations" {
    var window = FlowControlWindow.init(1000);

    try std.testing.expect(window.canSend(500));
    try std.testing.expect(window.available() == 1000);

    try window.consume(300);
    try std.testing.expect(window.available() == 700);
    try std.testing.expect(window.canSend(700));
    try std.testing.expect(!window.canSend(701));

    try window.updateLimit(1500);
    try std.testing.expect(window.available() == 1200);
}

test "connection flow control" {
    var conn_fc = ConnectionFlowControl.init(1000, 1000);

    try std.testing.expect(conn_fc.canSendData(500));
    try conn_fc.consumeSendCredit(300);
    try std.testing.expect(!conn_fc.canSendData(701));

    try conn_fc.updatePeerMaxData(1500);
    try std.testing.expect(conn_fc.canSendData(700));
}

test "stream flow control" {
    var stream_fc = StreamFlowControl.init(0, 1000, 1000);

    try std.testing.expect(stream_fc.canSendData(500));
    try stream_fc.consumeSendCredit(300);
    try std.testing.expect(stream_fc.send_window.consumed == 300);

    try stream_fc.consumeRecvCredit(200);
    try std.testing.expect(stream_fc.recv_window.consumed == 200);
}

test "flow controller integration" {
    var fc = FlowController.init(std.testing.allocator, 1000, 1000);
    defer fc.deinit();

    try fc.addStream(0, 500, 500);

    try std.testing.expect(fc.canSendStreamData(0, 300));
    try fc.consumeSendCredit(0, 300);

    // Should be limited by stream flow control now
    try std.testing.expect(!fc.canSendStreamData(0, 201));
    try std.testing.expect(fc.canSendStreamData(0, 200));
}
