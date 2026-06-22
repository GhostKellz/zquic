//! QUIC flow control implementation
//!
//! Implements connection and stream-level flow control according to RFC 9000

const std = @import("std");
const Error = @import("../utils/error.zig");
const Frame = @import("quic_frames.zig").Frame;
const MaxDataFrame = @import("quic_frames.zig").MaxDataFrame;
const MaxStreamDataFrame = @import("quic_frames.zig").MaxStreamDataFrame;
const MaxStreamsFrame = @import("quic_frames.zig").MaxStreamsFrame;
const DataBlockedFrame = @import("quic_frames.zig").DataBlockedFrame;
const StreamDataBlockedFrame = @import("quic_frames.zig").StreamDataBlockedFrame;
const StreamsBlockedFrame = @import("quic_frames.zig").StreamsBlockedFrame;

/// Flow control window for a stream or connection
pub const FlowControlWindow = struct {
    limit: u64,
    consumed: u64,
    advertised: u64,
    blocked_at: ?u64,

    const Self = @This();

    pub fn init(initial_limit: u64) Self {
        return Self{
            .limit = initial_limit,
            .consumed = 0,
            .advertised = initial_limit,
            .blocked_at = null,
        };
    }

    /// Check if we can send `size` bytes
    pub fn canSend(self: *const Self, size: u64) bool {
        return size <= self.available();
    }

    /// Consume `size` bytes from the flow control window
    pub fn consume(self: *Self, size: u64) Error.ZquicError!void {
        if (!self.canSend(size)) {
            self.blocked_at = self.limit;
            return Error.ZquicError.FlowControlError;
        }
        self.consumed += size;
        self.blocked_at = null;
    }

    /// Return available window space
    pub fn available(self: *const Self) u64 {
        return self.limit -| self.consumed;
    }

    /// Update the flow control limit (when receiving MAX_DATA or MAX_STREAM_DATA)
    pub fn updateLimit(self: *Self, new_limit: u64) Error.ZquicError!void {
        if (new_limit < self.limit) {
            return Error.ZquicError.FlowControlError;
        }
        self.limit = new_limit;
        if (self.consumed < self.limit) {
            self.blocked_at = null;
        }
    }

    /// Check if we should send a flow control update
    pub fn shouldSendUpdate(self: *const Self) bool {
        return self.consumed >= self.advertised / 2 and self.advertised == self.limit;
    }

    /// Generate a new flow control limit to advertise
    pub fn generateUpdate(self: *Self, max_window: u64) u64 {
        // Increase the window based on consumption patterns
        const new_limit = @min(self.consumed + max_window, std.math.maxInt(u64));
        self.limit = @max(self.limit, new_limit);
        self.advertised = new_limit;
        return new_limit;
    }
};

pub const StreamLimit = struct {
    limit: u64,
    opened: u64,
    advertised: u64,
    blocked_at: ?u64,

    pub fn init(limit: u64) StreamLimit {
        return .{
            .limit = limit,
            .opened = 0,
            .advertised = limit,
            .blocked_at = null,
        };
    }

    pub fn canOpen(self: *const StreamLimit) bool {
        return self.opened < self.limit;
    }

    pub fn onStreamOpened(self: *StreamLimit) Error.ZquicError!void {
        if (!self.canOpen()) {
            self.blocked_at = self.limit;
            return Error.ZquicError.StreamLimitError;
        }
        self.opened += 1;
        self.blocked_at = null;
    }

    pub fn updateLimit(self: *StreamLimit, new_limit: u64) Error.ZquicError!void {
        if (new_limit < self.limit) return Error.ZquicError.StreamLimitError;
        self.limit = new_limit;
        if (self.opened < self.limit) self.blocked_at = null;
    }

    pub fn shouldSendUpdate(self: *const StreamLimit) bool {
        return self.opened >= self.advertised / 2 and self.advertised == self.limit;
    }

    pub fn generateUpdate(self: *StreamLimit, increment: u64) u64 {
        const next = self.opened + increment;
        self.limit = @max(self.limit, next);
        self.advertised = self.limit;
        return self.limit;
    }
};

pub const PendingFlowControlFrame = union(enum) {
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsFrame,
    max_streams_uni: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked_bidi: StreamsBlockedFrame,
    streams_blocked_uni: StreamsBlockedFrame,

    pub fn toFrame(self: PendingFlowControlFrame) Frame {
        return switch (self) {
            .max_data => |frame| .{ .max_data = frame },
            .max_stream_data => |frame| .{ .max_stream_data = frame },
            .max_streams_bidi => |frame| .{ .max_streams_bidi = frame },
            .max_streams_uni => |frame| .{ .max_streams_uni = frame },
            .data_blocked => |frame| .{ .data_blocked = frame },
            .stream_data_blocked => |frame| .{ .stream_data_blocked = frame },
            .streams_blocked_bidi => |frame| .{ .streams_blocked_bidi = frame },
            .streams_blocked_uni => |frame| .{ .streams_blocked_uni = frame },
        };
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
    bidi_stream_limit: StreamLimit,
    uni_stream_limit: StreamLimit,
    stream_fc_map: std.ArrayListUnmanaged(StreamEntry),
    pending_frames: std.ArrayListUnmanaged(PendingFlowControlFrame),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, initial_max_data: u64, peer_max_data: u64) Self {
        return Self{
            .connection_fc = ConnectionFlowControl.init(initial_max_data, peer_max_data),
            .bidi_stream_limit = StreamLimit.init(100),
            .uni_stream_limit = StreamLimit.init(100),
            .stream_fc_map = .empty,
            .pending_frames = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.stream_fc_map.deinit(self.allocator);
        self.pending_frames.deinit(self.allocator);
    }

    /// Add flow control for a new stream
    pub fn addStream(self: *Self, stream_id: u64, initial_max_stream_data: u64, peer_max_stream_data: u64) Error.ZquicError!void {
        const is_bidi = (stream_id & 0x02) == 0;
        if (is_bidi) {
            try self.bidi_stream_limit.onStreamOpened();
        } else {
            try self.uni_stream_limit.onStreamOpened();
        }
        const stream_fc = StreamFlowControl.init(stream_id, initial_max_stream_data, peer_max_stream_data);
        try self.stream_fc_map.append(self.allocator, .{ .id = stream_id, .fc = stream_fc });
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
        self.connection_fc.consumeSendCredit(size) catch |err| {
            try self.pending_frames.append(self.allocator, .{
                .data_blocked = DataBlockedFrame.init(self.connection_fc.send_window.limit),
            });
            return err;
        };

        for (self.stream_fc_map.items) |*entry| {
            if (entry.id == stream_id) {
                entry.fc.consumeSendCredit(size) catch |err| {
                    // Rollback connection credit if stream credit failed
                    self.connection_fc.send_window.consumed -= size;
                    try self.pending_frames.append(self.allocator, .{
                        .stream_data_blocked = StreamDataBlockedFrame.init(stream_id, entry.fc.send_window.limit),
                    });
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
        var streams_needing_updates: std.ArrayListUnmanaged(u64) = .empty;

        for (self.stream_fc_map.items) |*entry| {
            if (entry.fc.shouldSendMaxStreamData()) {
                try streams_needing_updates.append(allocator, entry.id);
            }
        }

        return streams_needing_updates.toOwnedSlice(allocator);
    }

    pub fn updatePeerMaxStreams(self: *Self, bidirectional: bool, max_streams: u64) Error.ZquicError!void {
        if (bidirectional) {
            try self.bidi_stream_limit.updateLimit(max_streams);
        } else {
            try self.uni_stream_limit.updateLimit(max_streams);
        }
    }

    pub fn queueReceiveWindowUpdates(self: *Self) !void {
        if (self.connection_fc.shouldSendMaxData()) {
            try self.pending_frames.append(self.allocator, .{
                .max_data = MaxDataFrame.init(self.connection_fc.generateMaxData()),
            });
        }

        for (self.stream_fc_map.items) |*entry| {
            if (entry.fc.shouldSendMaxStreamData()) {
                try self.pending_frames.append(self.allocator, .{
                    .max_stream_data = MaxStreamDataFrame.init(entry.id, entry.fc.generateMaxStreamData()),
                });
            }
        }

        if (self.bidi_stream_limit.shouldSendUpdate()) {
            try self.pending_frames.append(self.allocator, .{
                .max_streams_bidi = MaxStreamsFrame.init(self.bidi_stream_limit.generateUpdate(100), true),
            });
        }
        if (self.uni_stream_limit.shouldSendUpdate()) {
            try self.pending_frames.append(self.allocator, .{
                .max_streams_uni = MaxStreamsFrame.init(self.uni_stream_limit.generateUpdate(100), false),
            });
        }
    }

    pub fn queueStreamsBlocked(self: *Self, bidirectional: bool) !void {
        const limit = if (bidirectional) self.bidi_stream_limit.limit else self.uni_stream_limit.limit;
        try self.pending_frames.append(self.allocator, if (bidirectional)
            .{ .streams_blocked_bidi = StreamsBlockedFrame.init(limit, true) }
        else
            .{ .streams_blocked_uni = StreamsBlockedFrame.init(limit, false) });
    }

    pub fn drainPendingFrames(self: *Self, allocator: std.mem.Allocator) ![]PendingFlowControlFrame {
        const frames = try self.pending_frames.toOwnedSlice(allocator);
        self.pending_frames = .empty;
        return frames;
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

test "flow controller emits blocked and max update frames" {
    var fc = FlowController.init(std.testing.allocator, 1000, 1000);
    defer fc.deinit();

    try fc.addStream(0, 500, 500);
    try std.testing.expectError(Error.ZquicError.FlowControlError, fc.consumeSendCredit(0, 501));

    const frames = try fc.drainPendingFrames(std.testing.allocator);
    defer std.testing.allocator.free(frames);
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expect(frames[0] == .stream_data_blocked);
    try std.testing.expectEqual(@as(u64, 0), frames[0].stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 500), frames[0].stream_data_blocked.maximum_stream_data);

    try fc.consumeRecvCredit(0, 300);
    try fc.queueReceiveWindowUpdates();
    const updates = try fc.drainPendingFrames(std.testing.allocator);
    defer std.testing.allocator.free(updates);
    try std.testing.expect(updates.len >= 1);
}

test "stream limits track max streams and blocked frames" {
    var fc = FlowController.init(std.testing.allocator, 1000, 1000);
    defer fc.deinit();
    fc.bidi_stream_limit = StreamLimit.init(1);

    try fc.addStream(0, 500, 500);
    try std.testing.expectError(Error.ZquicError.StreamLimitError, fc.addStream(4, 500, 500));
    try fc.queueStreamsBlocked(true);

    const frames = try fc.drainPendingFrames(std.testing.allocator);
    defer std.testing.allocator.free(frames);
    try std.testing.expect(frames.len >= 1);
    try std.testing.expect(frames[frames.len - 1] == .streams_blocked_bidi);
    try fc.updatePeerMaxStreams(true, 2);
    try fc.addStream(4, 500, 500);
}
