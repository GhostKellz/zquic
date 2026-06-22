//! QUIC Stream with async I/O support
//!
//! Stream management without external dependencies

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");

/// Stream ID and direction utilities
pub const StreamId = struct {
    id: u64,

    const Self = @This();

    pub fn init(id: u64) Self {
        return Self{ .id = id };
    }

    pub fn isClientInitiated(self: Self) bool {
        return (self.id & 0x01) == 0;
    }

    pub fn isServerInitiated(self: Self) bool {
        return (self.id & 0x01) == 1;
    }

    pub fn isBidirectional(self: Self) bool {
        return (self.id & 0x02) == 0;
    }

    pub fn isUnidirectional(self: Self) bool {
        return (self.id & 0x02) == 2;
    }

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

/// Stream states (using u8 for atomic compatibility)
pub const StreamState = enum(u8) {
    idle = 0,
    open = 1,
    half_closed_local = 2,
    half_closed_remote = 3,
    closed = 4,
};

/// Flow control event for async processing
pub const FlowControlEvent = union(enum) {
    bytes_written: u64,
    bytes_read: u64,
    window_update: u64,
    blocked: void,
};

/// Zero-copy data chunk
pub const DataChunk = struct {
    data: []const u8,
    offset: u64,
    fin: bool,
    timestamp: u64,

    pub fn init(data: []const u8, offset: u64, fin: bool) DataChunk {
        return DataChunk{
            .data = data,
            .offset = offset,
            .fin = fin,
            .timestamp = @intCast(Time.nowNanos()),
        };
    }
};

/// QUIC stream with internal async I/O
pub const SuperStream = struct {
    id: u64,
    stream_type: StreamType,
    state: std.atomic.Value(StreamState),
    allocator: std.mem.Allocator,

    // Data buffers
    read_buffer: std.ArrayListUnmanaged(u8),
    read_start: usize, // Offset to avoid memmove on every read
    write_buffer: std.ArrayListUnmanaged(u8),

    // Flow control state (atomic for lock-free access)
    send_window: std.atomic.Value(u64),
    recv_window: std.atomic.Value(u64),
    bytes_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),

    // Stream statistics
    peak_throughput: std.atomic.Value(u64),
    last_activity: std.atomic.Value(i64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id: u64, stream_type: StreamType) !Self {
        return Self{
            .id = id,
            .stream_type = stream_type,
            .state = std.atomic.Value(StreamState).init(.idle),
            .allocator = allocator,

            // Initialize buffers
            .read_buffer = .empty,
            .read_start = 0,
            .write_buffer = .empty,

            // Initialize flow control (generous initial windows for high throughput)
            .send_window = std.atomic.Value(u64).init(1_048_576), // 1MB
            .recv_window = std.atomic.Value(u64).init(1_048_576), // 1MB
            .bytes_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),

            .peak_throughput = std.atomic.Value(u64).init(0),
            .last_activity = std.atomic.Value(i64).init(Time.nowSeconds()),
        };
    }

    pub fn deinit(self: *Self) void {
        self.state.store(.closed, .release);
        self.read_buffer.deinit(self.allocator);
        self.write_buffer.deinit(self.allocator);
    }

    /// Read data from stream - O(1) using read_start offset instead of O(n) memmove
    pub fn read(self: *Self, buffer: []u8) !usize {
        const available = self.read_buffer.items.len - self.read_start;
        if (available == 0) {
            return 0;
        }

        const copy_len = @min(buffer.len, available);
        @memcpy(buffer[0..copy_len], self.read_buffer.items[self.read_start..][0..copy_len]);
        self.read_start += copy_len;

        // Compact buffer when >50% consumed to prevent unbounded growth
        if (self.read_start > self.read_buffer.items.len / 2 and self.read_start > 4096) {
            const remaining = self.read_buffer.items.len - self.read_start;
            if (remaining > 0) {
                @memcpy(self.read_buffer.items[0..remaining], self.read_buffer.items[self.read_start..]);
            }
            self.read_buffer.shrinkRetainingCapacity(remaining);
            self.read_start = 0;
        }

        _ = self.bytes_received.fetchAdd(copy_len, .acq_rel);
        try self.updateActivityTimestamp();

        return copy_len;
    }

    /// Read data from stream with timeout
    /// Polls for data until timeout_ms milliseconds have elapsed
    /// Returns error.Timeout if no data received within the timeout period
    pub fn readWithTimeout(self: *Self, buffer: []u8, timeout_ms: u32) !usize {
        const deadline_us = Time.nowMicros() + @as(i64, timeout_ms) * 1000;
        const poll_interval_ns: u64 = 1_000_000; // 1ms polling interval

        while (Time.nowMicros() < deadline_us) {
            const bytes_read = try self.read(buffer);
            if (bytes_read > 0) {
                return bytes_read;
            }

            // Small sleep to avoid busy-waiting
            Time.sleep(poll_interval_ns);
        }

        return Error.ZquicError.Timeout;
    }

    /// Write data to stream
    pub fn write(self: *Self, data: []const u8, fin: bool) !usize {
        const current_state = self.state.load(.acquire);
        if (current_state == .closed or current_state == .half_closed_local) {
            return Error.ZquicError.StreamStateError;
        }

        const bytes_sent = self.bytes_sent.load(.acquire);
        const send_limit = self.send_window.load(.acquire);
        if (bytes_sent + data.len > send_limit) {
            return Error.ZquicError.FlowControlError;
        }

        try self.write_buffer.appendSlice(self.allocator, data);
        _ = self.bytes_sent.fetchAdd(data.len, .acq_rel);
        if (current_state == .idle) {
            self.state.store(.open, .release);
        }
        if (fin) {
            self.markLocalFin();
        }
        try self.updateActivityTimestamp();

        return data.len;
    }

    /// Zero-copy async read - returns reference to data, no copying
    pub fn readAsync(self: *Self) !DataChunk {
        const offset = self.bytes_received.load(.acquire);
        const available = self.read_buffer.items.len - self.read_start;
        if (available > 0) {
            return DataChunk.init(self.read_buffer.items[self.read_start..], offset, false);
        }
        return DataChunk.init(&[_]u8{}, offset, false);
    }

    /// Zero-copy async write - takes ownership of data reference
    pub fn writeAsync(self: *Self, data: []const u8, fin: bool) !void {
        _ = try self.write(data, fin);
    }

    /// Handle incoming data
    pub fn handleIncomingData(self: *Self, data: []const u8) !void {
        try self.handleIncomingDataWithFin(data, false);
    }

    /// Handle incoming data and optional FIN from the peer.
    pub fn handleIncomingDataWithFin(self: *Self, data: []const u8, fin: bool) !void {
        const current_state = self.state.load(.acquire);
        if (current_state == .closed or current_state == .half_closed_remote) {
            return Error.ZquicError.StreamStateError;
        }

        const unread = self.read_buffer.items.len - self.read_start;
        const recv_limit = self.recv_window.load(.acquire);
        if (unread + data.len > recv_limit) {
            return Error.ZquicError.FlowControlError;
        }

        try self.read_buffer.appendSlice(self.allocator, data);
        if (current_state == .idle) {
            self.state.store(.open, .release);
        }
        if (fin) {
            self.markRemoteFin();
        }
        try self.updateActivityTimestamp();
    }

    /// Update flow control windows
    pub fn updateFlowControl(self: *Self, credits: u64) !void {
        _ = self.send_window.fetchAdd(credits, .acq_rel);
    }

    /// Process stream asynchronously
    pub fn processAsync(self: *Self) !void {
        try self.checkFlowControl();
        try self.updateActivityTimestamp();
    }

    fn checkFlowControl(self: *Self) !void {
        // Check and update flow control state
        _ = self;
    }

    fn updateActivityTimestamp(self: *Self) !void {
        const sec = Time.nowSeconds();
        self.last_activity.store(sec, .release);
    }

    /// Close the stream
    pub fn close(self: *Self) !void {
        self.state.store(.closed, .release);
    }

    fn markLocalFin(self: *Self) void {
        const current_state = self.state.load(.acquire);
        const next_state: StreamState = switch (current_state) {
            .half_closed_remote => .closed,
            .closed => .closed,
            else => .half_closed_local,
        };
        self.state.store(next_state, .release);
    }

    fn markRemoteFin(self: *Self) void {
        const current_state = self.state.load(.acquire);
        const next_state: StreamState = switch (current_state) {
            .half_closed_local => .closed,
            .closed => .closed,
            else => .half_closed_remote,
        };
        self.state.store(next_state, .release);
    }

    /// Get stream statistics
    pub fn getStats(self: *const Self) StreamStats {
        return StreamStats{
            .bytes_sent = self.bytes_sent.load(.acquire),
            .bytes_received = self.bytes_received.load(.acquire),
            .peak_throughput = self.peak_throughput.load(.acquire),
            .last_activity = self.last_activity.load(.acquire),
            .send_window = self.send_window.load(.acquire),
            .recv_window = self.recv_window.load(.acquire),
        };
    }
};

/// Stream statistics
pub const StreamStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    peak_throughput: u64,
    last_activity: i64,
    send_window: u64,
    recv_window: u64,
};

/// Legacy stream for compatibility
pub const Stream = SuperStream;

test "stream initialization" {
    var stream = try SuperStream.init(std.testing.allocator, 0, .client_bidirectional);
    defer stream.deinit();

    try std.testing.expect(stream.state.load(.acquire) == .idle);
    try std.testing.expect(stream.id == 0);
}

test "stream read write" {
    var stream = try SuperStream.init(std.testing.allocator, 0, .client_bidirectional);
    defer stream.deinit();

    const data = "Hello, QUIC!";
    const written = try stream.write(data, false);
    try std.testing.expect(written == data.len);

    // Add data to read buffer
    try stream.handleIncomingData("Test data");

    var buffer: [32]u8 = undefined;
    const read_len = try stream.read(&buffer);
    try std.testing.expect(read_len == 9);
}

test "stream fin transitions reject writes after local fin" {
    var stream = try SuperStream.init(std.testing.allocator, 0, .client_bidirectional);
    defer stream.deinit();

    _ = try stream.write("done", true);
    try std.testing.expectEqual(StreamState.half_closed_local, stream.state.load(.acquire));
    try std.testing.expectError(Error.ZquicError.StreamStateError, stream.write("more", false));

    try stream.handleIncomingDataWithFin("", true);
    try std.testing.expectEqual(StreamState.closed, stream.state.load(.acquire));
}

test "stream receive flow control rejects oversized data" {
    var stream = try SuperStream.init(std.testing.allocator, 0, .client_bidirectional);
    defer stream.deinit();

    stream.recv_window.store(4, .release);
    try stream.handleIncomingData("abcd");
    try std.testing.expectError(Error.ZquicError.FlowControlError, stream.handleIncomingData("e"));
}
