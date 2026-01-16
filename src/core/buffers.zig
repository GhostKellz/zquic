//! QUIC Buffer Management Module
//!
//! Provides high-performance ring buffers and specialized buffer types
//! for QUIC protocol operations. All buffers use explicit allocator
//! management and provide clear ownership semantics.
//!
//! Features:
//! - RingBuffer: Circular buffer for stream data
//! - PacketBuffer: Fixed-size buffer for packet assembly
//! - SendBuffer: Ordered buffer for reliable transmission
//! - RecvBuffer: Out-of-order assembly buffer
//! - Explicit lifecycle management with deinit methods

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Buffer management errors
pub const BufferError = error{
    /// Buffer is full and cannot accept more data
    BufferFull,
    /// Buffer is empty and has no data to read
    BufferEmpty,
    /// Invalid offset or length provided
    InvalidRange,
    /// Attempting to write beyond buffer capacity
    OutOfBounds,
    /// Buffer has been closed for writing
    BufferClosed,
    /// Data already exists at this offset
    DataExists,
} || std.mem.Allocator.Error;

/// High-performance ring buffer for streaming data
pub const RingBuffer = struct {
    data: []u8,
    head: usize,
    tail: usize,
    capacity: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ring buffer with given capacity
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
        const data = try allocator.alloc(u8, capacity);
        return Self{
            .data = data,
            .head = 0,
            .tail = 0,
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    /// Clean up ring buffer
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }

    /// Get current number of bytes in buffer
    pub fn len(self: *const Self) usize {
        if (self.tail >= self.head) {
            return self.tail - self.head;
        } else {
            return self.capacity - self.head + self.tail;
        }
    }

    /// Check if buffer is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.head == self.tail;
    }

    /// Check if buffer is full
    pub fn isFull(self: *const Self) bool {
        return self.len() == self.capacity - 1; // Leave one slot empty to distinguish full from empty
    }

    /// Get available space for writing
    pub fn availableSpace(self: *const Self) usize {
        return self.capacity - 1 - self.len();
    }

    /// Write data to ring buffer
    pub fn write(self: *Self, data: []const u8) BufferError!usize {
        if (data.len == 0) return 0;

        const available = self.availableSpace();
        const to_write = @min(data.len, available);
        if (to_write == 0) return BufferError.BufferFull;

        // Handle wrap-around
        if (self.tail + to_write <= self.capacity) {
            // No wrap-around needed
            @memcpy(self.data[self.tail .. self.tail + to_write], data[0..to_write]);
            self.tail = (self.tail + to_write) % self.capacity;
        } else {
            // Handle wrap-around
            const first_chunk = self.capacity - self.tail;
            @memcpy(self.data[self.tail..], data[0..first_chunk]);
            @memcpy(self.data[0 .. to_write - first_chunk], data[first_chunk..to_write]);
            self.tail = to_write - first_chunk;
        }

        return to_write;
    }

    /// Read data from ring buffer
    pub fn read(self: *Self, buffer: []u8) BufferError!usize {
        if (buffer.len == 0) return 0;

        const available = self.len();
        const to_read = @min(buffer.len, available);
        if (to_read == 0) return BufferError.BufferEmpty;

        // Handle wrap-around
        if (self.head + to_read <= self.capacity) {
            // No wrap-around needed
            @memcpy(buffer[0..to_read], self.data[self.head .. self.head + to_read]);
            self.head = (self.head + to_read) % self.capacity;
        } else {
            // Handle wrap-around
            const first_chunk = self.capacity - self.head;
            @memcpy(buffer[0..first_chunk], self.data[self.head..]);
            @memcpy(buffer[first_chunk..to_read], self.data[0 .. to_read - first_chunk]);
            self.head = to_read - first_chunk;
        }

        return to_read;
    }

    /// Peek at data without consuming it
    pub fn peek(self: *const Self, buffer: []u8) BufferError!usize {
        if (buffer.len == 0) return 0;

        const available = self.len();
        const to_peek = @min(buffer.len, available);
        if (to_peek == 0) return BufferError.BufferEmpty;

        // Handle wrap-around for peeking
        if (self.head + to_peek <= self.capacity) {
            @memcpy(buffer[0..to_peek], self.data[self.head .. self.head + to_peek]);
        } else {
            const first_chunk = self.capacity - self.head;
            @memcpy(buffer[0..first_chunk], self.data[self.head..]);
            @memcpy(buffer[first_chunk..to_peek], self.data[0 .. to_peek - first_chunk]);
        }

        return to_peek;
    }

    /// Skip bytes without reading them
    pub fn skip(self: *Self, bytes: usize) BufferError!usize {
        const available = self.len();
        const to_skip = @min(bytes, available);
        if (to_skip == 0) return BufferError.BufferEmpty;

        self.head = (self.head + to_skip) % self.capacity;
        return to_skip;
    }

    /// Clear all data from buffer
    pub fn clear(self: *Self) void {
        self.head = 0;
        self.tail = 0;
    }
};

/// Fixed-size packet buffer for QUIC packet assembly
pub const PacketBuffer = struct {
    data: []u8,
    len: usize,
    capacity: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Standard QUIC packet size (safe for most networks)
    pub const DEFAULT_PACKET_SIZE: usize = 1200;

    /// Maximum QUIC packet size
    pub const MAX_PACKET_SIZE: usize = 65535;

    /// Initialize packet buffer with default size
    pub fn init(allocator: std.mem.Allocator) !Self {
        return initWithCapacity(allocator, DEFAULT_PACKET_SIZE);
    }

    /// Initialize packet buffer with specific capacity
    pub fn initWithCapacity(allocator: std.mem.Allocator, capacity: usize) !Self {
        const data = try allocator.alloc(u8, capacity);
        return Self{
            .data = data,
            .len = 0,
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    /// Clean up packet buffer
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }

    /// Get current length of data in buffer
    pub fn length(self: *const Self) usize {
        return self.len;
    }

    /// Check if buffer is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.len == 0;
    }

    /// Check if buffer is full
    pub fn isFull(self: *const Self) bool {
        return self.len == self.capacity;
    }

    /// Get available space for writing
    pub fn availableSpace(self: *const Self) usize {
        return self.capacity - self.len;
    }

    /// Append data to packet buffer
    pub fn append(self: *Self, data: []const u8) BufferError!void {
        if (self.len + data.len > self.capacity) return BufferError.BufferFull;

        @memcpy(self.data[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    /// Write data at specific offset
    pub fn writeAt(self: *Self, offset: usize, data: []const u8) BufferError!void {
        if (offset + data.len > self.capacity) return BufferError.OutOfBounds;

        @memcpy(self.data[offset .. offset + data.len], data);
        self.len = @max(self.len, offset + data.len);
    }

    /// Get slice of current data
    pub fn slice(self: *const Self) []const u8 {
        return self.data[0..self.len];
    }

    /// Get mutable slice of current data
    pub fn sliceMut(self: *Self) []u8 {
        return self.data[0..self.len];
    }

    /// Reset buffer to empty state
    pub fn reset(self: *Self) void {
        self.len = 0;
    }

    /// Resize buffer content (truncate or extend with zeros)
    pub fn resize(self: *Self, new_len: usize) BufferError!void {
        if (new_len > self.capacity) return BufferError.OutOfBounds;

        if (new_len > self.len) {
            // Zero out new bytes
            @memset(self.data[self.len..new_len], 0);
        }
        self.len = new_len;
    }
};

/// Ordered send buffer for reliable transmission
pub const SendBuffer = struct {
    /// Data segment with offset and payload
    const Segment = struct {
        offset: u64,
        data: []u8,
        acked: bool,
    };

    segments: std.ArrayListUnmanaged(Segment),
    next_offset: u64,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize send buffer
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .segments = .{},
            .next_offset = 0,
            .allocator = allocator,
        };
    }

    /// Clean up send buffer
    pub fn deinit(self: *Self) void {
        for (self.segments.items) |segment| {
            self.allocator.free(segment.data);
        }
        self.segments.deinit(self.allocator);
    }

    /// Add data to send buffer
    pub fn append(self: *Self, data: []const u8) BufferError!u64 {
        const owned_data = try self.allocator.dupe(u8, data);
        const segment = Segment{
            .offset = self.next_offset,
            .data = owned_data,
            .acked = false,
        };

        try self.segments.append(self.allocator, segment);
        const offset = self.next_offset;
        self.next_offset += data.len;
        return offset;
    }

    /// Mark data as acknowledged
    pub fn ack(self: *Self, offset: u64, length: u64) void {
        for (self.segments.items) |*segment| {
            if (segment.offset >= offset and segment.offset + segment.data.len <= offset + length) {
                segment.acked = true;
            }
        }
    }

    /// Get unacknowledged segments for retransmission
    pub fn getUnacked(self: *Self, allocator: std.mem.Allocator) ![]Segment {
        var unacked: std.ArrayListUnmanaged(Segment) = .{};
        defer unacked.deinit(allocator);

        for (self.segments.items) |segment| {
            if (!segment.acked) {
                try unacked.append(allocator, segment);
            }
        }

        return unacked.toOwnedSlice(allocator);
    }

    /// Remove acknowledged segments to free memory - O(n) instead of O(n²)
    pub fn compact(self: *Self) BufferError!void {
        // Two-pointer compaction: keep unacked segments, free acked ones
        var write_idx: usize = 0;
        for (self.segments.items) |segment| {
            if (segment.acked) {
                // Free the acked segment's data
                self.allocator.free(segment.data);
            } else {
                // Keep unacked segment - move to write position
                self.segments.items[write_idx] = segment;
                write_idx += 1;
            }
        }
        // Shrink to only contain unacked segments
        self.segments.shrinkRetainingCapacity(write_idx);
    }

    /// Get total bytes in buffer
    pub fn totalBytes(self: *const Self) u64 {
        return self.next_offset;
    }

    /// Get number of unacknowledged bytes
    pub fn unackedBytes(self: *const Self) u64 {
        var count: u64 = 0;
        for (self.segments.items) |segment| {
            if (!segment.acked) {
                count += segment.data.len;
            }
        }
        return count;
    }
};

/// Out-of-order receive buffer for stream reassembly
pub const RecvBuffer = struct {
    /// Data chunk with offset and payload
    const Chunk = struct {
        offset: u64,
        data: []u8,
    };

    chunks: std.ArrayListUnmanaged(Chunk),
    next_expected: u64,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize receive buffer
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .chunks = .{},
            .next_expected = 0,
            .allocator = allocator,
        };
    }

    /// Clean up receive buffer
    pub fn deinit(self: *Self) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk.data);
        }
        self.chunks.deinit(self.allocator);
    }

    /// Add data chunk at specific offset
    pub fn insert(self: *Self, offset: u64, data: []const u8) BufferError!void {
        // Check for overlapping data
        for (self.chunks.items) |chunk| {
            if (offset < chunk.offset + chunk.data.len and offset + data.len > chunk.offset) {
                return BufferError.DataExists; // Overlapping data
            }
        }

        const owned_data = try self.allocator.dupe(u8, data);
        const chunk = Chunk{
            .offset = offset,
            .data = owned_data,
        };

        // Insert in sorted order by offset
        var insert_pos: usize = 0;
        for (self.chunks.items, 0..) |existing_chunk, i| {
            if (offset < existing_chunk.offset) {
                insert_pos = i;
                break;
            }
            insert_pos = i + 1;
        }

        try self.chunks.insert(self.allocator, insert_pos, chunk);
    }

    /// Read contiguous data from buffer
    pub fn read(self: *Self, buffer: []u8) BufferError!usize {
        if (self.chunks.items.len == 0) return BufferError.BufferEmpty;

        var bytes_read: usize = 0;
        var current_offset = self.next_expected;

        var i: usize = 0;
        while (i < self.chunks.items.len and bytes_read < buffer.len) {
            const chunk = &self.chunks.items[i];

            if (chunk.offset > current_offset) {
                // Gap in data - cannot read further
                break;
            }

            if (chunk.offset + chunk.data.len <= current_offset) {
                // This chunk is entirely before our current position
                i += 1;
                continue;
            }

            // Calculate how much to read from this chunk
            const chunk_start = if (chunk.offset < current_offset)
                current_offset - chunk.offset
            else
                0;
            const available_in_chunk = chunk.data.len - chunk_start;
            const space_in_buffer = buffer.len - bytes_read;
            const to_read = @min(available_in_chunk, space_in_buffer);

            @memcpy(buffer[bytes_read .. bytes_read + to_read], chunk.data[chunk_start .. chunk_start + to_read]);

            bytes_read += to_read;
            current_offset += to_read;

            if (chunk_start + to_read >= chunk.data.len) {
                // Consumed entire chunk
                i += 1;
            } else {
                // Partial chunk read - done for now
                break;
            }
        }

        self.next_expected = current_offset;

        // Remove fully consumed chunks
        var remove_count: usize = 0;
        for (self.chunks.items) |chunk| {
            if (chunk.offset + chunk.data.len <= self.next_expected) {
                self.allocator.free(chunk.data);
                remove_count += 1;
            } else {
                break;
            }
        }

        if (remove_count > 0) {
            std.mem.copyForwards(Chunk, self.chunks.items[0..], self.chunks.items[remove_count..]);
            self.chunks.shrinkRetainingCapacity(self.chunks.items.len - remove_count);
        }

        return bytes_read;
    }

    /// Check if data is available for reading
    pub fn hasContiguousData(self: *const Self) bool {
        if (self.chunks.items.len == 0) return false;
        return self.chunks.items[0].offset <= self.next_expected;
    }

    /// Get next expected offset
    pub fn nextExpected(self: *const Self) u64 {
        return self.next_expected;
    }

    /// Get total buffered bytes
    pub fn bufferedBytes(self: *const Self) u64 {
        var total: u64 = 0;
        for (self.chunks.items) |chunk| {
            total += chunk.data.len;
        }
        return total;
    }
};

// Tests
test "ring buffer operations" {
    const allocator = std.testing.allocator;

    var ring = try RingBuffer.init(allocator, 10);
    defer ring.deinit();

    // Test basic write/read
    const written = try ring.write("hello");
    try std.testing.expectEqual(@as(usize, 5), written);
    try std.testing.expectEqual(@as(usize, 5), ring.len());

    var buffer: [10]u8 = undefined;
    const read = try ring.read(&buffer);
    try std.testing.expectEqual(@as(usize, 5), read);
    try std.testing.expectEqualStrings("hello", buffer[0..read]);
}

test "packet buffer operations" {
    const allocator = std.testing.allocator;

    var packet = try PacketBuffer.init(allocator);
    defer packet.deinit();

    try packet.append("test data");
    try std.testing.expectEqual(@as(usize, 9), packet.length());
    try std.testing.expectEqualStrings("test data", packet.slice());

    packet.reset();
    try std.testing.expectEqual(@as(usize, 0), packet.length());
    try std.testing.expect(packet.isEmpty());
}

test "send buffer operations" {
    const allocator = std.testing.allocator;

    var send_buf = SendBuffer.init(allocator);
    defer send_buf.deinit();

    const offset = try send_buf.append("hello");
    try std.testing.expectEqual(@as(u64, 0), offset);
    try std.testing.expectEqual(@as(u64, 5), send_buf.totalBytes());

    send_buf.ack(0, 5);
    try std.testing.expectEqual(@as(u64, 0), send_buf.unackedBytes());
}

test "receive buffer out-of-order assembly" {
    const allocator = std.testing.allocator;

    var recv_buf = RecvBuffer.init(allocator);
    defer recv_buf.deinit();

    // Insert data out of order
    try recv_buf.insert(5, "world");
    try recv_buf.insert(0, "hello");

    var buffer: [20]u8 = undefined;
    const read = try recv_buf.read(&buffer);
    try std.testing.expectEqual(@as(usize, 10), read);
    try std.testing.expectEqualStrings("helloworld", buffer[0..read]);
}
