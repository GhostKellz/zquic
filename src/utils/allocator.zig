//! Memory allocation utilities for ZQUIC
//!
//! Provides deterministic memory management patterns suitable for
//! embedded systems and high-performance networking applications.

const std = @import("std");

/// A fixed-size pool allocator for predictable memory usage
pub const PoolAllocator = struct {
    pool: []u8,
    offset: usize,
    backing_allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(backing_allocator: std.mem.Allocator, size: usize) !Self {
        const pool = try backing_allocator.alloc(u8, size);
        return Self{
            .pool = pool,
            .offset = 0,
            .backing_allocator = backing_allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backing_allocator.free(self.pool);
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return std.mem.Allocator{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, n: usize, log2_ptr_align: u8, ra: usize) ?[*]u8 {
        _ = ra;
        const self: *Self = @ptrCast(@alignCast(ctx));
        const alignment = @as(usize, 1) << @intCast(log2_ptr_align);

        // Align the offset
        const aligned_offset = std.mem.alignForward(usize, self.offset, alignment);

        if (aligned_offset + n > self.pool.len) {
            return null; // Out of memory
        }

        self.offset = aligned_offset + n;
        return self.pool[aligned_offset..].ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, new_len: usize, ra: usize) bool {
        _ = ctx;
        _ = log2_buf_align;
        _ = ra;
        // Simple implementation: only allow shrinking
        return new_len <= buf.len;
    }

    fn free(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, ra: usize) void {
        _ = ctx;
        _ = buf;
        _ = log2_buf_align;
        _ = ra;
        // Pool allocator doesn't support individual free operations
    }

    pub fn reset(self: *Self) void {
        self.offset = 0;
    }
};

/// A ring buffer allocator for circular packet processing
pub const RingAllocator = struct {
    buffer: []u8,
    head: usize,
    tail: usize,
    backing_allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(backing_allocator: std.mem.Allocator, size: usize) !Self {
        const buffer = try backing_allocator.alloc(u8, size);
        return Self{
            .buffer = buffer,
            .head = 0,
            .tail = 0,
            .backing_allocator = backing_allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backing_allocator.free(self.buffer);
    }

    pub fn available(self: *const Self) usize {
        if (self.tail >= self.head) {
            return self.buffer.len - (self.tail - self.head) - 1;
        } else {
            return self.head - self.tail - 1;
        }
    }

    pub fn allocBytes(self: *Self, size: usize) ?[]u8 {
        if (size > self.available()) {
            return null;
        }

        const start = self.tail;
        self.tail = (self.tail + size) % self.buffer.len;

        // Handle wrap-around case
        if (start + size <= self.buffer.len) {
            return self.buffer[start .. start + size];
        } else {
            // Would need to handle wrap-around, which is complex
            // For simplicity, fail if we can't allocate contiguously
            self.tail = start; // Restore state
            return null;
        }
    }

    pub fn free(self: *Self, size: usize) void {
        self.head = (self.head + size) % self.buffer.len;
    }
};

test "pool allocator basic functionality" {
    var pool = try PoolAllocator.init(std.testing.allocator, 1024);
    defer pool.deinit();

    var allocator = pool.allocator();

    const slice1 = try allocator.alloc(u8, 100);
    try std.testing.expect(slice1.len == 100);

    const slice2 = try allocator.alloc(u32, 10);
    try std.testing.expect(slice2.len == 10);

    pool.reset();

    const slice3 = try allocator.alloc(u8, 50);
    try std.testing.expect(slice3.len == 50);
}

test "ring allocator basic functionality" {
    var ring = try RingAllocator.init(std.testing.allocator, 1024);
    defer ring.deinit();

    const available_before = ring.available();
    try std.testing.expect(available_before == 1023); // -1 for ring buffer sentinel

    const slice1 = ring.allocBytes(100);
    try std.testing.expect(slice1 != null);
    try std.testing.expect(slice1.?.len == 100);

    ring.free(50);

    const available_after = ring.available();
    try std.testing.expect(available_after > available_before - 100);
}
