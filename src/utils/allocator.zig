//! Memory Allocation Utilities for ZQUIC
//!
//! Provides deterministic memory management patterns suitable for
//! embedded systems and high-performance networking applications.
//!
//! ## Allocator Types
//!
//! | Type | Use Case | Lifetime |
//! |------|----------|----------|
//! | `ScopedArena` | Per-packet/request temp allocations | Single operation |
//! | `PoolAllocator` | Fixed-size buffer pools | Connection lifetime |
//! | `RingAllocator` | Circular packet buffers | Ongoing I/O |
//!
//! ## Usage Patterns
//!
//! ### Per-Packet Arena
//! ```zig
//! var arena = ScopedArena.init(backing_allocator, 64 * 1024);
//! defer arena.deinit();
//!
//! // All allocations freed at once when arena is reset/deinit
//! const packet_data = try arena.allocator().alloc(u8, packet_size);
//! processPacket(packet_data);
//! arena.reset(); // Ready for next packet
//! ```
//!
//! ### Connection Pool
//! ```zig
//! var pool = try PoolAllocator.init(allocator, 1024 * 1024); // 1MB pool
//! defer pool.deinit();
//!
//! // Fast bump allocations during connection lifetime
//! const buffer = try pool.allocator().alloc(u8, size);
//! ```

const std = @import("std");

// ============================================================================
// Scoped Arena Allocator
// ============================================================================

/// A scoped arena for temporary allocations within a single operation.
///
/// Ideal for per-packet, per-request, or per-frame allocations where
/// all memory can be freed at once when the operation completes.
///
/// ## Example: Per-Request Processing
/// ```zig
/// pub fn handleRequest(backing: std.mem.Allocator, request: *Request) !void {
///     var arena = ScopedArena.init(backing);
///     defer arena.deinit();
///
///     // All temp allocations use the arena
///     const headers = try parseHeaders(arena.allocator(), request.raw_headers);
///     const body = try decodeBody(arena.allocator(), request.raw_body);
///
///     // Process request...
///     // All memory freed automatically when arena goes out of scope
/// }
/// ```
pub const ScopedArena = struct {
    arena: std.heap.ArenaAllocator,
    stats: ArenaStats,

    const Self = @This();

    pub const ArenaStats = struct {
        allocations: u64 = 0,
        bytes_allocated: u64 = 0,
        resets: u64 = 0,
    };

    /// Initialize a new scoped arena.
    pub fn init(backing_allocator: std.mem.Allocator) Self {
        return Self{
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
            .stats = .{},
        };
    }

    /// Deinitialize the arena, freeing all memory.
    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    /// Get the arena's allocator interface.
    pub fn allocator(self: *Self) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Reset the arena, freeing all allocations but keeping capacity.
    /// Useful for reusing the arena across multiple operations.
    pub fn reset(self: *Self) void {
        _ = self.arena.reset(.retain_capacity);
        self.stats.resets += 1;
    }

    /// Reset and release all memory back to the backing allocator.
    pub fn resetAndFree(self: *Self) void {
        _ = self.arena.reset(.free_all);
        self.stats.resets += 1;
    }

    /// Allocate memory from the arena (convenience wrapper).
    pub fn alloc(self: *Self, comptime T: type, n: usize) ![]T {
        const result = try self.arena.allocator().alloc(T, n);
        self.stats.allocations += 1;
        self.stats.bytes_allocated += n * @sizeOf(T);
        return result;
    }

    /// Create a single item (convenience wrapper).
    pub fn create(self: *Self, comptime T: type) !*T {
        const result = try self.arena.allocator().create(T);
        self.stats.allocations += 1;
        self.stats.bytes_allocated += @sizeOf(T);
        return result;
    }

    /// Duplicate a slice (convenience wrapper).
    pub fn dupe(self: *Self, comptime T: type, s: []const T) ![]T {
        const result = try self.arena.allocator().dupe(T, s);
        self.stats.allocations += 1;
        self.stats.bytes_allocated += s.len * @sizeOf(T);
        return result;
    }

    /// Get arena statistics.
    pub fn getStats(self: *const Self) ArenaStats {
        return self.stats;
    }
};

/// Per-packet arena with fixed maximum size.
///
/// Optimized for packet processing where max packet size is known.
/// Fails fast if allocation would exceed limit.
pub const PacketArena = struct {
    arena: ScopedArena,
    max_size: usize,
    current_size: usize,

    const Self = @This();

    /// Standard QUIC max packet size (1472 bytes for safe MTU)
    pub const DEFAULT_MAX_SIZE = 1472;

    /// Large packet size for jumbo frames
    pub const JUMBO_MAX_SIZE = 9000;

    pub fn init(backing_allocator: std.mem.Allocator, max_size: usize) Self {
        return Self{
            .arena = ScopedArena.init(backing_allocator),
            .max_size = max_size,
            .current_size = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Allocate with size limit checking.
    pub fn allocChecked(self: *Self, comptime T: type, n: usize) ![]T {
        const size = n * @sizeOf(T);
        if (self.current_size + size > self.max_size) {
            return error.OutOfMemory;
        }
        const result = try self.arena.alloc(T, n);
        self.current_size += size;
        return result;
    }

    /// Reset for next packet.
    pub fn reset(self: *Self) void {
        self.arena.reset();
        self.current_size = 0;
    }

    /// Get remaining capacity.
    pub fn remaining(self: *const Self) usize {
        return self.max_size - self.current_size;
    }
};

// ============================================================================
// Pool Allocator
// ============================================================================

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

test "scoped arena basic functionality" {
    var arena = ScopedArena.init(std.testing.allocator);
    defer arena.deinit();

    // Allocate some memory
    const slice1 = try arena.alloc(u8, 100);
    try std.testing.expect(slice1.len == 100);

    const ptr = try arena.create(u32);
    ptr.* = 42;
    try std.testing.expect(ptr.* == 42);

    // Check stats
    const stats = arena.getStats();
    try std.testing.expect(stats.allocations == 2);
    try std.testing.expect(stats.bytes_allocated == 100 + @sizeOf(u32));

    // Reset and reuse
    arena.reset();
    try std.testing.expect(arena.getStats().resets == 1);

    const slice2 = try arena.alloc(u8, 50);
    try std.testing.expect(slice2.len == 50);
}

test "packet arena size limiting" {
    var packet_arena = PacketArena.init(std.testing.allocator, 256);
    defer packet_arena.deinit();

    // Should succeed - within limit
    const slice1 = try packet_arena.allocChecked(u8, 100);
    try std.testing.expect(slice1.len == 100);
    try std.testing.expect(packet_arena.remaining() == 156);

    // Should succeed - still within limit
    const slice2 = try packet_arena.allocChecked(u8, 100);
    try std.testing.expect(slice2.len == 100);
    try std.testing.expect(packet_arena.remaining() == 56);

    // Should fail - would exceed limit
    const result = packet_arena.allocChecked(u8, 100);
    try std.testing.expect(result == error.OutOfMemory);

    // Reset and try again
    packet_arena.reset();
    try std.testing.expect(packet_arena.remaining() == 256);

    const slice3 = try packet_arena.allocChecked(u8, 200);
    try std.testing.expect(slice3.len == 200);
}
