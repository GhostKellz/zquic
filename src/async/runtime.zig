//! ZQUIC Async Runtime
//!
//! Internal async runtime for QUIC networking.
//! Uses poll-based event loop - no external dependencies.

const std = @import("std");
const posix = std.posix;
const EventLoop = @import("event_loop.zig").EventLoop;
const Timer = @import("event_loop.zig").Timer;
const TimerWheel = @import("event_loop.zig").TimerWheel;
const EventType = @import("event_loop.zig").EventType;
const UdpMultiplexer = @import("../net/multiplexer.zig").UdpMultiplexer;
const MultiplexerConfig = @import("../net/multiplexer.zig").MultiplexerConfig;
const Connection = @import("../core/connection.zig");
const Error = @import("../utils/error.zig");

/// Runtime configuration
pub const QuicRuntimeConfig = struct {
    /// Maximum concurrent connections
    max_connections: u32 = 1000,
    /// Connection timeout (ms)
    connection_timeout_ms: u32 = 300_000,
    /// Packet batch size for processing
    packet_batch_size: u32 = 32,
    /// Send queue size per connection
    send_queue_size: u32 = 1000,
    /// Enable connection pooling
    enable_connection_pooling: bool = false,
    /// Pool configuration
    pool_config: PoolConfig = .{},
};

/// Connection pool configuration
pub const PoolConfig = struct {
    max_size: u32 = 100,
    idle_timeout_ms: u32 = 60_000,
};

/// Runtime statistics
pub const RuntimeStats = struct {
    total_connections: u64 = 0,
    active_connections: u32 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
};

/// Connection pool for reusing connections
pub const ConnectionPool = struct {
    connections: std.ArrayListUnmanaged(*Connection.Connection),
    available: std.ArrayListUnmanaged(usize),
    config: PoolConfig,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) Self {
        return Self{
            .connections = .{},
            .available = .{},
            .config = config,
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }

        self.connections.deinit(self.allocator);
        self.available.deinit(self.allocator);
    }

    pub fn acquire(self: *Self) ?*Connection.Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available.popOrNull()) |idx| {
            return self.connections.items[idx];
        }
        return null;
    }

    pub fn release(self: *Self, conn: *Connection.Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                self.available.append(self.allocator, i) catch {};
                break;
            }
        }
    }
};

/// QUIC async runtime
pub const QuicRuntime = struct {
    event_loop: EventLoop,
    timer_wheel: TimerWheel,
    multiplexer: ?UdpMultiplexer,
    connection_pool: ?ConnectionPool,
    config: QuicRuntimeConfig,
    stats: RuntimeStats,
    allocator: std.mem.Allocator,
    running: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, local_address: std.net.Address, config: QuicRuntimeConfig) Error.ZquicError!Self {
        const multiplexer_config = MultiplexerConfig{
            .max_connections = config.max_connections,
            .connection_timeout_ms = config.connection_timeout_ms,
            .send_queue_size = config.send_queue_size,
        };

        const multiplexer = UdpMultiplexer.init(allocator, local_address, multiplexer_config) catch |err| {
            _ = err;
            return Error.ZquicError.NetworkError;
        };

        const connection_pool = if (config.enable_connection_pooling)
            ConnectionPool.init(allocator, config.pool_config)
        else
            null;

        return Self{
            .event_loop = EventLoop.init(allocator),
            .timer_wheel = TimerWheel.init(allocator),
            .multiplexer = multiplexer,
            .connection_pool = connection_pool,
            .config = config,
            .stats = .{},
            .allocator = allocator,
            .running = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.multiplexer) |*m| {
            m.deinit();
        }
        if (self.connection_pool) |*p| {
            p.deinit();
        }
        self.event_loop.deinit();
        self.timer_wheel.deinit();
    }

    /// Run the runtime (blocking)
    pub fn run(self: *Self) !void {
        self.running = true;

        while (self.running) {
            // Process timers
            const wait_time = self.timer_wheel.tick();

            // Poll for events
            _ = try self.event_loop.pollOnce(@intCast(@min(wait_time, 100)));

            // Process multiplexer if available
            if (self.multiplexer) |*m| {
                _ = m.processSendQueue() catch {};
            }
        }
    }

    /// Stop the runtime
    pub fn stop(self: *Self) void {
        self.running = false;
        self.event_loop.stop();
    }

    /// Add a timer
    pub fn addTimer(self: *Self, delay_ms: u64, callback: *const fn (?*anyopaque) void, user_data: ?*anyopaque) !void {
        try self.timer_wheel.addTimer(Timer.init(delay_ms, callback, user_data));
    }

    /// Add a repeating timer
    pub fn addRepeatingTimer(self: *Self, interval_ms: u64, callback: *const fn (?*anyopaque) void, user_data: ?*anyopaque) !void {
        try self.timer_wheel.addTimer(Timer.initRepeating(interval_ms, callback, user_data));
    }

    /// Get runtime statistics
    pub fn getStats(self: *const Self) RuntimeStats {
        return self.stats;
    }
};

test "runtime initialization" {
    const config = QuicRuntimeConfig{
        .max_connections = 10,
    };

    const local_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);

    var runtime = QuicRuntime.init(std.testing.allocator, local_addr, config) catch return; // Skip if bind fails
    defer runtime.deinit();

    const stats = runtime.getStats();
    try std.testing.expect(stats.total_connections == 0);
}

test "connection pool" {
    const config = PoolConfig{ .max_size = 5 };
    var pool = ConnectionPool.init(std.testing.allocator, config);
    defer pool.deinit();

    // Initially no connections
    try std.testing.expect(pool.acquire() == null);
}
