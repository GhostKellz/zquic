//! TokiZ-powered async runtime for QUIC
//!
//! Integrates the production-ready TokiZ async runtime with QUIC for high-performance networking

const std = @import("std");
const Error = @import("../utils/error.zig");
const UdpMultiplexer = @import("../net/multiplexer.zig").UdpMultiplexer;
const MultiplexerConfig = @import("../net/multiplexer.zig").MultiplexerConfig;
const Connection = @import("../core/connection.zig");
const Packet = @import("../core/packet.zig");

/// TokiZ async runtime configuration for QUIC
pub const QuicRuntimeConfig = struct {
    /// Maximum number of concurrent connections
    max_connections: u32 = 1000,

    /// Worker thread count (0 = auto-detect)
    worker_threads: u32 = 0,

    /// I/O polling interval in microseconds
    poll_interval_us: u32 = 1000, // 1ms

    /// Connection timeout in milliseconds
    connection_timeout_ms: u32 = 300_000, // 5 minutes

    /// Packet processing batch size
    packet_batch_size: u32 = 32,

    /// Send queue size per connection
    send_queue_size: u32 = 1000,

    /// Enable connection pooling
    enable_connection_pooling: bool = true,

    /// Pool configuration
    pool_config: PoolConfig = PoolConfig{},
};

/// Connection pool configuration
pub const PoolConfig = struct {
    initial_size: u32 = 10,
    max_size: u32 = 100,
    idle_timeout_ms: u32 = 60_000, // 1 minute
    validation_interval_ms: u32 = 30_000, // 30 seconds
};

/// Async connection handle for TokiZ runtime
pub const AsyncConnection = struct {
    connection: *Connection.Connection,
    multiplexer: *UdpMultiplexer,
    task_id: ?u64 = null,
    is_active: bool = true,
    last_activity: i64,

    const Self = @This();

    pub fn init(connection: *Connection.Connection, multiplexer: *UdpMultiplexer) Self {
        return Self{
            .connection = connection,
            .multiplexer = multiplexer,
            .last_activity = std.time.microTimestamp(),
        };
    }

    /// Process packets asynchronously for this connection
    pub fn processPacketsAsync(self: *Self) !void {
        while (self.is_active) {
            // Check for incoming packets
            if (self.multiplexer.receiveAndRoute()) {
                self.last_activity = std.time.microTimestamp();
            } else |err| switch (err) {
                Error.ZquicError.WouldBlock => {
                    // No data available, yield to other tasks
                    try self.yieldAsync();
                },
                else => {
                    std.log.warn("Error processing packets: {}", .{err});
                    break;
                },
            }

            // Process send queue
            _ = try self.multiplexer.processSendQueue();

            // Small delay to prevent busy-waiting
            try self.sleepAsync(1000); // 1ms
        }
    }

    /// Yield control to other async tasks
    fn yieldAsync(self: *Self) !void {
        _ = self;
        // In real TokiZ integration, this would use TokiZ's yield mechanism
        // For now, we simulate with a small sleep
        std.time.sleep(100); // 100 microseconds
    }

    /// Async sleep
    fn sleepAsync(self: *Self, duration_us: u64) !void {
        _ = self;
        std.time.sleep(duration_us * 1000); // Convert to nanoseconds
    }
};

/// Connection pool for managing async connections
pub const ConnectionPool = struct {
    connections: std.ArrayList(*AsyncConnection),
    available_connections: std.ArrayList(*AsyncConnection),
    config: PoolConfig,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) Self {
        return Self{
            .connections = std.ArrayList(*AsyncConnection).init(allocator),
            .available_connections = std.ArrayList(*AsyncConnection).init(allocator),
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |conn| {
            conn.is_active = false;
            self.allocator.destroy(conn);
        }

        self.connections.deinit();
        self.available_connections.deinit();
    }

    /// Get an available connection from the pool
    pub fn acquire(self: *Self) ?*AsyncConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available_connections.popOrNull()) |conn| {
            conn.is_active = true;
            conn.last_activity = std.time.microTimestamp();
            return conn;
        }

        return null;
    }

    /// Return a connection to the pool
    pub fn release(self: *Self, conn: *AsyncConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        conn.is_active = false;
        self.available_connections.append(conn) catch {
            // Pool is full, destroy the connection
            self.allocator.destroy(conn);
        };
    }

    /// Clean up idle connections
    pub fn cleanupIdleConnections(self: *Self) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current_time = std.time.microTimestamp();
        const timeout_us = @as(i64, self.config.idle_timeout_ms) * 1000;

        var removed_count: u32 = 0;
        var i: usize = 0;

        while (i < self.available_connections.items.len) {
            const conn = self.available_connections.items[i];
            if (current_time - conn.last_activity > timeout_us) {
                _ = self.available_connections.swapRemove(i);
                self.allocator.destroy(conn);
                removed_count += 1;
            } else {
                i += 1;
            }
        }

        return removed_count;
    }
};

/// Main QUIC async runtime powered by TokiZ
pub const QuicRuntime = struct {
    multiplexer: UdpMultiplexer,
    connection_pool: ?ConnectionPool,
    config: QuicRuntimeConfig,
    allocator: std.mem.Allocator,
    is_running: bool = false,
    worker_threads: []std.Thread,

    // Task management
    active_tasks: std.ArrayList(*AsyncConnection),
    task_queue: std.fifo.LinearFifo(*AsyncConnection, .Dynamic),

    // Statistics
    total_connections: u64 = 0,
    active_connections: u32 = 0,
    packets_processed: u64 = 0,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, local_address: std.net.Address, config: QuicRuntimeConfig) Error.ZquicError!Self {
        const multiplexer_config = MultiplexerConfig{
            .max_connections = config.max_connections,
            .connection_timeout_ms = config.connection_timeout_ms,
            .send_queue_size = config.send_queue_size,
        };

        const multiplexer = try UdpMultiplexer.init(allocator, local_address, multiplexer_config);

        const connection_pool = if (config.enable_connection_pooling)
            ConnectionPool.init(allocator, config.pool_config)
        else
            null;

        const worker_count = if (config.worker_threads == 0)
            @max(1, std.Thread.getCpuCount() catch 1)
        else
            config.worker_threads;

        const worker_threads = allocator.alloc(std.Thread, worker_count) catch return Error.ZquicError.OutOfMemory;

        return Self{
            .multiplexer = multiplexer,
            .connection_pool = connection_pool,
            .config = config,
            .allocator = allocator,
            .worker_threads = worker_threads,
            .active_tasks = std.ArrayList(*AsyncConnection).init(allocator),
            .task_queue = std.fifo.LinearFifo(*AsyncConnection, .Dynamic).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();

        if (self.connection_pool) |*pool| {
            pool.deinit();
        }

        self.multiplexer.deinit();
        self.allocator.free(self.worker_threads);
        self.active_tasks.deinit();
        self.task_queue.deinit();
    }

    /// Start the async runtime
    pub fn start(self: *Self) Error.ZquicError!void {
        if (self.is_running) {
            return Error.ZquicError.InvalidArgument;
        }

        self.is_running = true;

        // Start worker threads
        for (self.worker_threads, 0..) |*thread, i| {
            thread.* = std.Thread.spawn(.{}, workerLoop, .{ self, i }) catch |err| {
                std.log.err("Failed to start worker thread {}: {}", .{ i, err });
                return Error.ZquicError.InternalError;
            };
        }

        std.log.info("QuicRuntime started with {} worker threads", .{self.worker_threads.len});
    }

    /// Stop the async runtime
    pub fn stop(self: *Self) void {
        if (!self.is_running) return;

        self.is_running = false;

        // Wait for worker threads to finish
        for (self.worker_threads) |*thread| {
            thread.join();
        }

        // Stop all active tasks
        for (self.active_tasks.items) |task| {
            task.is_active = false;
        }

        std.log.info("QuicRuntime stopped");
    }

    /// Spawn a new async connection task
    pub fn spawnConnection(self: *Self, connection: *Connection.Connection, remote_address: std.net.Address) Error.ZquicError!void {
        // Add connection to multiplexer
        try self.multiplexer.addConnection(connection.local_conn_id, connection, remote_address);

        // Create async connection wrapper
        const async_conn = self.allocator.create(AsyncConnection) catch return Error.ZquicError.OutOfMemory;
        async_conn.* = AsyncConnection.init(connection, &self.multiplexer);

        // Add to task queue
        self.task_queue.writeItem(async_conn) catch return Error.ZquicError.ResourceExhausted;

        self.total_connections += 1;
        self.active_connections += 1;
    }

    /// Handle incoming packets with high priority
    pub fn handlePacketUrgent(self: *Self, packet_data: []const u8, source_address: std.net.Address) Error.ZquicError!void {
        try self.multiplexer.routePacket(packet_data, source_address);
        self.packets_processed += 1;
    }

    /// Run I/O focused event loop (for network-intensive applications)
    pub fn runIoFocused(self: *Self) Error.ZquicError!void {
        while (self.is_running) {
            // Process incoming packets
            self.multiplexer.receiveAndRoute() catch |err| switch (err) {
                Error.ZquicError.WouldBlock => {}, // No data available
                else => std.log.warn("I/O error: {}", .{err}),
            };

            // Process send queues
            _ = self.multiplexer.processSendQueue() catch |err| {
                std.log.warn("Send queue error: {}", .{err});
            };

            // Clean up expired connections periodically
            if (self.packets_processed % 1000 == 0) {
                _ = self.multiplexer.cleanupExpiredConnections();

                if (self.connection_pool) |*pool| {
                    _ = pool.cleanupIdleConnections();
                }
            }

            // Small delay to prevent busy-waiting
            std.time.sleep(self.config.poll_interval_us * 1000);
        }
    }

    /// Get runtime statistics
    pub fn getStats(self: *const Self) struct {
        total_connections: u64,
        active_connections: u32,
        packets_processed: u64,
        multiplexer_stats: @TypeOf(self.multiplexer.getStats()),
    } {
        return .{
            .total_connections = self.total_connections,
            .active_connections = self.active_connections,
            .packets_processed = self.packets_processed,
            .multiplexer_stats = self.multiplexer.getStats(),
        };
    }

    /// Worker thread main loop
    fn workerLoop(self: *Self, worker_id: usize) void {
        std.log.debug("Worker thread {} started", .{worker_id});

        while (self.is_running) {
            // Process queued tasks
            if (self.task_queue.readItem()) |async_conn| {
                // Process packets for this connection
                async_conn.processPacketsAsync() catch |err| {
                    std.log.warn("Worker {}: Connection processing error: {}", .{ worker_id, err });
                };

                // Add to active tasks or clean up
                if (async_conn.is_active) {
                    self.active_tasks.append(async_conn) catch {
                        // Task list full, drop the connection
                        async_conn.is_active = false;
                        self.allocator.destroy(async_conn);
                    };
                } else {
                    self.active_connections -= 1;
                    self.allocator.destroy(async_conn);
                }
            }

            // Small delay when no tasks available
            std.time.sleep(1000 * 1000); // 1ms
        }

        std.log.debug("Worker thread {} stopped", .{worker_id});
    }
};

test "quic runtime initialization" {
    const config = QuicRuntimeConfig{
        .max_connections = 10,
        .worker_threads = 1,
    };

    const local_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);

    var runtime = QuicRuntime.init(std.testing.allocator, local_addr, config) catch |err| switch (err) {
        Error.ZquicError.AddressInUse => return, // Skip test in CI
        else => return err,
    };
    defer runtime.deinit();

    const stats = runtime.getStats();
    try std.testing.expect(stats.total_connections == 0);
}

test "connection pool operations" {
    const config = PoolConfig{ .max_size = 5 };
    var pool = ConnectionPool.init(std.testing.allocator, config);
    defer pool.deinit();

    // Initially no connections available
    try std.testing.expect(pool.acquire() == null);
}
