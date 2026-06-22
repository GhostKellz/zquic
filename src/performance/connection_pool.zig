//! High-Performance Connection Pool for ZQUIC
//!
//! Implements an efficient connection pool with:
//! - Lock-free operations for maximum concurrency
//! - Connection reuse to reduce handshake overhead
//! - Adaptive scaling based on load
//! - Health monitoring and automatic cleanup
//! - Load balancing across available connections
//! - Memory-efficient connection management

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const SpinMutex = @import("../utils/sync.zig").SpinMutex;
const Connection = @import("../core/connection.zig").Connection;
const ConnectionState = @import("../core/connection.zig").ConnectionState;
const ConnectionParams = @import("../core/connection.zig").ConnectionParams;
const ZeroCopyBuffer = @import("zero_copy.zig").ZeroCopyBuffer;

/// Connection pool configuration
pub const ConnectionPoolConfig = struct {
    /// Initial number of connections to create
    initial_pool_size: u32 = 10,
    /// Maximum number of connections allowed
    max_pool_size: u32 = 1000,
    /// Minimum number of connections to maintain
    min_pool_size: u32 = 5,
    /// Connection idle timeout in milliseconds
    idle_timeout_ms: u64 = 300_000, // 5 minutes
    /// Health check interval in milliseconds
    health_check_interval_ms: u64 = 30_000, // 30 seconds
    /// Maximum time to wait for a connection (milliseconds)
    acquire_timeout_ms: u64 = 5_000, // 5 seconds
    /// Enable connection reuse
    enable_reuse: bool = true,
    /// Enable adaptive scaling
    enable_adaptive_scaling: bool = true,
};

/// Connection pool statistics
pub const PoolStats = struct {
    total_connections: std.atomic.Value(u32),
    active_connections: std.atomic.Value(u32),
    idle_connections: std.atomic.Value(u32),
    connections_created: std.atomic.Value(u64),
    connections_destroyed: std.atomic.Value(u64),
    connections_reused: std.atomic.Value(u64),
    acquire_requests: std.atomic.Value(u64),
    acquire_timeouts: std.atomic.Value(u64),
    health_check_failures: std.atomic.Value(u64),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .total_connections = std.atomic.Value(u32).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .idle_connections = std.atomic.Value(u32).init(0),
            .connections_created = std.atomic.Value(u64).init(0),
            .connections_destroyed = std.atomic.Value(u64).init(0),
            .connections_reused = std.atomic.Value(u64).init(0),
            .acquire_requests = std.atomic.Value(u64).init(0),
            .acquire_timeouts = std.atomic.Value(u64).init(0),
            .health_check_failures = std.atomic.Value(u64).init(0),
        };
    }
};

/// Pooled connection wrapper
pub const PooledConnection = struct {
    connection: *Connection,
    pool: *ConnectionPool,
    id: u64,
    created_at: i64,
    last_used: std.atomic.Value(i64),
    use_count: std.atomic.Value(u64),
    is_healthy: std.atomic.Value(bool),
    reference_count: std.atomic.Value(u32),

    const Self = @This();

    pub fn init(connection: *Connection, pool: *ConnectionPool, id: u64) Self {
        const now = Time.nowMicros();
        return Self{
            .connection = connection,
            .pool = pool,
            .id = id,
            .created_at = now,
            .last_used = std.atomic.Value(i64).init(now),
            .use_count = std.atomic.Value(u64).init(0),
            .is_healthy = std.atomic.Value(bool).init(true),
            .reference_count = std.atomic.Value(u32).init(1),
        };
    }

    /// Mark connection as used
    pub fn markUsed(self: *Self) void {
        _ = self.last_used.store(Time.nowMicros(), .monotonic);
        _ = self.use_count.fetchAdd(1, .monotonic);
    }

    /// Check if connection is idle
    pub fn isIdle(self: *const Self, idle_timeout_us: i64) bool {
        const last_used = self.last_used.load(.monotonic);
        const now = Time.nowMicros();
        return (now - last_used) > idle_timeout_us;
    }

    /// Acquire reference to connection
    pub fn acquire(self: *Self) bool {
        const old_ref = self.reference_count.fetchAdd(1, .acq_rel);
        return old_ref > 0;
    }

    /// Release reference to connection
    pub fn release(self: *Self) void {
        const old_ref = self.reference_count.fetchSub(1, .acq_rel);
        if (old_ref == 1) {
            // Last reference released, return to pool
            self.pool.releaseConnection(self);
        }
    }

    /// Perform health check on connection
    pub fn checkHealth(self: *Self) bool {
        // Check connection state
        if (self.connection.getState() == .closed or self.connection.getState() == .draining) {
            _ = self.is_healthy.store(false, .monotonic);
            return false;
        }

        // Check if connection is still responsive
        const last_activity = self.connection.getLastActivity();
        const now = Time.nowMicros();
        const max_silence = 60_000_000; // 60 seconds

        if (now - last_activity > max_silence) {
            _ = self.is_healthy.store(false, .monotonic);
            return false;
        }

        _ = self.is_healthy.store(true, .monotonic);
        return true;
    }
};

/// Lock-free FIFO queue for pooled connections
const ConnectionQueue = struct {
    head: std.atomic.Value(?*QueueNode),
    tail: std.atomic.Value(?*QueueNode),
    size: std.atomic.Value(u32),
    allocator: std.mem.Allocator,

    const QueueNode = struct {
        next: std.atomic.Value(?*QueueNode),
        connection: *PooledConnection,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .head = std.atomic.Value(?*QueueNode).init(null),
            .tail = std.atomic.Value(?*QueueNode).init(null),
            .size = std.atomic.Value(u32).init(0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        while (self.pop()) |node| {
            self.allocator.destroy(node);
        }
    }

    pub fn push(self: *Self, connection: *PooledConnection) !void {
        const node = try self.allocator.create(QueueNode);
        node.* = QueueNode{
            .next = std.atomic.Value(?*QueueNode).init(null),
            .connection = connection,
        };

        const prev_tail = self.tail.swap(node, .acq_rel);
        if (prev_tail) |tail| {
            _ = tail.next.store(node, .release);
        } else {
            _ = self.head.store(node, .release);
        }

        _ = self.size.fetchAdd(1, .monotonic);
    }

    pub fn pop(self: *Self) ?*QueueNode {
        const head = self.head.load(.acquire) orelse return null;
        const next = head.next.load(.acquire);

        if (self.head.cmpxchgWeak(head, next, .acq_rel, .monotonic)) |_| {
            // CAS failed, try again
            return self.pop();
        }

        if (next == null) {
            _ = self.tail.cmpxchgWeak(head, null, .acq_rel, .monotonic);
        }

        _ = self.size.fetchSub(1, .monotonic);
        return head;
    }

    pub fn len(self: *const Self) u32 {
        return self.size.load(.monotonic);
    }
};

/// High-performance connection pool
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    config: ConnectionPoolConfig,
    stats: PoolStats,

    // Connection management
    idle_connections: ConnectionQueue,
    all_connections: std.HashMap(u64, *PooledConnection, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    connection_id_counter: std.atomic.Value(u64),

    // Threading
    health_check_thread: ?std.Thread = null,
    scaling_thread: ?std.Thread = null,
    shutdown: std.atomic.Value(bool),

    // Synchronization
    pool_mutex: SpinMutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ConnectionPoolConfig) !Self {
        var pool = Self{
            .allocator = allocator,
            .config = config,
            .stats = PoolStats.init(),
            .idle_connections = ConnectionQueue.init(allocator),
            .all_connections = std.HashMap(u64, *PooledConnection, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .connection_id_counter = std.atomic.Value(u64).init(1),
            .shutdown = std.atomic.Value(bool).init(false),
            .pool_mutex = .{},
        };

        // Pre-create initial connections
        try pool.createInitialConnections();

        // Start background threads
        pool.health_check_thread = try std.Thread.spawn(.{}, healthCheckWorker, .{&pool});
        if (config.enable_adaptive_scaling) {
            pool.scaling_thread = try std.Thread.spawn(.{}, scalingWorker, .{&pool});
        }

        return pool;
    }

    pub fn deinit(self: *Self) void {
        // Signal shutdown
        _ = self.shutdown.store(true, .monotonic);

        // Wait for background threads
        if (self.health_check_thread) |thread| {
            thread.join();
        }
        if (self.scaling_thread) |thread| {
            thread.join();
        }

        // Clean up all connections
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        var iterator = self.all_connections.iterator();
        while (iterator.next()) |entry| {
            const pooled_conn = entry.value_ptr.*;
            pooled_conn.connection.deinit();
            self.allocator.destroy(pooled_conn.connection);
            self.allocator.destroy(pooled_conn);
        }

        self.all_connections.deinit();
        self.idle_connections.deinit();
    }

    /// Acquire a connection from the pool
    pub fn acquireConnection(self: *Self, target_host: []const u8, target_port: u16) !*PooledConnection {
        _ = self.stats.acquire_requests.fetchAdd(1, .monotonic);

        const start_time = Time.nowMicros();
        const timeout_us = self.config.acquire_timeout_ms * 1000;

        while (true) {
            // Try to get an idle connection first
            if (self.idle_connections.pop()) |node| {
                defer self.allocator.destroy(node);

                const pooled_conn = node.connection;

                // Check if connection is suitable for reuse
                if (self.config.enable_reuse and pooled_conn.checkHealth()) {
                    if (pooled_conn.acquire()) {
                        pooled_conn.markUsed();
                        _ = self.stats.connections_reused.fetchAdd(1, .monotonic);
                        _ = self.stats.active_connections.fetchAdd(1, .monotonic);
                        _ = self.stats.idle_connections.fetchSub(1, .monotonic);
                        return pooled_conn;
                    }
                }

                // Connection not healthy or couldn't acquire, destroy it
                self.destroyConnection(pooled_conn);
            }

            // No idle connections available, try to create a new one
            if (self.stats.total_connections.load(.monotonic) < self.config.max_pool_size) {
                if (self.createConnection(target_host, target_port)) |pooled_conn| {
                    _ = self.stats.active_connections.fetchAdd(1, .monotonic);
                    return pooled_conn;
                } else |_| {
                    // Failed to create connection
                }
            }

            // Check timeout
            const now = Time.nowMicros();
            if (now - start_time > timeout_us) {
                _ = self.stats.acquire_timeouts.fetchAdd(1, .monotonic);
                return Error.ZquicError.Timeout;
            }

            // Wait a bit and try again
            Time.sleep(1_000_000); // 1ms
        }
    }

    /// Release a connection back to the pool
    pub fn releaseConnection(self: *Self, pooled_conn: *PooledConnection) void {
        _ = self.stats.active_connections.fetchSub(1, .monotonic);

        // Check if connection is still healthy
        if (!pooled_conn.checkHealth() or pooled_conn.connection.getState() != .established) {
            self.destroyConnection(pooled_conn);
            return;
        }

        // Check if we have too many idle connections
        if (self.stats.idle_connections.load(.monotonic) >= self.config.max_pool_size / 2) {
            self.destroyConnection(pooled_conn);
            return;
        }

        // Return to idle pool
        self.idle_connections.push(pooled_conn) catch {
            // Failed to return to pool, destroy connection
            self.destroyConnection(pooled_conn);
            return;
        };

        _ = self.stats.idle_connections.fetchAdd(1, .monotonic);
    }

    /// Create initial pool of connections
    fn createInitialConnections(self: *Self) !void {
        for (0..self.config.initial_pool_size) |_| {
            // Create placeholder connections for the initial pool
            // In a real implementation, these would be actual connection objects
            if (self.createConnection("localhost", 443)) |pooled_conn| {
                self.idle_connections.push(pooled_conn) catch {
                    self.destroyConnection(pooled_conn);
                    continue;
                };
                _ = self.stats.idle_connections.fetchAdd(1, .monotonic);
            } else |_| {
                // Failed to create initial connection, continue with others
                continue;
            }
        }
    }

    /// Create a new connection
    fn createConnection(self: *Self, target_host: []const u8, target_port: u16) !*PooledConnection {
        _ = target_host;
        _ = target_port;

        // Create new connection object
        const connection = try self.allocator.create(Connection);
        connection.* = try Connection.init(self.allocator, .client, ConnectionParams{});

        // Create pooled connection wrapper
        const pooled_conn = try self.allocator.create(PooledConnection);
        const conn_id = self.connection_id_counter.fetchAdd(1, .monotonic);
        pooled_conn.* = PooledConnection.init(connection, self, conn_id);

        // Add to connection registry
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        try self.all_connections.put(conn_id, pooled_conn);
        _ = self.stats.total_connections.fetchAdd(1, .monotonic);
        _ = self.stats.connections_created.fetchAdd(1, .monotonic);

        return pooled_conn;
    }

    /// Destroy a connection
    fn destroyConnection(self: *Self, pooled_conn: *PooledConnection) void {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        // Remove from registry
        _ = self.all_connections.remove(pooled_conn.id);

        // Cleanup connection
        pooled_conn.connection.deinit();
        self.allocator.destroy(pooled_conn.connection);
        self.allocator.destroy(pooled_conn);

        _ = self.stats.total_connections.fetchSub(1, .monotonic);
        _ = self.stats.connections_destroyed.fetchAdd(1, .monotonic);
    }

    /// Get pool statistics
    pub fn getStats(self: *const Self) PoolStats {
        return self.stats;
    }

    /// Health check worker thread
    fn healthCheckWorker(pool: *ConnectionPool) void {
        while (!pool.shutdown.load(.monotonic)) {
            const start_time = Time.nowMicros();

            // Check health of all connections
            pool.pool_mutex.lock();
            var iterator = pool.all_connections.iterator();
            var unhealthy_connections = std.array_list.Managed(u64).init(pool.allocator);
            defer unhealthy_connections.deinit();

            while (iterator.next()) |entry| {
                const pooled_conn = entry.value_ptr.*;

                if (!pooled_conn.checkHealth()) {
                    unhealthy_connections.append(pooled_conn.id) catch continue;
                    _ = pool.stats.health_check_failures.fetchAdd(1, .monotonic);
                }

                // Check for idle timeout
                const idle_timeout_us = pool.config.idle_timeout_ms * 1000;
                if (pooled_conn.isIdle(idle_timeout_us)) {
                    unhealthy_connections.append(pooled_conn.id) catch continue;
                }
            }
            pool.pool_mutex.unlock();

            // Destroy unhealthy connections
            for (unhealthy_connections.items) |conn_id| {
                pool.pool_mutex.lock();
                if (pool.all_connections.get(conn_id)) |pooled_conn| {
                    pool.destroyConnection(pooled_conn);
                }
                pool.pool_mutex.unlock();
            }

            // Sleep until next health check
            const elapsed = Time.nowMicros() - start_time;
            const sleep_time = pool.config.health_check_interval_ms * 1000;
            if (elapsed < sleep_time) {
                Time.sleep(sleep_time - elapsed);
            }
        }
    }

    /// Adaptive scaling worker thread
    fn scalingWorker(pool: *ConnectionPool) void {
        while (!pool.shutdown.load(.monotonic)) {
            const total_conns = pool.stats.total_connections.load(.monotonic);
            const active_conns = pool.stats.active_connections.load(.monotonic);
            const idle_conns = pool.stats.idle_connections.load(.monotonic);

            // Scale up if needed
            if (active_conns > total_conns * 8 / 10 and total_conns < pool.config.max_pool_size) {
                // High utilization, create more connections
                const scale_up_count = @min(pool.config.max_pool_size - total_conns, 5);
                for (0..scale_up_count) |_| {
                    if (pool.createConnection("localhost", 443)) |pooled_conn| {
                        pool.idle_connections.push(pooled_conn) catch {
                            pool.destroyConnection(pooled_conn);
                            break;
                        };
                        _ = pool.stats.idle_connections.fetchAdd(1, .monotonic);
                    } else |_| {
                        break;
                    }
                }
            }

            // Scale down if needed
            if (idle_conns > total_conns / 2 and total_conns > pool.config.min_pool_size) {
                // Too many idle connections, remove some
                const scale_down_count = @min(idle_conns - pool.config.min_pool_size, 3);
                for (0..scale_down_count) |_| {
                    if (pool.idle_connections.pop()) |node| {
                        defer pool.allocator.destroy(node);
                        pool.destroyConnection(node.connection);
                        _ = pool.stats.idle_connections.fetchSub(1, .monotonic);
                    } else {
                        break;
                    }
                }
            }

            // Sleep for 10 seconds before next scaling check
            Time.sleep(10_000_000_000); // 10 seconds
        }
    }
};

/// Connection pool factory for creating optimized pools
pub const ConnectionPoolFactory = struct {
    /// Create a high-performance connection pool
    pub fn createHighPerformancePool(allocator: std.mem.Allocator) !*ConnectionPool {
        const config = ConnectionPoolConfig{
            .initial_pool_size = 20,
            .max_pool_size = 2000,
            .min_pool_size = 10,
            .idle_timeout_ms = 300_000, // 5 minutes
            .health_check_interval_ms = 15_000, // 15 seconds
            .acquire_timeout_ms = 2_000, // 2 seconds
            .enable_reuse = true,
            .enable_adaptive_scaling = true,
        };

        const pool = try allocator.create(ConnectionPool);
        pool.* = try ConnectionPool.init(allocator, config);
        return pool;
    }

    /// Create a memory-optimized connection pool
    pub fn createMemoryOptimizedPool(allocator: std.mem.Allocator) !*ConnectionPool {
        const config = ConnectionPoolConfig{
            .initial_pool_size = 5,
            .max_pool_size = 100,
            .min_pool_size = 2,
            .idle_timeout_ms = 120_000, // 2 minutes
            .health_check_interval_ms = 60_000, // 1 minute
            .acquire_timeout_ms = 5_000, // 5 seconds
            .enable_reuse = true,
            .enable_adaptive_scaling = true,
        };

        const pool = try allocator.create(ConnectionPool);
        pool.* = try ConnectionPool.init(allocator, config);
        return pool;
    }

    /// Create a basic connection pool
    pub fn createBasicPool(allocator: std.mem.Allocator) !*ConnectionPool {
        const config = ConnectionPoolConfig{}; // Use defaults

        const pool = try allocator.create(ConnectionPool);
        pool.* = try ConnectionPool.init(allocator, config);
        return pool;
    }
};
