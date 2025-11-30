//! Connection Load Balancer
//!
//! Provides load balancing for high-performance QUIC applications

const std = @import("std");
const Connection = @import("../core/connection.zig");

/// Load balancing strategy
pub const LoadBalanceStrategy = enum {
    round_robin,
    least_connections,
    weighted_round_robin,
    random,
};

/// Backend server configuration
pub const Backend = struct {
    id: []const u8,
    address: std.net.Address,
    weight: u32 = 1,
    max_connections: u32 = 100,
    current_connections: std.atomic.Value(u32),
    is_healthy: bool = true,
    health_check_failures: u32 = 0,

    const Self = @This();

    pub fn init(id: []const u8, address: std.net.Address) Self {
        return Self{
            .id = id,
            .address = address,
            .weight = 1,
            .max_connections = 100,
            .current_connections = std.atomic.Value(u32).init(0),
            .is_healthy = true,
            .health_check_failures = 0,
        };
    }

    pub fn incrementConnections(self: *Self) void {
        _ = self.current_connections.fetchAdd(1, .monotonic);
    }

    pub fn decrementConnections(self: *Self) void {
        _ = self.current_connections.fetchSub(1, .monotonic);
    }

    pub fn getConnectionCount(self: *const Self) u32 {
        return self.current_connections.load(.monotonic);
    }

    pub fn hasCapacity(self: *const Self) bool {
        return self.getConnectionCount() < self.max_connections and self.is_healthy;
    }
};

/// Load balancer statistics
pub const LoadBalancerStats = struct {
    total_requests: u64 = 0,
    successful_requests: u64 = 0,
    failed_requests: u64 = 0,
    active_backends: u32 = 0,
};

/// Connection load balancer
pub const LoadBalancer = struct {
    backends: std.ArrayListUnmanaged(Backend),
    strategy: LoadBalanceStrategy,
    round_robin_index: std.atomic.Value(u32),
    stats: LoadBalancerStats,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, strategy: LoadBalanceStrategy) Self {
        return Self{
            .backends = .{},
            .strategy = strategy,
            .round_robin_index = std.atomic.Value(u32).init(0),
            .stats = .{},
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.backends.deinit(self.allocator);
    }

    pub fn addBackend(self: *Self, backend: Backend) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.backends.append(self.allocator, backend);
        self.stats.active_backends += 1;
    }

    pub fn removeBackend(self: *Self, id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.backends.items.len) {
            if (std.mem.eql(u8, self.backends.items[i].id, id)) {
                _ = self.backends.swapRemove(i);
                if (self.stats.active_backends > 0) {
                    self.stats.active_backends -= 1;
                }
                break;
            }
            i += 1;
        }
    }

    /// Select a backend based on the configured strategy
    pub fn selectBackend(self: *Self) ?*Backend {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.backends.items.len == 0) return null;

        return switch (self.strategy) {
            .round_robin => self.selectRoundRobin(),
            .least_connections => self.selectLeastConnections(),
            .weighted_round_robin => self.selectWeightedRoundRobin(),
            .random => self.selectRandom(),
        };
    }

    fn selectRoundRobin(self: *Self) ?*Backend {
        const len: u32 = @intCast(self.backends.items.len);
        if (len == 0) return null;

        var attempts: u32 = 0;
        while (attempts < len) {
            const idx = self.round_robin_index.fetchAdd(1, .monotonic) % len;
            var backend = &self.backends.items[idx];
            if (backend.hasCapacity()) {
                return backend;
            }
            attempts += 1;
        }
        return null;
    }

    fn selectLeastConnections(self: *Self) ?*Backend {
        var best: ?*Backend = null;
        var min_conns: u32 = std.math.maxInt(u32);

        for (self.backends.items) |*backend| {
            if (backend.hasCapacity()) {
                const conns = backend.getConnectionCount();
                if (conns < min_conns) {
                    min_conns = conns;
                    best = backend;
                }
            }
        }
        return best;
    }

    fn selectWeightedRoundRobin(self: *Self) ?*Backend {
        // Simple weighted selection - higher weight = more likely
        var total_weight: u32 = 0;
        for (self.backends.items) |backend| {
            if (backend.hasCapacity()) {
                total_weight += backend.weight;
            }
        }

        if (total_weight == 0) return null;

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        var random_weight = prng.random().intRangeAtMost(u32, 1, total_weight);

        for (self.backends.items) |*backend| {
            if (backend.hasCapacity()) {
                if (random_weight <= backend.weight) {
                    return backend;
                }
                random_weight -= backend.weight;
            }
        }
        return null;
    }

    fn selectRandom(self: *Self) ?*Backend {
        var healthy_count: usize = 0;
        for (self.backends.items) |backend| {
            if (backend.hasCapacity()) healthy_count += 1;
        }

        if (healthy_count == 0) return null;

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        var target = prng.random().intRangeAtMost(usize, 0, healthy_count - 1);

        for (self.backends.items) |*backend| {
            if (backend.hasCapacity()) {
                if (target == 0) return backend;
                target -= 1;
            }
        }
        return null;
    }

    pub fn getStats(self: *const Self) LoadBalancerStats {
        return self.stats;
    }
};

test "load balancer initialization" {
    var lb = LoadBalancer.init(std.testing.allocator, .round_robin);
    defer lb.deinit();

    try std.testing.expect(lb.backends.items.len == 0);
}

test "load balancer add backend" {
    var lb = LoadBalancer.init(std.testing.allocator, .round_robin);
    defer lb.deinit();

    const addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8080);
    try lb.addBackend(Backend.init("backend1", addr));

    try std.testing.expect(lb.backends.items.len == 1);
    try std.testing.expect(lb.stats.active_backends == 1);
}

test "load balancer round robin" {
    var lb = LoadBalancer.init(std.testing.allocator, .round_robin);
    defer lb.deinit();

    const addr1 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 8080);
    const addr2 = std.net.Address.initIp4([4]u8{ 10, 0, 0, 2 }, 8080);
    try lb.addBackend(Backend.init("b1", addr1));
    try lb.addBackend(Backend.init("b2", addr2));

    const first = lb.selectBackend();
    const second = lb.selectBackend();

    try std.testing.expect(first != null);
    try std.testing.expect(second != null);
    try std.testing.expect(first != second);
}
