//! Connection Load Balancer with TokiZ pooling
//!
//! Provides intelligent load balancing and connection pooling for high-performance QUIC applications

const std = @import("std");
const Error = @import("../utils/error.zig");
const Connection = @import("../core/connection.zig");
const Packet = @import("../core/packet.zig");
const QuicRuntime = @import("runtime.zig").QuicRuntime;

/// Load balancing strategy
pub const LoadBalanceStrategy = enum {
    round_robin,
    least_connections,
    weighted_round_robin,
    latency_based,
    connection_count_based,
};

/// Connection pool statistics
pub const PoolStats = struct {
    total_connections: u32,
    active_connections: u32,
    idle_connections: u32,
    peak_connections: u32,
    total_requests: u64,
    failed_requests: u64,
    average_latency_us: u64,
    connection_errors: u64,
};

/// Backend server configuration
pub const Backend = struct {
    id: []const u8,
    address: std.net.Address,
    weight: u32 = 1,
    max_connections: u32 = 100,
    current_connections: u32 = 0,
    is_healthy: bool = true,
    
    // Health check metrics
    health_check_failures: u32 = 0,
    last_health_check: i64 = 0,
    average_response_time_us: u64 = 0,
    
    // Connection pool for this backend
    connection_pool: std.ArrayList(*Connection.Connection),
    available_connections: std.ArrayList(*Connection.Connection),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8, address: std.net.Address) !Self {
        const id_copy = try allocator.dupe(u8, id);
        
        return Self{
            .id = id_copy,
            .address = address,
            .connection_pool = std.ArrayList(*Connection.Connection).init(allocator),
            .available_connections = std.ArrayList(*Connection.Connection).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        // Clean up all connections
        for (self.connection_pool.items) |conn| {
            conn.deinit();
            allocator.destroy(conn);
        }
        
        self.connection_pool.deinit();
        self.available_connections.deinit();
        allocator.free(self.id);
    }
    
    /// Get connection load factor (0.0 = no load, 1.0 = full load)
    pub fn getLoadFactor(self: *const Self) f32 {
        if (self.max_connections == 0) return 1.0;
        return @as(f32, @floatFromInt(self.current_connections)) / @as(f32, @floatFromInt(self.max_connections));
    }
    
    /// Check if backend can accept more connections
    pub fn canAcceptConnection(self: *const Self) bool {
        return self.is_healthy and self.current_connections < self.max_connections;
    }
    
    /// Get an available connection from the pool
    pub fn acquireConnection(self: *Self, allocator: std.mem.Allocator) Error.ZquicError!*Connection.Connection {
        if (self.available_connections.popOrNull()) |conn| {
            self.current_connections += 1;
            return conn;
        }
        
        // Create new connection if under limit
        if (self.current_connections < self.max_connections) {
            const conn_id = try Packet.ConnectionId.init(&[_]u8{ 
                @truncate(std.time.microTimestamp()), 
                @truncate(std.time.microTimestamp() >> 8),
                @truncate(std.time.microTimestamp() >> 16),
                @truncate(std.time.microTimestamp() >> 24),
            });
            
            const connection = try allocator.create(Connection.Connection);
            connection.* = Connection.Connection.init(allocator, .client, conn_id);
            
            try self.connection_pool.append(connection);
            self.current_connections += 1;
            
            return connection;
        }
        
        return Error.ZquicError.ConnectionLimitReached;
    }
    
    /// Release a connection back to the pool
    pub fn releaseConnection(self: *Self, connection: *Connection.Connection) void {
        if (self.current_connections > 0) {
            self.current_connections -= 1;
        }
        
        // Check if connection is still usable
        if (connection.isEstablished() and !connection.isClosed()) {
            self.available_connections.append(connection) catch {
                // Pool is full or error occurred, let the connection be cleaned up
            };
        }
    }
};

/// Load balancer configuration
pub const LoadBalancerConfig = struct {
    strategy: LoadBalanceStrategy = .least_connections,
    health_check_interval_ms: u32 = 30_000,
    health_check_timeout_ms: u32 = 5_000,
    max_health_check_failures: u32 = 3,
    connection_timeout_ms: u32 = 10_000,
    enable_circuit_breaker: bool = true,
    circuit_breaker_threshold: u32 = 5,
    circuit_breaker_reset_timeout_ms: u32 = 60_000,
};

/// Circuit breaker state
pub const CircuitBreakerState = enum {
    closed,    // Normal operation
    open,      // Failing, rejecting requests
    half_open, // Testing if service recovered
};

/// Circuit breaker for backend protection
pub const CircuitBreaker = struct {
    state: CircuitBreakerState = .closed,
    failure_count: u32 = 0,
    success_count: u32 = 0,
    last_failure_time: i64 = 0,
    threshold: u32,
    reset_timeout_ms: u32,
    
    const Self = @This();
    
    pub fn init(threshold: u32, reset_timeout_ms: u32) Self {
        return Self{
            .threshold = threshold,
            .reset_timeout_ms = reset_timeout_ms,
        };
    }
    
    /// Check if requests should be allowed through
    pub fn allowRequest(self: *Self) bool {
        const current_time = std.time.microTimestamp();
        
        switch (self.state) {
            .closed => return true,
            .open => {
                // Check if we should transition to half-open
                if (current_time - self.last_failure_time > @as(i64, self.reset_timeout_ms) * 1000) {
                    self.state = .half_open;
                    self.success_count = 0;
                    return true;
                }
                return false;
            },
            .half_open => return true,
        }
    }
    
    /// Record a successful operation
    pub fn recordSuccess(self: *Self) void {
        self.failure_count = 0;
        
        if (self.state == .half_open) {
            self.success_count += 1;
            // If we get enough successes, close the circuit
            if (self.success_count >= 5) {
                self.state = .closed;
            }
        }
    }
    
    /// Record a failed operation
    pub fn recordFailure(self: *Self) void {
        self.failure_count += 1;
        self.last_failure_time = std.time.microTimestamp();
        
        if (self.failure_count >= self.threshold) {
            self.state = .open;
        }
    }
};

/// Connection load balancer
pub const ConnectionLoadBalancer = struct {
    backends: std.ArrayList(Backend),
    config: LoadBalancerConfig,
    allocator: std.mem.Allocator,
    
    // Load balancing state
    round_robin_index: u32 = 0,
    circuit_breakers: std.HashMap(u64, CircuitBreaker, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    
    // Statistics
    total_requests: u64 = 0,
    successful_requests: u64 = 0,
    failed_requests: u64 = 0,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, config: LoadBalancerConfig) Self {
        return Self{
            .backends = std.ArrayList(Backend).init(allocator),
            .config = config,
            .allocator = allocator,
            .circuit_breakers = std.HashMap(u64, CircuitBreaker, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.backends.items) |*backend| {
            backend.deinit(self.allocator);
        }
        self.backends.deinit();
        self.circuit_breakers.deinit();
    }
    
    /// Add a backend server
    pub fn addBackend(self: *Self, id: []const u8, address: std.net.Address, weight: u32, max_connections: u32) Error.ZquicError!void {
        var backend = Backend.init(self.allocator, id, address) catch return Error.ZquicError.OutOfMemory;
        backend.weight = weight;
        backend.max_connections = max_connections;
        
        self.backends.append(backend) catch return Error.ZquicError.OutOfMemory;
        
        // Initialize circuit breaker for this backend
        if (self.config.enable_circuit_breaker) {
            const backend_hash = std.hash_map.hashString(id);
            const circuit_breaker = CircuitBreaker.init(
                self.config.circuit_breaker_threshold,
                self.config.circuit_breaker_reset_timeout_ms
            );
            self.circuit_breakers.put(backend_hash, circuit_breaker) catch return Error.ZquicError.OutOfMemory;
        }
    }
    
    /// Remove a backend server
    pub fn removeBackend(self: *Self, id: []const u8) bool {
        for (self.backends.items, 0..) |*backend, i| {
            if (std.mem.eql(u8, backend.id, id)) {
                backend.deinit(self.allocator);
                _ = self.backends.swapRemove(i);
                
                // Remove circuit breaker
                const backend_hash = std.hash_map.hashString(id);
                _ = self.circuit_breakers.remove(backend_hash);
                
                return true;
            }
        }
        return false;
    }
    
    /// Select the best backend for a new connection
    pub fn selectBackend(self: *Self) Error.ZquicError!*Backend {
        if (self.backends.items.len == 0) {
            return Error.ZquicError.NetworkUnreachable;
        }
        
        return switch (self.config.strategy) {
            .round_robin => self.selectRoundRobin(),
            .least_connections => self.selectLeastConnections(),
            .weighted_round_robin => self.selectWeightedRoundRobin(),
            .latency_based => self.selectLatencyBased(),
            .connection_count_based => self.selectLeastConnections(), // Same as least connections
        };
    }
    
    /// Acquire a connection from the selected backend
    pub fn acquireConnection(self: *Self) Error.ZquicError!struct { backend: *Backend, connection: *Connection.Connection } {
        self.total_requests += 1;
        
        const backend = try self.selectBackend();
        
        // Check circuit breaker
        if (self.config.enable_circuit_breaker) {
            const backend_hash = std.hash_map.hashString(backend.id);
            if (self.circuit_breakers.getPtr(backend_hash)) |circuit_breaker| {
                if (!circuit_breaker.allowRequest()) {
                    self.failed_requests += 1;
                    return Error.ZquicError.ConnectionRefused;
                }
            }
        }
        
        const connection = backend.acquireConnection(self.allocator) catch |err| {
            self.failed_requests += 1;
            
            // Record failure in circuit breaker
            if (self.config.enable_circuit_breaker) {
                const backend_hash = std.hash_map.hashString(backend.id);
                if (self.circuit_breakers.getPtr(backend_hash)) |circuit_breaker| {
                    circuit_breaker.recordFailure();
                }
            }
            
            return err;
        };
        
        self.successful_requests += 1;
        return .{ .backend = backend, .connection = connection };
    }
    
    /// Release a connection back to its backend
    pub fn releaseConnection(self: *Self, backend: *Backend, connection: *Connection.Connection, success: bool) void {
        backend.releaseConnection(connection);
        
        // Update circuit breaker
        if (self.config.enable_circuit_breaker) {
            const backend_hash = std.hash_map.hashString(backend.id);
            if (self.circuit_breakers.getPtr(backend_hash)) |circuit_breaker| {
                if (success) {
                    circuit_breaker.recordSuccess();
                } else {
                    circuit_breaker.recordFailure();
                }
            }
        }
    }
    
    /// Get load balancer statistics
    pub fn getStats(self: *const Self) struct {
        total_requests: u64,
        successful_requests: u64,
        failed_requests: u64,
        success_rate: f32,
        backend_count: usize,
        total_connections: u32,
        average_load: f32,
    } {
        var total_connections: u32 = 0;
        var total_load: f32 = 0.0;
        
        for (self.backends.items) |*backend| {
            total_connections += backend.current_connections;
            total_load += backend.getLoadFactor();
        }
        
        const success_rate = if (self.total_requests > 0)
            @as(f32, @floatFromInt(self.successful_requests)) / @as(f32, @floatFromInt(self.total_requests))
        else
            0.0;
        
        const average_load = if (self.backends.items.len > 0)
            total_load / @as(f32, @floatFromInt(self.backends.items.len))
        else
            0.0;
        
        return .{
            .total_requests = self.total_requests,
            .successful_requests = self.successful_requests,
            .failed_requests = self.failed_requests,
            .success_rate = success_rate,
            .backend_count = self.backends.items.len,
            .total_connections = total_connections,
            .average_load = average_load,
        };
    }
    
    // Selection strategies
    fn selectRoundRobin(self: *Self) Error.ZquicError!*Backend {
        var attempts: u32 = 0;
        const max_attempts = self.backends.items.len;
        
        while (attempts < max_attempts) {
            const index = self.round_robin_index % @as(u32, @intCast(self.backends.items.len));
            self.round_robin_index = (self.round_robin_index + 1) % @as(u32, @intCast(self.backends.items.len));
            
            const backend = &self.backends.items[index];
            if (backend.canAcceptConnection()) {
                return backend;
            }
            
            attempts += 1;
        }
        
        return Error.ZquicError.ConnectionLimitReached;
    }
    
    fn selectLeastConnections(self: *Self) Error.ZquicError!*Backend {
        var best_backend: ?*Backend = null;
        var least_connections: u32 = std.math.maxInt(u32);
        
        for (self.backends.items) |*backend| {
            if (backend.canAcceptConnection() and backend.current_connections < least_connections) {
                best_backend = backend;
                least_connections = backend.current_connections;
            }
        }
        
        return best_backend orelse Error.ZquicError.ConnectionLimitReached;
    }
    
    fn selectWeightedRoundRobin(self: *Self) Error.ZquicError!*Backend {
        // Simplified weighted round robin - select based on weight and current load
        var best_backend: ?*Backend = null;
        var best_score: f32 = -1.0;
        
        for (self.backends.items) |*backend| {
            if (backend.canAcceptConnection()) {
                const load_factor = backend.getLoadFactor();
                const weight_factor = @as(f32, @floatFromInt(backend.weight));
                const score = weight_factor * (1.0 - load_factor);
                
                if (score > best_score) {
                    best_backend = backend;
                    best_score = score;
                }
            }
        }
        
        return best_backend orelse Error.ZquicError.ConnectionLimitReached;
    }
    
    fn selectLatencyBased(self: *Self) Error.ZquicError!*Backend {
        var best_backend: ?*Backend = null;
        var lowest_latency: u64 = std.math.maxInt(u64);
        
        for (self.backends.items) |*backend| {
            if (backend.canAcceptConnection() and backend.average_response_time_us < lowest_latency) {
                best_backend = backend;
                lowest_latency = backend.average_response_time_us;
            }
        }
        
        return best_backend orelse Error.ZquicError.ConnectionLimitReached;
    }
};

test "load balancer initialization" {
    const config = LoadBalancerConfig{};
    var lb = ConnectionLoadBalancer.init(std.testing.allocator, config);
    defer lb.deinit();
    
    const stats = lb.getStats();
    try std.testing.expect(stats.backend_count == 0);
}

test "backend management" {
    const config = LoadBalancerConfig{};
    var lb = ConnectionLoadBalancer.init(std.testing.allocator, config);
    defer lb.deinit();
    
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8080);
    try lb.addBackend("backend1", addr, 1, 10);
    
    const stats = lb.getStats();
    try std.testing.expect(stats.backend_count == 1);
    
    const removed = lb.removeBackend("backend1");
    try std.testing.expect(removed);
}

test "circuit breaker" {
    var cb = CircuitBreaker.init(3, 60000);
    
    try std.testing.expect(cb.allowRequest());
    
    // Record failures
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    
    // Should be open now
    try std.testing.expect(!cb.allowRequest());
}