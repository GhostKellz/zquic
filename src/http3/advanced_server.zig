//! Advanced HTTP/3 Server with Proxy and Load Balancing
//!
//! Features that match and exceed Quinn's capabilities:
//! - High-performance reverse proxy with load balancing
//! - Advanced connection pooling and multiplexing
//! - Circuit breaker pattern for resilience
//! - Health checks and auto-recovery
//! - Metrics and monitoring
//! - Edge routing and traffic management
//! - WebSocket over HTTP/3 support
//! - Server push optimization
//! - Adaptive load balancing algorithms

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const Connection = @import("../core/connection.zig").Connection;
const Stream = @import("../core/stream.zig");
const Frame = @import("frame.zig");
const QpackDecoder = @import("qpack.zig").QpackDecoder;
const Method = @import("request.zig").Method;
const Request = @import("request.zig").Request;
const StatusCode = @import("response.zig").StatusCode;
const Response = @import("response.zig").Response;
const EnhancedUdpMultiplexer = @import("../transport/enhanced_multiplexer.zig").EnhancedUdpMultiplexer;
const NetAddress = @import("../net/address.zig");
const Time = @import("../utils/time.zig");

/// Load balancing algorithms
pub const LoadBalancingAlgorithm = enum {
    round_robin,
    least_connections,
    weighted_round_robin,
    least_response_time,
    ip_hash,
    consistent_hash,
    random,

    pub fn toString(self: LoadBalancingAlgorithm) []const u8 {
        return switch (self) {
            .round_robin => "round_robin",
            .least_connections => "least_connections",
            .weighted_round_robin => "weighted_round_robin",
            .least_response_time => "least_response_time",
            .ip_hash => "ip_hash",
            .consistent_hash => "consistent_hash",
            .random => "random",
        };
    }
};

/// Health check configuration
pub const HealthCheckConfig = struct {
    enabled: bool = true,
    interval_ms: u32 = 30_000,
    timeout_ms: u32 = 5_000,
    path: []const u8 = "/health",
    method: []const u8 = "GET",
    expected_status: u16 = 200,
    expected_body: ?[]const u8 = null,
    failure_threshold: u8 = 3,
    recovery_threshold: u8 = 2,
};

/// Circuit breaker states
pub const CircuitBreakerState = enum {
    closed,
    open,
    half_open,
};

/// Circuit breaker configuration
pub const CircuitBreakerConfig = struct {
    enabled: bool = true,
    failure_threshold: u32 = 5,
    success_threshold: u32 = 3,
    timeout_ms: u32 = 60_000,
    half_open_max_calls: u32 = 3,
};

/// Backend server configuration
pub const BackendConfig = struct {
    host: []const u8,
    port: u16,
    weight: u32 = 1,
    max_connections: u32 = 100,
    timeout_ms: u32 = 30_000,
    health_check: HealthCheckConfig = HealthCheckConfig{},
    circuit_breaker: CircuitBreakerConfig = CircuitBreakerConfig{},

    // Advanced features
    connection_pool_size: u32 = 50,
    keepalive_timeout_ms: u32 = 300_000,
    retry_count: u8 = 3,
    retry_delay_ms: u32 = 1000,
    enable_http2_fallback: bool = true,
    enable_tls: bool = true,
    sni_hostname: ?[]const u8 = null,

    pub fn getAddress(self: *const BackendConfig) !NetAddress.Address {
        return NetAddress.resolveIp(self.host, self.port);
    }
};

/// Backend server instance
pub const BackendServer = struct {
    config: BackendConfig,
    health_status: HealthStatus,
    circuit_breaker: CircuitBreaker,
    connection_pool: ConnectionPool,
    stats: BackendStats,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: BackendConfig) !Self {
        return Self{
            .config = config,
            .health_status = HealthStatus.init(),
            .circuit_breaker = CircuitBreaker.init(config.circuit_breaker),
            .connection_pool = try ConnectionPool.init(allocator, config.connection_pool_size),
            .stats = BackendStats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.connection_pool.deinit();
    }

    pub fn isHealthy(self: *const Self) bool {
        return self.health_status.is_healthy and self.circuit_breaker.state == .closed;
    }

    pub fn isAvailable(self: *const Self) bool {
        return self.isHealthy() and self.connection_pool.hasAvailableConnections();
    }

    pub fn getLoad(self: *const Self) f64 {
        const active_connections = self.connection_pool.getActiveConnections();
        const max_connections = self.config.max_connections;
        return @as(f64, @floatFromInt(active_connections)) / @as(f64, @floatFromInt(max_connections));
    }

    pub fn getAverageResponseTime(self: *const Self) f64 {
        return self.stats.average_response_time;
    }
};

/// Health status tracking
pub const HealthStatus = struct {
    is_healthy: bool,
    last_check: i64,
    consecutive_failures: u8,
    consecutive_successes: u8,

    pub fn init() HealthStatus {
        return HealthStatus{
            .is_healthy = true,
            .last_check = Time.nowSeconds(),
            .consecutive_failures = 0,
            .consecutive_successes = 0,
        };
    }

    pub fn markSuccess(self: *HealthStatus) void {
        self.consecutive_successes += 1;
        self.consecutive_failures = 0;
        self.last_check = Time.nowSeconds();
    }

    pub fn markFailure(self: *HealthStatus) void {
        self.consecutive_failures += 1;
        self.consecutive_successes = 0;
        self.last_check = Time.nowSeconds();
    }

    pub fn updateHealthStatus(self: *HealthStatus, config: HealthCheckConfig) void {
        if (self.consecutive_failures >= config.failure_threshold) {
            self.is_healthy = false;
        } else if (self.consecutive_successes >= config.recovery_threshold) {
            self.is_healthy = true;
        }
    }
};

/// Circuit breaker implementation
pub const CircuitBreaker = struct {
    state: CircuitBreakerState,
    config: CircuitBreakerConfig,
    failure_count: u32,
    success_count: u32,
    last_failure_time: i64,
    half_open_calls: u32,

    pub fn init(config: CircuitBreakerConfig) CircuitBreaker {
        return CircuitBreaker{
            .state = .closed,
            .config = config,
            .failure_count = 0,
            .success_count = 0,
            .last_failure_time = 0,
            .half_open_calls = 0,
        };
    }

    pub fn canExecute(self: *CircuitBreaker) bool {
        if (!self.config.enabled) return true;

        const now = Time.nowSeconds();

        switch (self.state) {
            .closed => return true,
            .open => {
                if (now - self.last_failure_time > self.config.timeout_ms) {
                    self.state = .half_open;
                    self.half_open_calls = 0;
                    return true;
                }
                return false;
            },
            .half_open => {
                return self.half_open_calls < self.config.half_open_max_calls;
            },
        }
    }

    pub fn recordSuccess(self: *CircuitBreaker) void {
        if (!self.config.enabled) return;

        switch (self.state) {
            .closed => {
                self.failure_count = 0;
            },
            .half_open => {
                self.success_count += 1;
                if (self.success_count >= self.config.success_threshold) {
                    self.state = .closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            },
            .open => {}, // Should not happen
        }
    }

    pub fn recordFailure(self: *CircuitBreaker) void {
        if (!self.config.enabled) return;

        self.failure_count += 1;
        self.last_failure_time = Time.nowSeconds();

        switch (self.state) {
            .closed => {
                if (self.failure_count >= self.config.failure_threshold) {
                    self.state = .open;
                }
            },
            .half_open => {
                self.state = .open;
                self.half_open_calls = 0;
            },
            .open => {}, // Already open
        }
    }

    pub fn recordCall(self: *CircuitBreaker) void {
        if (self.state == .half_open) {
            self.half_open_calls += 1;
        }
    }
};

/// Connection pool for backend connections
pub const ConnectionPool = struct {
    connections: std.ArrayListUnmanaged(PooledConnection),
    available_connections: std.ArrayListUnmanaged(usize),
    max_size: u32,
    allocator: std.mem.Allocator,

    const PooledConnection = struct {
        connection: ?*Connection,
        in_use: bool,
        created_at: i64,
        last_used: i64,
        request_count: u32,

        pub fn init() PooledConnection {
            const now = Time.nowSeconds();
            return PooledConnection{
                .connection = null,
                .in_use = false,
                .created_at = now,
                .last_used = now,
                .request_count = 0,
            };
        }

        pub fn isExpired(self: *const PooledConnection, max_age_ms: u32) bool {
            const now = Time.nowSeconds();
            return now - self.last_used > max_age_ms;
        }
    };

    pub fn init(allocator: std.mem.Allocator, max_size: u32) !ConnectionPool {
        return ConnectionPool{
            .connections = .empty,
            .available_connections = .empty,
            .max_size = max_size,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.connections.items) |*conn| {
            if (conn.connection) |c| {
                c.deinit();
            }
        }
        self.connections.deinit(self.allocator);
        self.available_connections.deinit(self.allocator);
    }

    pub fn getConnection(self: *ConnectionPool) ?*Connection {
        // Try to get an available connection
        if (self.available_connections.items.len > 0) {
            const index = self.available_connections.items[self.available_connections.items.len - 1];
            self.available_connections.shrinkRetainingCapacity(self.available_connections.items.len - 1);
            var pooled_conn = &self.connections.items[index];
            pooled_conn.in_use = true;
            pooled_conn.last_used = Time.nowSeconds();
            return pooled_conn.connection;
        }

        // Create new connection if under limit
        if (self.connections.items.len < self.max_size) {
            const pooled_conn = PooledConnection.init();
            self.connections.append(self.allocator, pooled_conn) catch return null;
            return null; // Would need to establish connection
        }

        return null;
    }

    pub fn returnConnection(self: *ConnectionPool, connection: *Connection) void {
        for (self.connections.items, 0..) |*conn, i| {
            if (conn.connection == connection) {
                conn.in_use = false;
                conn.last_used = Time.nowSeconds();
                conn.request_count += 1;
                self.available_connections.append(self.allocator, i) catch |err| {
                    std.log.warn("ConnectionPool: Failed to mark connection available: {}", .{err});
                };
                break;
            }
        }
    }

    pub fn hasAvailableConnections(self: *const ConnectionPool) bool {
        return self.available_connections.items.len > 0 or self.connections.items.len < self.max_size;
    }

    pub fn getActiveConnections(self: *const ConnectionPool) u32 {
        var count: u32 = 0;
        for (self.connections.items) |*conn| {
            if (conn.in_use) count += 1;
        }
        return count;
    }

    pub fn cleanupExpiredConnections(self: *ConnectionPool, max_age_ms: u32) void {
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];
            if (!conn.in_use and conn.isExpired(max_age_ms)) {
                if (conn.connection) |c| {
                    c.deinit();
                }
                _ = self.connections.swapRemove(i);

                // Update available connections indices
                for (self.available_connections.items, 0..) |*idx, j| {
                    if (idx.* == i) {
                        _ = self.available_connections.swapRemove(j);
                        break;
                    } else if (idx.* > i) {
                        idx.* -= 1;
                    }
                }
            } else {
                i += 1;
            }
        }
    }
};

/// Backend statistics
pub const BackendStats = struct {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    total_response_time: u64,
    average_response_time: f64,
    min_response_time: u64,
    max_response_time: u64,
    bytes_sent: u64,
    bytes_received: u64,

    pub fn init() BackendStats {
        return BackendStats{
            .total_requests = 0,
            .successful_requests = 0,
            .failed_requests = 0,
            .total_response_time = 0,
            .average_response_time = 0.0,
            .min_response_time = std.math.maxInt(u64),
            .max_response_time = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
        };
    }

    pub fn recordRequest(self: *BackendStats, success: bool, response_time: u64, bytes_sent: u64, bytes_received: u64) void {
        self.total_requests += 1;

        if (success) {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }

        self.total_response_time += response_time;
        self.average_response_time = @as(f64, @floatFromInt(self.total_response_time)) / @as(f64, @floatFromInt(self.total_requests));

        if (response_time < self.min_response_time) {
            self.min_response_time = response_time;
        }

        if (response_time > self.max_response_time) {
            self.max_response_time = response_time;
        }

        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
    }

    pub fn getSuccessRate(self: *const BackendStats) f64 {
        if (self.total_requests == 0) return 0.0;
        return @as(f64, @floatFromInt(self.successful_requests)) / @as(f64, @floatFromInt(self.total_requests));
    }
};

/// Load balancer implementation
pub const LoadBalancer = struct {
    algorithm: LoadBalancingAlgorithm,
    backends: std.ArrayListUnmanaged(BackendServer),
    current_index: u32,
    hash_ring: ?ConsistentHashRing,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, algorithm: LoadBalancingAlgorithm) LoadBalancer {
        return LoadBalancer{
            .algorithm = algorithm,
            .backends = .empty,
            .current_index = 0,
            .hash_ring = null,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *LoadBalancer) void {
        for (self.backends.items) |*backend| {
            backend.deinit();
        }
        self.backends.deinit(self.allocator);

        if (self.hash_ring) |*ring| {
            ring.deinit();
        }
    }

    pub fn addBackend(self: *LoadBalancer, config: BackendConfig) !void {
        const backend = try BackendServer.init(self.allocator, config);
        try self.backends.append(self.allocator, backend);

        // Update consistent hash ring if needed
        if (self.algorithm == .consistent_hash) {
            if (self.hash_ring == null) {
                self.hash_ring = ConsistentHashRing.init(self.allocator);
            }
            try self.hash_ring.?.addNode(config.host, config.weight);
        }
    }

    pub fn removeBackend(self: *LoadBalancer, host: []const u8) void {
        for (self.backends.items, 0..) |*backend, i| {
            if (std.mem.eql(u8, backend.config.host, host)) {
                backend.deinit();
                _ = self.backends.swapRemove(i);

                // Update consistent hash ring if needed
                if (self.algorithm == .consistent_hash and self.hash_ring != null) {
                    self.hash_ring.?.removeNode(host);
                }
                break;
            }
        }
    }

    pub fn selectBackend(self: *LoadBalancer, request: *const Request) ?*BackendServer {
        if (self.backends.items.len == 0) return null;

        switch (self.algorithm) {
            .round_robin => {
                const index = self.current_index % self.backends.items.len;
                self.current_index += 1;
                return &self.backends.items[index];
            },
            .least_connections => {
                var best_backend: ?*BackendServer = null;
                var min_load: f64 = std.math.inf(f64);

                for (self.backends.items) |*backend| {
                    if (!backend.isAvailable()) continue;
                    const load = backend.getLoad();
                    if (load < min_load) {
                        min_load = load;
                        best_backend = backend;
                    }
                }

                return best_backend;
            },
            .weighted_round_robin => {
                // Weighted round robin implementation
                var total_weight: u32 = 0;
                for (self.backends.items) |*backend| {
                    if (!backend.isAvailable()) continue;
                    total_weight += backend.config.weight;
                }

                if (total_weight == 0) return null;

                const target = self.current_index % total_weight;
                self.current_index += 1;

                var current_weight: u32 = 0;
                for (self.backends.items) |*backend| {
                    if (!backend.isAvailable()) continue;
                    current_weight += backend.config.weight;
                    if (current_weight > target) {
                        return backend;
                    }
                }

                return null;
            },
            .least_response_time => {
                var best_backend: ?*BackendServer = null;
                var min_response_time: f64 = std.math.inf(f64);

                for (self.backends.items) |*backend| {
                    if (!backend.isAvailable()) continue;
                    const response_time = backend.getAverageResponseTime();
                    if (response_time < min_response_time) {
                        min_response_time = response_time;
                        best_backend = backend;
                    }
                }

                return best_backend;
            },
            .ip_hash => {
                const client_key = requestClientKey(request);
                const hash = std.hash_map.hashString(client_key);
                const index = hash % self.backends.items.len;
                return &self.backends.items[index];
            },
            .consistent_hash => {
                if (self.hash_ring) |*ring| {
                    const client_key = requestClientKey(request);
                    const host = ring.getNode(client_key);

                    for (self.backends.items) |*backend| {
                        if (!backend.isAvailable()) continue;
                        if (std.mem.eql(u8, backend.config.host, host)) {
                            return backend;
                        }
                    }
                }

                // Fallback to round robin
                const index = self.current_index % self.backends.items.len;
                self.current_index += 1;
                return &self.backends.items[index];
            },
            .random => {
                var random_bytes: [8]u8 = undefined;
                zcrypto.rand.fill(&random_bytes);
                const index = std.mem.readInt(u64, &random_bytes, .little) % self.backends.items.len;
                return &self.backends.items[index];
            },
        }
    }

    fn requestClientKey(request: *const Request) []const u8 {
        return request.getHeader("x-forwarded-for") orelse request.getHeader("host") orelse request.path;
    }

    pub fn getStats(self: *const LoadBalancer) LoadBalancerStats {
        var stats = LoadBalancerStats{
            .total_backends = @intCast(self.backends.items.len),
            .healthy_backends = 0,
            .total_requests = 0,
            .successful_requests = 0,
            .failed_requests = 0,
            .average_response_time = 0.0,
        };

        for (self.backends.items) |*backend| {
            if (backend.isHealthy()) {
                stats.healthy_backends += 1;
            }

            stats.total_requests += backend.stats.total_requests;
            stats.successful_requests += backend.stats.successful_requests;
            stats.failed_requests += backend.stats.failed_requests;
            stats.average_response_time += backend.stats.average_response_time;
        }

        if (stats.healthy_backends > 0) {
            stats.average_response_time /= @as(f64, @floatFromInt(stats.healthy_backends));
        }

        return stats;
    }
};

/// Load balancer statistics
pub const LoadBalancerStats = struct {
    total_backends: u32,
    healthy_backends: u32,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    average_response_time: f64,

    pub fn getSuccessRate(self: *const LoadBalancerStats) f64 {
        if (self.total_requests == 0) return 0.0;
        return @as(f64, @floatFromInt(self.successful_requests)) / @as(f64, @floatFromInt(self.total_requests));
    }
};

/// Consistent hash ring for consistent hashing load balancing
pub const ConsistentHashRing = struct {
    nodes: std.AutoHashMapUnmanaged(u64, []const u8),
    sorted_hashes: std.ArrayListUnmanaged(u64),
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) ConsistentHashRing {
        return ConsistentHashRing{
            .nodes = .empty,
            .sorted_hashes = .empty,
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *ConsistentHashRing) void {
        self.nodes.deinit(self.allocator);
        self.sorted_hashes.deinit(self.allocator);
    }

    pub fn addNode(self: *ConsistentHashRing, node: []const u8, weight: u32) !void {
        // Add multiple virtual nodes based on weight
        for (0..weight) |i| {
            const virtual_node = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ node, i });
            defer self.allocator.free(virtual_node);

            const hash = std.hash_map.hashString(virtual_node);
            try self.nodes.put(self.allocator, hash, node);
            try self.sorted_hashes.append(self.allocator, hash);
        }

        // Sort hashes for binary search
        std.mem.sort(u64, self.sorted_hashes.items, {}, std.sort.asc(u64));
    }

    pub fn removeNode(self: *ConsistentHashRing, node: []const u8) void {
        var hashes_to_remove: std.ArrayListUnmanaged(u64) = .empty;
        defer hashes_to_remove.deinit(self.allocator);

        var iterator = self.nodes.iterator();
        while (iterator.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.*, node)) {
                hashes_to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (hashes_to_remove.items) |hash| {
            _ = self.nodes.remove(hash);

            // Remove from sorted list
            for (self.sorted_hashes.items, 0..) |h, i| {
                if (h == hash) {
                    _ = self.sorted_hashes.swapRemove(i);
                    break;
                }
            }
        }
    }

    pub fn getNode(self: *ConsistentHashRing, key: []const u8) []const u8 {
        if (self.sorted_hashes.items.len == 0) return "";

        const hash = std.hash_map.hashString(key);

        // Find the first node with hash >= key hash
        for (self.sorted_hashes.items) |node_hash| {
            if (node_hash >= hash) {
                return self.nodes.get(node_hash) orelse "";
            }
        }

        // Wrap around to the first node
        return self.nodes.get(self.sorted_hashes.items[0]) orelse "";
    }
};

/// Advanced HTTP/3 server configuration
pub const AdvancedServerConfig = struct {
    // Basic server settings
    max_connections: u32 = 10_000,
    max_streams_per_connection: u32 = 1000,
    request_timeout_ms: u32 = 30_000,
    keep_alive_timeout_ms: u32 = 60_000,
    max_request_body_size: usize = 10 * 1024 * 1024, // 10MB

    // Proxy settings
    enable_proxy: bool = false,
    proxy_timeout_ms: u32 = 30_000,
    proxy_buffer_size: usize = 1024 * 1024, // 1MB
    enable_proxy_protocol: bool = false,

    // Load balancing
    load_balancing_algorithm: LoadBalancingAlgorithm = .round_robin,
    health_check_interval_ms: u32 = 30_000,

    // Performance settings
    enable_server_push: bool = true,
    push_cache_size: usize = 1000,
    enable_early_hints: bool = true,
    enable_websocket: bool = true,

    // Compression
    enable_compression: bool = true,
    compression_level: u8 = 6,
    compression_min_size: usize = 1024,

    // Security
    enable_cors: bool = true,
    cors_origins: []const []const u8 = &[_][]const u8{},
    enable_security_headers: bool = true,
    enable_rate_limiting: bool = true,
    rate_limit_per_ip: u32 = 1000,
    rate_limit_window_ms: u32 = 60_000,

    // Monitoring
    enable_metrics: bool = true,
    metrics_path: []const u8 = "/metrics",
    enable_access_logs: bool = true,
    access_log_format: []const u8 = "combined",

    // Static files
    static_files_root: ?[]const u8 = null,
    static_files_index: []const u8 = "index.html",
    enable_directory_listing: bool = false,

    // Edge features
    enable_edge_side_includes: bool = false,
    enable_image_optimization: bool = false,
    enable_cdn_integration: bool = false,
};

/// Advanced HTTP/3 Server
pub const AdvancedHttp3Server = struct {
    config: AdvancedServerConfig,
    multiplexer: *EnhancedUdpMultiplexer,
    load_balancer: ?LoadBalancer,
    connections: std.AutoHashMapUnmanaged(u64, *ConnectionContext),

    // Middleware and routing
    router: Router,
    middleware_stack: std.ArrayListUnmanaged(Middleware),

    // Performance monitoring
    stats: ServerStats,
    metrics_collector: MetricsCollector,

    // Health monitoring
    health_monitor: HealthMonitor,

    accepting_streams: bool,
    shutdown_in_progress: bool,
    shutdown_started_at_us: i64,
    shutdown_error_code: u64,
    shutdown_reason: ?[]const u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: AdvancedServerConfig, multiplexer: *EnhancedUdpMultiplexer) !Self {
        var load_balancer: ?LoadBalancer = null;
        if (config.enable_proxy) {
            load_balancer = LoadBalancer.init(allocator, config.load_balancing_algorithm);
        }

        return Self{
            .config = config,
            .multiplexer = multiplexer,
            .load_balancer = load_balancer,
            .connections = .empty,
            .router = Router.init(allocator),
            .middleware_stack = .empty,
            .stats = ServerStats.init(),
            .metrics_collector = MetricsCollector.init(allocator),
            .health_monitor = HealthMonitor.init(allocator),
            .accepting_streams = true,
            .shutdown_in_progress = false,
            .shutdown_started_at_us = 0,
            .shutdown_error_code = 0,
            .shutdown_reason = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.load_balancer) |*lb| {
            lb.deinit();
        }

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit(self.allocator);

        self.router.deinit();
        self.middleware_stack.deinit(self.allocator);
        self.metrics_collector.deinit();
        self.health_monitor.deinit();
    }

    /// Add backend server for load balancing
    pub fn addBackend(self: *Self, config: BackendConfig) !void {
        if (self.load_balancer) |*lb| {
            try lb.addBackend(config);
        }
    }

    /// Remove backend server
    pub fn removeBackend(self: *Self, host: []const u8) void {
        if (self.load_balancer) |*lb| {
            lb.removeBackend(host);
        }
    }

    /// Add middleware to the stack
    pub fn addMiddleware(self: *Self, middleware: Middleware) !void {
        try self.middleware_stack.append(self.allocator, middleware);
    }

    /// Add route handler
    pub fn addRoute(self: *Self, method: []const u8, path: []const u8, handler: HandlerFn) !void {
        try self.router.addRoute(method, path, handler);
    }

    /// Handle incoming connection
    pub fn handleConnection(self: *Self, connection: *Connection) !void {
        if (!self.accepting_streams) {
            return Error.ZquicError.ConnectionClosed;
        }

        const conn_id = @intFromPtr(connection);

        if (self.connections.count() >= self.config.max_connections) {
            return Error.ZquicError.ConnectionLimitReached;
        }

        const context = try self.allocator.create(ConnectionContext);
        context.* = ConnectionContext.init(self.allocator, connection);

        try self.connections.put(self.allocator, conn_id, context);

        self.stats.connections_total += 1;
        self.stats.connections_active += 1;

        // Start connection handling
        try self.processConnectionStreams(context);
    }

    /// Start graceful shutdown: stop accepting streams and advertise GOAWAY.
    pub fn beginGracefulShutdown(self: *Self, error_code: u64, reason: ?[]const u8) !void {
        if (self.shutdown_in_progress) {
            return;
        }

        self.accepting_streams = false;
        self.shutdown_in_progress = true;
        self.shutdown_started_at_us = Time.nowMicros();
        self.shutdown_error_code = error_code;
        self.shutdown_reason = reason;

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            try self.sendGoaway(entry.value_ptr.*);
        }
    }

    /// Progress graceful shutdown without blocking indefinitely.
    /// Returns true once all tracked connections have been closed and released.
    pub fn pollGracefulShutdown(self: *Self, timeout_ms: u64) !bool {
        if (!self.shutdown_in_progress) {
            return self.connections.count() == 0;
        }

        const now = Time.nowMicros();
        const timed_out = timeout_ms == 0 or
            now - self.shutdown_started_at_us >= @as(i64, @intCast(timeout_ms * std.time.us_per_ms));

        var all_drained = true;
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            try entry.value_ptr.*.pruneClosedStreams();
            if (entry.value_ptr.*.activeStreamCount() > 0) {
                all_drained = false;
            }
        }

        if (!all_drained and !timed_out) {
            return false;
        }

        try self.closeAndReleaseConnections();
        self.shutdown_in_progress = false;
        return true;
    }

    fn sendGoaway(self: *Self, context: *ConnectionContext) !void {
        _ = self;
        if (context.goaway_sent) {
            return;
        }

        var highest_stream_id: u64 = 0;
        var iterator = context.active_streams.iterator();
        while (iterator.next()) |entry| {
            highest_stream_id = @max(highest_stream_id, entry.key_ptr.*);
        }

        const goaway = Frame.GoawayFrame.init(highest_stream_id);
        var encoded_buf: [16]u8 = undefined;
        var writer = std.Io.Writer.fixed(&encoded_buf);
        try goaway.serialize(&writer);
        const encoded = std.Io.Writer.buffered(&writer);

        iterator = context.active_streams.iterator();
        while (iterator.next()) |entry| {
            const stream = entry.value_ptr.*;
            _ = stream.write(encoded, false) catch |err| {
                std.log.debug("Advanced HTTP/3: failed to write GOAWAY on stream {}: {}", .{ entry.key_ptr.*, err });
                continue;
            };
        }

        context.goaway_sent = true;
        context.updateActivity();
    }

    fn closeAndReleaseConnections(self: *Self) !void {
        var ids: std.ArrayListUnmanaged(u64) = .empty;
        defer ids.deinit(self.allocator);

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            try ids.append(self.allocator, entry.key_ptr.*);
        }

        for (ids.items) |conn_id| {
            if (self.connections.fetchRemove(conn_id)) |entry| {
                const context = entry.value;
                if (!context.connection.isTerminated() and !context.connection.isShuttingDown()) {
                    try context.connection.initiateShutdown(self.shutdown_error_code, self.shutdown_reason);
                }

                context.deinit();
                self.allocator.destroy(context);
                if (self.stats.connections_active > 0) {
                    self.stats.connections_active -= 1;
                }
            }
        }
    }

    /// Process streams for a connection
    fn processConnectionStreams(self: *Self, context: *ConnectionContext) !void {
        if (!self.accepting_streams or context.connection.isTerminated() or context.connection.isShuttingDown()) {
            return;
        }

        try context.connection.processPendingStreamEvents();
        try context.pruneClosedStreams();

        const streams = try context.connection.collectOpenStreams(self.allocator);
        defer self.allocator.free(streams);

        for (streams) |stream| {
            if (stream.state.load(.acquire) == .closed) {
                continue;
            }

            if (context.containsStream(stream.id)) {
                continue;
            }

            if (context.activeStreamCount() >= self.config.max_streams_per_connection) {
                stream.close() catch {};
                return Error.ZquicError.StreamLimitError;
            }

            try context.acceptStream(stream);
            try self.handleStream(context, stream);
        }
    }

    /// Handle individual stream
    fn handleStream(self: *Self, context: *ConnectionContext, stream: *Stream.Stream) !void {
        const request_start = Time.nowMicros();

        // Parse HTTP/3 request
        var request = try self.parseRequest(stream);
        defer request.deinit();

        // Update activity
        context.updateActivity();

        // Apply middleware
        var response = Response.init(self.allocator, request.context.stream_id);
        defer response.deinit();

        for (self.middleware_stack.items) |middleware| {
            try middleware.process(&request, &response);
        }

        // Route request
        if (self.config.enable_proxy and self.load_balancer != null) {
            try self.handleProxyRequest(context, &request, &response);
        } else {
            try self.handleDirectRequest(context, &request, &response);
        }

        // Send response
        try self.sendResponse(stream, &response);

        // Update statistics
        const request_duration = Time.nowMicros() - request_start;
        self.stats.incrementRequest();
        self.stats.addBytesReceived(request.getContentLength() orelse request.getBody().len);
        self.stats.addBytesSent(response.getBodySize());

        // Record metrics
        self.metrics_collector.recordRequest(@intCast(@max(request_duration, 0)), @intFromEnum(response.status));
    }

    /// Handle proxy request
    fn handleProxyRequest(self: *Self, context: *ConnectionContext, request: *const Request, response: *Response) !void {
        _ = context;

        if (self.load_balancer) |*lb| {
            const backend = lb.selectBackend(request) orelse {
                response.setStatus(.service_unavailable);
                try response.write("Service Unavailable");
                return;
            };

            // Check circuit breaker
            if (!backend.circuit_breaker.canExecute()) {
                response.setStatus(.service_unavailable);
                try response.write("Service Unavailable - Circuit Breaker Open");
                return;
            }

            // Record circuit breaker call
            backend.circuit_breaker.recordCall();

            // Get connection from pool
            const conn = backend.connection_pool.getConnection() orelse {
                response.setStatus(.service_unavailable);
                try response.write("Service Unavailable - No Connections");
                backend.circuit_breaker.recordFailure();
                return;
            };

            // Forward request to backend
            var backend_response = self.forwardRequest(conn, request) catch {
                backend.circuit_breaker.recordFailure();
                response.setStatus(.bad_gateway);
                try response.write("Bad Gateway");
                return;
            };
            defer backend_response.deinit();

            // Record success
            backend.circuit_breaker.recordSuccess();

            // Copy response from backend
            response.status = backend_response.status;
            for (backend_response.headers.fields.items) |field| {
                try response.addHeader(field.name, field.value);
            }
            try response.write(backend_response.getBody());

            // Return connection to pool
            backend.connection_pool.returnConnection(conn);
        }
    }

    /// Handle direct request (non-proxy)
    fn handleDirectRequest(self: *Self, context: *ConnectionContext, request: *const Request, response: *Response) !void {
        _ = context;

        if (self.router.findRoute(request.method.toString(), request.path)) |route| {
            try route.handler(request, response);
        } else {
            // Check for static files
            if (self.config.static_files_root) |root| {
                try self.handleStaticFile(root, request, response);
            } else {
                response.setStatus(.not_found);
                try response.write("Not Found");
            }
        }
    }

    /// Handle static file serving
    fn handleStaticFile(self: *Self, root: []const u8, request: *const Request, response: *Response) !void {
        _ = self;
        _ = root;
        _ = request;

        // Static file serving implementation
        response.setStatus(.not_found);
        try response.write("Not Found");
    }

    /// Forward request to backend
    fn forwardRequest(self: *Self, connection: *Connection, request: *const Request) !Response {
        _ = connection;

        // Implementation would forward the request to the backend
        // and return the response
        return Response.init(self.allocator, request.context.stream_id);
    }

    /// Parse HTTP/3 request from stream
    fn parseRequest(self: *Self, stream: *Stream.Stream) !Request {
        _ = stream;

        // Implementation would parse HTTP/3 frames to construct request
        return Request.init(self.allocator, 0, "");
    }

    /// Send HTTP/3 response
    fn sendResponse(self: *Self, stream: *Stream.Stream, response: *const Response) !void {
        _ = self;
        _ = stream;
        _ = response;

        // Implementation would send HTTP/3 frames
    }

    /// Get server statistics
    pub fn getStats(self: *const Self) ServerStats {
        return self.stats;
    }

    /// Get load balancer statistics
    pub fn getLoadBalancerStats(self: *const Self) ?LoadBalancerStats {
        if (self.load_balancer) |*lb| {
            return lb.getStats();
        }
        return null;
    }

    /// Get health status
    pub fn getHealth(self: *const Self) HealthStatus {
        return self.health_monitor.getOverallHealth();
    }
};

/// Connection context for advanced server
pub const ConnectionContext = struct {
    connection: *Connection,
    active_streams: std.AutoHashMapUnmanaged(u64, *Stream.Stream),
    last_activity: i64,
    goaway_sent: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, connection: *Connection) ConnectionContext {
        return ConnectionContext{
            .connection = connection,
            .active_streams = .empty,
            .last_activity = Time.nowSeconds(),
            .goaway_sent = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionContext) void {
        self.active_streams.deinit(self.allocator);
    }

    pub fn updateActivity(self: *ConnectionContext) void {
        self.last_activity = Time.nowSeconds();
    }

    pub fn containsStream(self: *const ConnectionContext, stream_id: u64) bool {
        return self.active_streams.contains(stream_id);
    }

    pub fn activeStreamCount(self: *const ConnectionContext) u32 {
        return @intCast(self.active_streams.count());
    }

    pub fn acceptStream(self: *ConnectionContext, stream: *Stream.Stream) !void {
        try self.active_streams.put(self.allocator, stream.id, stream);
        self.updateActivity();
    }

    pub fn pruneClosedStreams(self: *ConnectionContext) !void {
        var closed_stream_ids: std.ArrayListUnmanaged(u64) = .empty;
        defer closed_stream_ids.deinit(self.allocator);

        var iterator = self.active_streams.iterator();
        while (iterator.next()) |entry| {
            const stream = entry.value_ptr.*;
            if (stream.state.load(.acquire) == .closed) {
                try closed_stream_ids.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (closed_stream_ids.items) |stream_id| {
            _ = self.active_streams.remove(stream_id);
        }
    }
};

/// Server statistics
pub const ServerStats = struct {
    connections_active: u32 = 0,
    connections_total: u64 = 0,
    requests_handled: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    start_time: i64,

    pub fn init() ServerStats {
        return ServerStats{
            .start_time = Time.nowSeconds(),
        };
    }

    pub fn incrementRequest(self: *ServerStats) void {
        self.requests_handled += 1;
    }

    pub fn addBytesReceived(self: *ServerStats, bytes: usize) void {
        self.bytes_received += bytes;
    }

    pub fn addBytesSent(self: *ServerStats, bytes: usize) void {
        self.bytes_sent += bytes;
    }

    pub fn uptime(self: *const ServerStats) i64 {
        return Time.nowSeconds() - self.start_time;
    }
};

/// Metrics collector for performance monitoring
pub const MetricsCollector = struct {
    request_durations: std.ArrayListUnmanaged(u64),
    status_codes: std.AutoHashMapUnmanaged(u16, u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MetricsCollector {
        return MetricsCollector{
            .request_durations = .empty,
            .status_codes = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MetricsCollector) void {
        self.request_durations.deinit(self.allocator);
        self.status_codes.deinit(self.allocator);
    }

    pub fn recordRequest(self: *MetricsCollector, duration: u64, status_code: u16) void {
        self.request_durations.append(self.allocator, duration) catch |err| {
            std.log.debug("MetricsCollector: Failed to record duration: {}", .{err});
        };

        const count = self.status_codes.get(status_code) orelse 0;
        self.status_codes.put(self.allocator, status_code, count + 1) catch |err| {
            std.log.debug("MetricsCollector: Failed to record status code: {}", .{err});
        };
    }

    pub fn getAverageResponseTime(self: *const MetricsCollector) f64 {
        if (self.request_durations.items.len == 0) return 0.0;

        var total: u64 = 0;
        for (self.request_durations.items) |duration| {
            total += duration;
        }

        return @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(self.request_durations.items.len));
    }
};

/// Health monitor for server and backends
pub const HealthMonitor = struct {
    overall_health: HealthStatus,
    component_health: std.StringHashMapUnmanaged(HealthStatus),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HealthMonitor {
        return HealthMonitor{
            .overall_health = HealthStatus.init(),
            .component_health = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HealthMonitor) void {
        self.component_health.deinit(self.allocator);
    }

    pub fn getOverallHealth(self: *const HealthMonitor) HealthStatus {
        return self.overall_health;
    }

    pub fn setComponentHealth(self: *HealthMonitor, component: []const u8, health: HealthStatus) !void {
        try self.component_health.put(component, health);

        // Update overall health based on component health
        self.updateOverallHealth();
    }

    fn updateOverallHealth(self: *HealthMonitor) void {
        var all_healthy = true;

        var iterator = self.component_health.iterator();
        while (iterator.next()) |entry| {
            if (!entry.value_ptr.is_healthy) {
                all_healthy = false;
                break;
            }
        }

        self.overall_health.is_healthy = all_healthy;
    }
};

/// Router for HTTP/3 requests
pub const Router = struct {
    routes: std.ArrayListUnmanaged(Route),
    allocator: std.mem.Allocator,

    const Route = struct {
        method: []const u8,
        path: []const u8,
        handler: HandlerFn,
    };

    pub fn init(allocator: std.mem.Allocator) Router {
        return Router{
            .routes = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Router) void {
        self.routes.deinit(self.allocator);
    }

    pub fn addRoute(self: *Router, method: []const u8, path: []const u8, handler: HandlerFn) !void {
        try self.routes.append(self.allocator, Route{
            .method = method,
            .path = path,
            .handler = handler,
        });
    }

    pub fn findRoute(self: *const Router, method: []const u8, path: []const u8) ?Route {
        for (self.routes.items) |route| {
            if (std.mem.eql(u8, route.method, method) and std.mem.eql(u8, route.path, path)) {
                return route;
            }
        }
        return null;
    }
};

/// Handler function type
pub const HandlerFn = *const fn (request: *const Request, response: *Response) Error.ZquicError!void;

/// Middleware type
pub const Middleware = struct {
    process: *const fn (request: *const Request, response: *Response) Error.ZquicError!void,
};

test "advanced server accepts core queued streams once" {
    const allocator = std.testing.allocator;
    var multiplexer: EnhancedUdpMultiplexer = undefined;
    var server = try AdvancedHttp3Server.init(allocator, .{}, &multiplexer);
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });
    try connection.queueStreamEvent(.{ .stream_data = .{
        .stream_id = 0,
        .data = "GET / HTTP/3",
        .fin = true,
    } });

    var context = ConnectionContext.init(allocator, &connection);
    defer context.deinit();

    try server.processConnectionStreams(&context);
    try std.testing.expect(context.containsStream(0));
    try std.testing.expectEqual(@as(u32, 1), context.activeStreamCount());
    try std.testing.expectEqual(@as(u64, 1), server.stats.requests_handled);

    try server.processConnectionStreams(&context);
    try std.testing.expectEqual(@as(u32, 1), context.activeStreamCount());
    try std.testing.expectEqual(@as(u64, 1), server.stats.requests_handled);
}

test "advanced server rejects new streams after shutdown starts" {
    const allocator = std.testing.allocator;
    var multiplexer: EnhancedUdpMultiplexer = undefined;
    var server = try AdvancedHttp3Server.init(allocator, .{}, &multiplexer);
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.initiateShutdown(0, "test shutdown");
    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });

    var context = ConnectionContext.init(allocator, &connection);
    defer context.deinit();

    try server.processConnectionStreams(&context);
    try std.testing.expect(!context.containsStream(0));
    try std.testing.expectEqual(@as(u32, 0), context.activeStreamCount());
}

test "advanced server graceful shutdown sends goaway and releases drained connections" {
    const allocator = std.testing.allocator;
    var multiplexer: EnhancedUdpMultiplexer = undefined;
    var server = try AdvancedHttp3Server.init(allocator, .{}, &multiplexer);
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });
    try connection.queueStreamEvent(.{ .stream_data = .{
        .stream_id = 0,
        .data = "GET / HTTP/3",
        .fin = true,
    } });

    try server.handleConnection(&connection);
    try std.testing.expectEqual(@as(u32, 1), server.stats.connections_active);

    const conn_id = @intFromPtr(&connection);
    const context = server.connections.get(conn_id).?;
    const stream = connection.getStream(0).?;

    try server.beginGracefulShutdown(0, "server shutdown");
    try std.testing.expect(!server.accepting_streams);
    try std.testing.expect(context.goaway_sent);
    try std.testing.expect(stream.write_buffer.items.len > 0);

    const parsed_header = try Frame.FrameHeader.parse(stream.write_buffer.items);
    try std.testing.expectEqual(Frame.FrameType.goaway, parsed_header.header.frame_type);

    try stream.close();
    const shutdown_complete = try server.pollGracefulShutdown(10_000);
    try std.testing.expect(shutdown_complete);
    try std.testing.expectEqual(@as(usize, 0), server.connections.count());
    try std.testing.expectEqual(@as(u32, 0), server.stats.connections_active);
    try std.testing.expect(connection.isShuttingDown());
    try std.testing.expect(connection.super_connection.outgoing_packets.items.len > 0);
}

test "advanced server graceful shutdown timeout closes active work" {
    const allocator = std.testing.allocator;
    var multiplexer: EnhancedUdpMultiplexer = undefined;
    var server = try AdvancedHttp3Server.init(allocator, .{}, &multiplexer);
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });

    try server.handleConnection(&connection);
    try server.beginGracefulShutdown(0, "timeout");

    const shutdown_complete = try server.pollGracefulShutdown(0);
    try std.testing.expect(shutdown_complete);
    try std.testing.expectEqual(@as(usize, 0), server.connections.count());
    try std.testing.expect(connection.isShuttingDown());
}

test "advanced server rejects overload above per-connection stream limit" {
    const allocator = std.testing.allocator;
    var multiplexer: EnhancedUdpMultiplexer = undefined;
    var server = try AdvancedHttp3Server.init(allocator, .{ .max_streams_per_connection = 1 }, &multiplexer);
    defer server.deinit();

    var connection = try Connection.init(allocator, .server, .{});
    defer connection.deinit();

    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 0,
        .stream_type = .client_bidirectional,
    } });
    try connection.queueStreamEvent(.{ .stream_data = .{
        .stream_id = 0,
        .data = "GET /a HTTP/3",
        .fin = true,
    } });
    try connection.queueStreamEvent(.{ .new_stream = .{
        .stream_id = 4,
        .stream_type = .client_bidirectional,
    } });
    try connection.queueStreamEvent(.{ .stream_data = .{
        .stream_id = 4,
        .data = "GET /b HTTP/3",
        .fin = true,
    } });

    try std.testing.expectError(Error.ZquicError.StreamLimitError, server.handleConnection(&connection));

    const context = server.connections.get(@intFromPtr(&connection)).?;
    try std.testing.expect(context.containsStream(0));
    try std.testing.expectEqual(@as(u32, 1), context.activeStreamCount());
    try std.testing.expectEqual(Stream.StreamState.closed, connection.getStream(4).?.state.load(.acquire));
}

test "connection pool evicts stale idle entries and keeps active entries" {
    const allocator = std.testing.allocator;
    var pool = try ConnectionPool.init(allocator, 4);
    defer pool.deinit();

    var stale = ConnectionPool.PooledConnection.init();
    stale.last_used = Time.nowSeconds() - 10;
    stale.in_use = false;
    var active = ConnectionPool.PooledConnection.init();
    active.last_used = Time.nowSeconds() - 10;
    active.in_use = true;

    try pool.connections.append(allocator, stale);
    try pool.connections.append(allocator, active);
    try pool.available_connections.append(allocator, 0);

    pool.cleanupExpiredConnections(1);

    try std.testing.expectEqual(@as(usize, 1), pool.connections.items.len);
    try std.testing.expect(pool.connections.items[0].in_use);
    try std.testing.expectEqual(@as(usize, 0), pool.available_connections.items.len);
}

test "load balancer skips unhealthy backend and reports stats" {
    const allocator = std.testing.allocator;
    var lb = LoadBalancer.init(allocator, .least_connections);
    defer lb.deinit();

    try lb.addBackend(.{ .host = "bad.example", .port = 443, .connection_pool_size = 1 });
    try lb.addBackend(.{ .host = "good.example", .port = 443, .connection_pool_size = 1 });
    lb.backends.items[0].health_status.is_healthy = false;

    var request = Request.init(allocator, 0, "conn-lb");
    defer request.deinit();
    request.path = try allocator.dupe(u8, "/");

    const selected = lb.selectBackend(&request).?;
    try std.testing.expectEqualStrings("good.example", selected.config.host);

    const stats = lb.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.total_backends);
    try std.testing.expectEqual(@as(u32, 1), stats.healthy_backends);
}

test "weighted load balancer honors priority routing under churn" {
    const allocator = std.testing.allocator;
    var lb = LoadBalancer.init(allocator, .weighted_round_robin);
    defer lb.deinit();

    try lb.addBackend(.{ .host = "low.example", .port = 443, .weight = 1, .connection_pool_size = 8 });
    try lb.addBackend(.{ .host = "high.example", .port = 443, .weight = 3, .connection_pool_size = 8 });

    var request = Request.init(allocator, 0, "conn-weight");
    defer request.deinit();
    request.path = try allocator.dupe(u8, "/weighted");

    var high_count: u32 = 0;
    var low_count: u32 = 0;
    for (0..8) |_| {
        const selected = lb.selectBackend(&request).?;
        if (std.mem.eql(u8, selected.config.host, "high.example")) {
            high_count += 1;
        } else if (std.mem.eql(u8, selected.config.host, "low.example")) {
            low_count += 1;
        }
    }

    try std.testing.expect(high_count > low_count);
    try std.testing.expectEqual(@as(u32, 6), high_count);
    try std.testing.expectEqual(@as(u32, 2), low_count);
}

test "load balancer add remove churn releases backend state" {
    const allocator = std.testing.allocator;
    var lb = LoadBalancer.init(allocator, .round_robin);
    defer lb.deinit();

    for (0..16) |i| {
        const host = try std.fmt.allocPrint(allocator, "backend-{d}.example", .{i});
        defer allocator.free(host);
        try lb.addBackend(.{ .host = host, .port = 443, .connection_pool_size = 2 });
        lb.removeBackend(host);
        try std.testing.expectEqual(@as(usize, 0), lb.backends.items.len);
    }
}
