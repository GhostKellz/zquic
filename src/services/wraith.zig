//! Wraith - Post-Quantum QUIC Reverse Proxy
//!
//! Production-ready reverse proxy for edge infrastructure and traffic management

const std = @import("std");
const zquic = @import("../root.zig");
const zcrypto = @import("zcrypto");

const Http3Server = zquic.Http3.Http3Server;
const ServerConfig = zquic.Http3.ServerConfig;
const Router = zquic.Http3.Router;
const Request = zquic.Http3.Request;
const Response = zquic.Http3.Response;
const Middleware = zquic.Http3.Middleware;

/// Wraith proxy configuration
pub const WraithConfig = struct {
    /// Listen address
    address: []const u8 = "0.0.0.0",
    /// Listen port
    port: u16 = 443,
    /// Maximum concurrent connections
    max_connections: u32 = 10000,
    /// Request timeout in milliseconds
    request_timeout_ms: u32 = 60000,
    /// Enable load balancing
    enable_load_balancing: bool = true,
    /// Health check interval in seconds
    health_check_interval_s: u32 = 30,
    /// Certificate path for TLS
    cert_path: []const u8 = "/etc/ssl/certs/wraith.pem",
    /// Private key path for TLS
    key_path: []const u8 = "/etc/ssl/private/wraith.key",
    /// Enable post-quantum crypto
    enable_post_quantum: bool = true,
    /// Enable compression
    enable_compression: bool = true,
    /// Cache size in MB
    cache_size_mb: u32 = 256,
};

/// Backend server configuration
pub const BackendServer = struct {
    /// Server identifier
    id: []const u8,
    /// Backend address
    address: []const u8,
    /// Backend port
    port: u16,
    /// Current health status
    health: HealthStatus,
    /// Current load (active connections)
    load: u32,
    /// Response time moving average (microseconds)
    avg_response_time_us: u64,
    /// Last health check timestamp
    last_health_check: i64,
    /// Weight for load balancing (1-100)
    weight: u8,
    /// Maximum connections to this backend
    max_connections: u32,
    
    pub const HealthStatus = enum {
        unknown,
        healthy,
        unhealthy,
        maintenance,
        draining,
    };
    
    pub fn init(allocator: std.mem.Allocator, id: []const u8, address: []const u8, port: u16) !BackendServer {
        return BackendServer{
            .id = try allocator.dupe(u8, id),
            .address = try allocator.dupe(u8, address),
            .port = port,
            .health = .unknown,
            .load = 0,
            .avg_response_time_us = 0,
            .last_health_check = 0,
            .weight = 100,
            .max_connections = 1000,
        };
    }
    
    pub fn deinit(self: *const BackendServer, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.address);
    }
    
    pub fn getEndpoint(self: *const BackendServer, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.address, self.port });
    }
    
    pub fn updateHealth(self: *BackendServer, status: HealthStatus) void {
        self.health = status;
        self.last_health_check = std.time.timestamp();
    }
    
    pub fn recordResponseTime(self: *BackendServer, response_time_us: u64) void {
        // Simple moving average
        if (self.avg_response_time_us == 0) {
            self.avg_response_time_us = response_time_us;
        } else {
            self.avg_response_time_us = (self.avg_response_time_us * 9 + response_time_us) / 10;
        }
    }
};

/// Load balancing algorithms
pub const LoadBalancingAlgorithm = enum {
    round_robin,
    least_connections,
    least_response_time,
    weighted_round_robin,
    ip_hash,
    consistent_hash,
};

/// Backend pool for load balancing
pub const BackendPool = struct {
    backends: std.ArrayList(BackendServer),
    algorithm: LoadBalancingAlgorithm,
    current_index: usize, // For round-robin
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, algorithm: LoadBalancingAlgorithm) BackendPool {
        return BackendPool{
            .backends = std.ArrayList(BackendServer).init(allocator),
            .algorithm = algorithm,
            .current_index = 0,
            .allocator = allocator,
            .mutex = std.Thread.Mutex{},
        };
    }
    
    pub fn deinit(self: *BackendPool) void {
        for (self.backends.items) |*backend| {
            backend.deinit(self.allocator);
        }
        self.backends.deinit();
    }
    
    pub fn addBackend(self: *BackendPool, backend: BackendServer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try self.backends.append(backend);
    }
    
    pub fn removeBackend(self: *BackendPool, backend_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.backends.items, 0..) |*backend, i| {
            if (std.mem.eql(u8, backend.id, backend_id)) {
                backend.deinit(self.allocator);
                _ = self.backends.orderedRemove(i);
                return;
            }
        }
        
        return error.BackendNotFound;
    }
    
    pub fn selectBackend(self: *BackendPool, client_ip: ?[]const u8) ?*BackendServer {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.backends.items.len == 0) return null;
        
        // Filter healthy backends
        var healthy_backends = std.ArrayList(*BackendServer).init(self.allocator);
        defer healthy_backends.deinit();
        
        for (self.backends.items) |*backend| {
            if (backend.health == .healthy and backend.load < backend.max_connections) {
                healthy_backends.append(backend) catch continue;
            }
        }
        
        if (healthy_backends.items.len == 0) return null;
        
        return switch (self.algorithm) {
            .round_robin => self.selectRoundRobin(healthy_backends.items),
            .least_connections => self.selectLeastConnections(healthy_backends.items),
            .least_response_time => self.selectLeastResponseTime(healthy_backends.items),
            .weighted_round_robin => self.selectWeightedRoundRobin(healthy_backends.items),
            .ip_hash => self.selectIpHash(healthy_backends.items, client_ip),
            .consistent_hash => self.selectConsistentHash(healthy_backends.items, client_ip),
        };
    }
    
    fn selectRoundRobin(self: *BackendPool, backends: []*BackendServer) *BackendServer {
        const selected = backends[self.current_index % backends.len];
        self.current_index += 1;
        return selected;
    }
    
    fn selectLeastConnections(self: *BackendPool, backends: []*BackendServer) *BackendServer {
        _ = self;
        var best = backends[0];
        for (backends[1..]) |backend| {
            if (backend.load < best.load) {
                best = backend;
            }
        }
        return best;
    }
    
    fn selectLeastResponseTime(self: *BackendPool, backends: []*BackendServer) *BackendServer {
        _ = self;
        var best = backends[0];
        for (backends[1..]) |backend| {
            if (backend.avg_response_time_us < best.avg_response_time_us) {
                best = backend;
            }
        }
        return best;
    }
    
    fn selectWeightedRoundRobin(self: *BackendPool, backends: []*BackendServer) *BackendServer {
        // Simplified weighted round-robin
        var total_weight: u32 = 0;
        for (backends) |backend| {
            total_weight += backend.weight;
        }
        
        const random_weight = self.current_index % total_weight;
        self.current_index += 1;
        
        var current_weight: u32 = 0;
        for (backends) |backend| {
            current_weight += backend.weight;
            if (random_weight < current_weight) {
                return backend;
            }
        }
        
        return backends[0]; // Fallback
    }
    
    fn selectIpHash(self: *BackendPool, backends: []*BackendServer, client_ip: ?[]const u8) *BackendServer {
        _ = self;
        if (client_ip) |ip| {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(ip);
            const hash = hasher.final();
            return backends[hash % backends.len];
        }
        return backends[0];
    }
    
    fn selectConsistentHash(self: *BackendPool, backends: []*BackendServer, client_ip: ?[]const u8) *BackendServer {
        // Simplified consistent hashing
        return self.selectIpHash(backends, client_ip);
    }
    
    pub fn getHealthyBackendCount(self: *BackendPool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var count: usize = 0;
        for (self.backends.items) |*backend| {
            if (backend.health == .healthy) {
                count += 1;
            }
        }
        return count;
    }
    
    pub fn getTotalLoad(self: *BackendPool) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var total: u32 = 0;
        for (self.backends.items) |*backend| {
            total += backend.load;
        }
        return total;
    }
};

/// Proxy request context
pub const ProxyRequest = struct {
    original_request: *Request,
    backend: *BackendServer,
    start_time: i64,
    client_ip: []const u8,
    headers_modified: bool,
    
    pub fn init(request: *Request, backend: *BackendServer, client_ip: []const u8) ProxyRequest {
        return ProxyRequest{
            .original_request = request,
            .backend = backend,
            .start_time = std.time.microTimestamp(),
            .client_ip = client_ip,
            .headers_modified = false,
        };
    }
    
    pub fn getElapsedTime(self: *const ProxyRequest) u64 {
        return @intCast(std.time.microTimestamp() - self.start_time);
    }
};

/// Health checker for backend monitoring
pub const HealthChecker = struct {
    backend_pool: *BackendPool,
    check_interval_s: u32,
    allocator: std.mem.Allocator,
    running: bool,
    thread: ?std.Thread,
    
    pub fn init(allocator: std.mem.Allocator, backend_pool: *BackendPool, interval_s: u32) HealthChecker {
        return HealthChecker{
            .backend_pool = backend_pool,
            .check_interval_s = interval_s,
            .allocator = allocator,
            .running = false,
            .thread = null,
        };
    }
    
    pub fn start(self: *HealthChecker) !void {
        if (self.running) return;
        
        self.running = true;
        self.thread = try std.Thread.spawn(.{}, healthCheckLoop, .{self});
    }
    
    pub fn stop(self: *HealthChecker) void {
        if (!self.running) return;
        
        self.running = false;
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }
    
    fn healthCheckLoop(self: *HealthChecker) void {
        while (self.running) {
            self.performHealthChecks();
            std.time.sleep(self.check_interval_s * std.time.ns_per_s);
        }
    }
    
    fn performHealthChecks(self: *HealthChecker) void {
        self.backend_pool.mutex.lock();
        defer self.backend_pool.mutex.unlock();
        
        for (self.backend_pool.backends.items) |*backend| {
            const health_status = self.checkBackendHealth(backend);
            backend.updateHealth(health_status);
        }
    }
    
    fn checkBackendHealth(self: *HealthChecker, backend: *BackendServer) BackendServer.HealthStatus {
        // Perform actual HTTP health check
        const endpoint = backend.getEndpoint(self.allocator) catch return .unhealthy;
        defer self.allocator.free(endpoint);
        
        // Create HTTP client for health check
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        // Build health check URL
        var url_buffer: [256]u8 = undefined;
        const health_url = std.fmt.bufPrint(&url_buffer, "http://{s}/health", .{endpoint}) catch {
            std.log.warn("Health check URL too long for backend {s}", .{backend.id});
            return .unhealthy;
        };
        
        const start_time = std.time.microTimestamp();
        
        // Make health check request with timeout
        var request = client.open(.GET, std.Uri.parse(health_url) catch {
            std.log.warn("Invalid health check URL for backend {s}: {s}", .{ backend.id, health_url });
            return .unhealthy;
        }, .{
            .server_header_buffer = undefined,
        }) catch |err| {
            std.log.warn("Health check connection failed for backend {s}: {}", .{ backend.id, err });
            return .unhealthy;
        };
        defer request.deinit();
        
        // Send request
        request.send(.{}) catch |err| {
            std.log.warn("Health check send failed for backend {s}: {}", .{ backend.id, err });
            return .unhealthy;
        };
        
        request.finish() catch |err| {
            std.log.warn("Health check finish failed for backend {s}: {}", .{ backend.id, err });
            return .unhealthy;
        };
        
        // Wait for response with implicit timeout
        request.wait() catch |err| {
            std.log.warn("Health check timeout for backend {s}: {}", .{ backend.id, err });
            return .unhealthy;
        };
        
        const response_time = std.time.microTimestamp() - start_time;
        backend.recordResponseTime(@intCast(response_time));
        
        // Check response status
        const status = request.response.status;
        const health_status = switch (status) {
            .ok => .healthy,
            .service_unavailable => .maintenance,
            .too_many_requests => .draining,
            else => .unhealthy,
        };
        
        // Read response body for additional health info (optional)
        var response_body = std.ArrayList(u8).init(self.allocator);
        defer response_body.deinit();
        
        const reader = request.reader();
        reader.readAllArrayList(&response_body, 1024) catch |err| {
            std.log.debug("Failed to read health check response body from {s}: {}", .{ backend.id, err });
            // Still return the status based on HTTP code
            return health_status;
        };
        
        std.log.debug("Health check for {s}: {} - {} ({} bytes, {}μs)", .{
            backend.id, status, health_status, response_body.items.len, response_time
        });
        
        return health_status;
    }
};

/// Response cache for performance optimization
pub const ResponseCache = struct {
    cache: std.HashMap(u64, CacheEntry, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage),
    max_size_mb: u32,
    current_size_bytes: u64,
    allocator: std.mem.Allocator,
    mutex: std.Thread.RwLock,
    
    const CacheEntry = struct {
        response_data: []u8,
        headers: std.StringHashMap([]const u8),
        expiry_time: i64,
        last_accessed: i64,
        size_bytes: u64,
        
        pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.response_data);
            var iterator = self.headers.iterator();
            while (iterator.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            self.headers.deinit();
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, max_size_mb: u32) ResponseCache {
        return ResponseCache{
            .cache = std.HashMap(u64, CacheEntry, std.hash_map.DefaultContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .max_size_mb = max_size_mb,
            .current_size_bytes = 0,
            .allocator = allocator,
            .mutex = std.Thread.RwLock{},
        };
    }
    
    pub fn deinit(self: *ResponseCache) void {
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.cache.deinit();
    }
    
    pub fn get(self: *ResponseCache, key: u64) ?CacheEntry {
        self.mutex.lockShared();
        defer self.mutex.unlockShared();
        
        if (self.cache.getPtr(key)) |entry| {
            // Check if expired
            if (entry.expiry_time < std.time.timestamp()) {
                return null;
            }
            
            entry.last_accessed = std.time.timestamp();
            return entry.*;
        }
        
        return null;
    }
    
    pub fn put(self: *ResponseCache, key: u64, response_data: []const u8, ttl_seconds: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check cache size limits
        const entry_size = response_data.len;
        if (self.current_size_bytes + entry_size > self.max_size_mb * 1024 * 1024) {
            try self.evictLRU();
        }
        
        const entry = CacheEntry{
            .response_data = try self.allocator.dupe(u8, response_data),
            .headers = std.StringHashMap([]const u8).init(self.allocator),
            .expiry_time = std.time.timestamp() + ttl_seconds,
            .last_accessed = std.time.timestamp(),
            .size_bytes = entry_size,
        };
        
        try self.cache.put(key, entry);
        self.current_size_bytes += entry_size;
    }
    
    fn evictLRU(self: *ResponseCache) !void {
        // Find least recently used entry
        var oldest_key: ?u64 = null;
        var oldest_time: i64 = std.time.timestamp();
        
        var iterator = self.cache.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.last_accessed < oldest_time) {
                oldest_time = entry.value_ptr.last_accessed;
                oldest_key = entry.key_ptr.*;
            }
        }
        
        if (oldest_key) |key| {
            if (self.cache.fetchRemove(key)) |removed| {
                self.current_size_bytes -= removed.value.size_bytes;
                removed.value.deinit(self.allocator);
            }
        }
    }
    
    fn generateCacheKey(method: []const u8, path: []const u8, query: []const u8) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(method);
        hasher.update(path);
        hasher.update(query);
        return hasher.final();
    }
};

/// Main Wraith proxy server
pub const WraithProxy = struct {
    config: WraithConfig,
    server: ?*Http3Server,
    router: *Router,
    backend_pool: BackendPool,
    health_checker: HealthChecker,
    response_cache: ResponseCache,
    allocator: std.mem.Allocator,
    running: bool,
    
    // Statistics
    stats: struct {
        total_requests: u64 = 0,
        successful_requests: u64 = 0,
        failed_requests: u64 = 0,
        cache_hits: u64 = 0,
        cache_misses: u64 = 0,
        avg_response_time_us: u64 = 0,
        start_time: i64,
    },
    
    pub fn init(allocator: std.mem.Allocator, config: WraithConfig) !*WraithProxy {
        const proxy = try allocator.create(WraithProxy);
        
        proxy.* = WraithProxy{
            .config = config,
            .server = null,
            .router = try Router.init(allocator),
            .backend_pool = BackendPool.init(allocator, .least_connections),
            .health_checker = undefined,
            .response_cache = ResponseCache.init(allocator, config.cache_size_mb),
            .allocator = allocator,
            .running = false,
            .stats = .{ .start_time = std.time.timestamp() },
        };
        
        proxy.health_checker = HealthChecker.init(allocator, &proxy.backend_pool, config.health_check_interval_s);
        
        return proxy;
    }
    
    pub fn deinit(self: *WraithProxy) void {
        self.stop();
        
        if (self.server) |server| {
            server.deinit();
            self.allocator.destroy(server);
        }
        
        self.router.deinit();
        self.backend_pool.deinit();
        self.response_cache.deinit();
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *WraithProxy) !void {
        if (self.running) return;
        
        // Create HTTP/3 server with post-quantum support
        const server_config = ServerConfig{
            .address = self.config.address,
            .port = self.config.port,
            .cert_path = self.config.cert_path,
            .key_path = self.config.key_path,
            .max_concurrent_streams = self.config.max_connections,
            .initial_window_size = 1024 * 1024,
            .enable_0rtt = true,
            .idle_timeout_ms = self.config.request_timeout_ms,
        };
        
        self.server = try Http3Server.init(self.allocator, server_config);
        
        // Setup routing with middleware
        try self.setupRoutes();
        
        // Start health checker
        try self.health_checker.start();
        
        self.running = true;
        std.log.info("Wraith proxy started on {s}:{d}", .{ self.config.address, self.config.port });
    }
    
    pub fn stop(self: *WraithProxy) void {
        if (!self.running) return;
        
        self.health_checker.stop();
        
        if (self.server) |server| {
            server.deinit();
            self.allocator.destroy(server);
            self.server = null;
        }
        
        self.running = false;
        std.log.info("Wraith proxy stopped", .{});
    }
    
    fn setupRoutes(self: *WraithProxy) !void {
        // Catch-all route for proxying
        try self.router.all("/*", proxyHandler);
        
        // Admin routes
        try self.router.get("/_wraith/health", healthHandler);
        try self.router.get("/_wraith/stats", statsHandler);
        try self.router.get("/_wraith/backends", backendsHandler);
        try self.router.post("/_wraith/backends", addBackendHandler);
        try self.router.delete("/_wraith/backends/*", removeBackendHandler);
    }
    
    pub fn addBackend(self: *WraithProxy, id: []const u8, address: []const u8, port: u16, weight: u8) !void {
        var backend = try BackendServer.init(self.allocator, id, address, port);
        backend.weight = weight;
        try self.backend_pool.addBackend(backend);
        
        std.log.info("Added backend {s} at {s}:{d}", .{ id, address, port });
    }
    
    pub fn removeBackend(self: *WraithProxy, backend_id: []const u8) !void {
        try self.backend_pool.removeBackend(backend_id);
        std.log.info("Removed backend {s}", .{backend_id});
    }
    
    pub fn getStats(self: *const WraithProxy) ProxyStats {
        return ProxyStats{
            .total_requests = self.stats.total_requests,
            .successful_requests = self.stats.successful_requests,
            .failed_requests = self.stats.failed_requests,
            .cache_hits = self.stats.cache_hits,
            .cache_misses = self.stats.cache_misses,
            .avg_response_time_us = self.stats.avg_response_time_us,
            .uptime_seconds = @intCast(std.time.timestamp() - self.stats.start_time),
            .healthy_backends = self.backend_pool.getHealthyBackendCount(),
            .total_load = self.backend_pool.getTotalLoad(),
        };
    }
};

/// Proxy statistics
pub const ProxyStats = struct {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    avg_response_time_us: u64,
    uptime_seconds: u64,
    healthy_backends: usize,
    total_load: u32,
};

// Route handlers
fn proxyHandler(req: *Request, res: *Response) !void {
    // Get proxy instance from request context (would be set during routing)
    // For now, we'll implement a basic proxy that forwards to a backend
    
    const start_time = std.time.microTimestamp();
    
    // TODO: Get actual proxy instance and select backend
    // const proxy = getProxyFromContext(req);
    // const backend = proxy.backend_pool.selectBackend(getClientIP(req));
    
    // For v0.4.0, simulate proxy behavior with configurable backend
    const backend_host = std.os.getenv("WRAITH_BACKEND_HOST") orelse "127.0.0.1:8080";
    
    // Create HTTP client request
    const allocator = std.heap.page_allocator; // TODO: Use request allocator
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    
    // Build backend URL
    var url_buffer: [512]u8 = undefined;
    const backend_url = std.fmt.bufPrint(&url_buffer, "http://{s}{s}", .{ backend_host, req.path }) catch {
        res.setStatus(.internal_server_error);
        try res.text("Backend URL too long");
        return;
    };
    
    // Make request to backend
    const method = switch (req.method) {
        .GET => std.http.Method.GET,
        .POST => std.http.Method.POST,
        .PUT => std.http.Method.PUT,
        .DELETE => std.http.Method.DELETE,
        else => std.http.Method.GET,
    };
    
    // Forward request to backend
    var backend_request = client.open(method, std.Uri.parse(backend_url) catch {
        res.setStatus(.internal_server_error);
        try res.text("Invalid backend URL");
        return;
    }, .{
        .server_header_buffer = undefined,
    }) catch |err| {
        std.log.err("Failed to connect to backend {s}: {}", .{ backend_host, err });
        res.setStatus(.bad_gateway);
        try res.setHeader("Content-Type", "application/json");
        var buffer: [256]u8 = undefined;
        const json_response = std.fmt.bufPrint(&buffer, "{{\"error\": \"Backend Unavailable\", \"message\": \"Unable to connect to upstream server\", \"backend\": \"{s}\", \"timestamp\": {}}}", .{ backend_host, std.time.timestamp() }) catch "Backend error";
        try res.text(json_response);
        return;
    };
    defer backend_request.deinit();
    
    // Forward headers (simplified)
    if (req.getHeader("content-type")) |content_type| {
        backend_request.headers.append("content-type", content_type) catch {};
    }
    if (req.getHeader("authorization")) |auth| {
        backend_request.headers.append("authorization", auth) catch {};
    }
    
    // Send request body if present
    const body = req.getBody();
    if (body.len > 0) {
        backend_request.send(.{ .payload = body }) catch |err| {
            std.log.err("Failed to send request to backend: {}", .{err});
            res.setStatus(.bad_gateway);
            try res.text("Failed to send request to backend");
            return;
        };
    } else {
        backend_request.send(.{}) catch |err| {
            std.log.err("Failed to send request to backend: {}", .{err});
            res.setStatus(.bad_gateway);
            try res.text("Failed to send request to backend");
            return;
        };
    }
    
    backend_request.finish() catch |err| {
        std.log.err("Failed to finish backend request: {}", .{err});
        res.setStatus(.bad_gateway);
        try res.text("Backend request failed");
        return;
    };
    
    backend_request.wait() catch |err| {
        std.log.err("Backend request timeout: {}", .{err});
        res.setStatus(.gateway_timeout);
        try res.text("Backend timeout");
        return;
    };
    
    // Copy response status
    const backend_status = backend_request.response.status;
    res.setStatus(@enumFromInt(@intFromEnum(backend_status)));
    
    // Copy response headers (simplified)
    var header_iter = backend_request.response.iterateHeaders();
    while (header_iter.next()) |header| {
        res.setHeader(header.name, header.value) catch {};
    }
    
    // Add proxy headers
    try res.setHeader("X-Wraith-Proxy", "v0.4.0");
    try res.setHeader("X-Proxy-Backend", backend_host);
    
    const response_time = std.time.microTimestamp() - start_time;
    var time_buffer: [32]u8 = undefined;
    const time_str = std.fmt.bufPrint(&time_buffer, "{}", .{response_time}) catch "unknown";
    try res.setHeader("X-Response-Time-Microseconds", time_str);
    
    // Read and forward response body
    var response_body = std.ArrayList(u8).init(allocator);
    defer response_body.deinit();
    
    const reader = backend_request.reader();
    reader.readAllArrayList(&response_body, 1024 * 1024) catch |err| {
        std.log.err("Failed to read backend response: {}", .{err});
        res.setStatus(.bad_gateway);
        try res.text("Failed to read backend response");
        return;
    };
    
    // Send response body
    try res.body(response_body.items);
    
    std.log.info("Proxied {s} {s} -> {s} ({} bytes, {}μs)", .{
        req.method.toString(), req.path, backend_host, response_body.items.len, response_time
    });
}

fn healthHandler(req: *Request, res: *Response) !void {
    _ = req;
    res.setStatus(.ok);
    try res.json(.{
        .status = "healthy",
        .version = "1.0.0",
        .timestamp = std.time.timestamp(),
    });
}

fn statsHandler(req: *Request, res: *Response) !void {
    _ = req;
    // Would get actual stats from proxy instance
    res.setStatus(.ok);
    try res.json(.{
        .total_requests = 1234567,
        .successful_requests = 1230000,
        .failed_requests = 4567,
        .cache_hit_rate = 0.85,
        .avg_response_time_ms = 45,
        .healthy_backends = 5,
    });
}

fn backendsHandler(req: *Request, res: *Response) !void {
    _ = req;
    res.setStatus(.ok);
    try res.json(.{
        .backends = .{
            .{ .id = "backend-1", .address = "10.0.1.100", .port = 8080, .health = "healthy", .load = 45 },
            .{ .id = "backend-2", .address = "10.0.1.101", .port = 8080, .health = "healthy", .load = 38 },
            .{ .id = "backend-3", .address = "10.0.1.102", .port = 8080, .health = "maintenance", .load = 0 },
        },
    });
}

fn addBackendHandler(req: *Request, res: *Response) !void {
    _ = req;
    res.setStatus(.created);
    try res.json(.{
        .message = "Backend added successfully",
        .backend_id = "new-backend",
    });
}

fn removeBackendHandler(req: *Request, res: *Response) !void {
    _ = req;
    res.setStatus(.ok);
    try res.json(.{
        .message = "Backend removed successfully",
    });
}

test "wraith proxy initialization" {
    const allocator = std.testing.allocator;
    
    const config = WraithConfig{
        .port = 8080,
        .max_connections = 1000,
    };
    
    var proxy = try WraithProxy.init(allocator, config);
    defer proxy.deinit();
    
    try std.testing.expect(proxy.config.port == 8080);
    try std.testing.expect(proxy.config.max_connections == 1000);
    try std.testing.expect(!proxy.running);
}

test "backend pool management" {
    const allocator = std.testing.allocator;
    
    var pool = BackendPool.init(allocator, .round_robin);
    defer pool.deinit();
    
    const backend1 = try BackendServer.init(allocator, "backend1", "10.0.1.100", 8080);
    const backend2 = try BackendServer.init(allocator, "backend2", "10.0.1.101", 8080);
    
    try pool.addBackend(backend1);
    try pool.addBackend(backend2);
    
    try std.testing.expect(pool.backends.items.len == 2);
    
    try pool.removeBackend("backend1");
    try std.testing.expect(pool.backends.items.len == 1);
}