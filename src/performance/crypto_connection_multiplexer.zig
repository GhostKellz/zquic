//! Crypto-Optimized Connection Multiplexer for ZQUIC
//!
//! High-performance connection pooling and multiplexing specifically designed for
//! crypto/blockchain workloads with support for DoQ, HTTP/3, and gRPC-over-QUIC

const std = @import("std");
const Error = @import("../utils/error.zig");
const Connection = @import("../core/connection.zig").Connection;
const ZeroRttContext = @import("../crypto/zero_rtt_resumption.zig").ZeroRttContext;
const HybridPQTlsContext = @import("../crypto/hybrid_pq_tls.zig").HybridPQTlsContext;

/// Protocol types supported by the multiplexer
pub const ProtocolType = enum {
    dns_over_quic, // DoQ for blockchain domains
    http3, // HTTP/3 for DeFi APIs
    grpc_over_quic, // gRPC for service communication
    custom, // Custom crypto protocols
};

/// Connection priority levels for crypto workloads
pub const ConnectionPriority = enum {
    critical, // Trading orders, liquidations
    high, // Block propagation, consensus
    normal, // General queries, sync
    background, // Maintenance, analytics
};

/// Crypto workload patterns for optimization
pub const WorkloadPattern = enum {
    high_frequency_trading, // Many small, time-critical requests
    blockchain_sync, // Large data transfers
    defi_api, // Burst API calls
    consensus_voting, // Critical but infrequent
    mempool_gossip, // Moderate frequency, medium size
};

/// Connection pool configuration optimized for crypto
pub const CryptoConnectionPoolConfig = struct {
    // Pool sizing
    initial_pool_size: u32 = 20, // Higher initial for crypto
    max_pool_size: u32 = 10000, // Large for blockchain nodes
    min_pool_size: u32 = 10,
    
    // Timeouts optimized for crypto
    idle_timeout_ms: u64 = 60_000, // 1 minute for responsive scaling
    health_check_interval_ms: u64 = 5_000, // 5 seconds for crypto stability
    acquire_timeout_ms: u64 = 1_000, // 1 second for trading latency
    
    // Crypto-specific features
    enable_zero_rtt: bool = true,
    enable_post_quantum: bool = true,
    enable_connection_migration: bool = true,
    enable_priority_queuing: bool = true,
    
    // Performance optimizations
    enable_adaptive_scaling: bool = true,
    enable_load_balancing: bool = true,
    enable_burst_handling: bool = true,
    
    // Protocol multiplexing
    enable_protocol_multiplexing: bool = true,
    max_concurrent_protocols: u32 = 4, // DoQ, HTTP/3, gRPC, custom
};

/// Connection health metrics for crypto workloads
pub const ConnectionHealth = struct {
    latency_us: u64, // Microsecond latency
    packet_loss_rate: f32, // Loss percentage
    congestion_window: u64, // Current CWND
    bandwidth_estimate: u64, // bits/second
    zero_rtt_success_rate: f32, // 0-RTT success rate
    last_health_check: i64, // Timestamp
    consecutive_failures: u32, // Health check failures
    
    const Self = @This();
    
    pub fn isHealthy(self: *const Self) bool {
        return self.latency_us < 100_000 and // < 100ms
               self.packet_loss_rate < 0.05 and // < 5% loss
               self.consecutive_failures < 3;
    }
    
    pub fn getHealthScore(self: *const Self) f32 {
        var score: f32 = 1.0;
        
        // Latency factor (lower is better)
        if (self.latency_us > 10_000) { // > 10ms
            score *= 0.8;
        }
        if (self.latency_us > 50_000) { // > 50ms
            score *= 0.6;
        }
        
        // Loss factor
        score *= (1.0 - self.packet_loss_rate);
        
        // Failure factor
        if (self.consecutive_failures > 0) {
            score *= 1.0 / (@as(f32, @floatFromInt(self.consecutive_failures)) + 1.0);
        }
        
        return @max(score, 0.0);
    }
};

/// Multiplexed connection supporting multiple protocols
pub const MultiplexedConnection = struct {
    connection: *Connection,
    id: u64,
    created_at: i64,
    last_used: std.atomic.Atomic(i64),
    
    // Protocol support
    supported_protocols: std.EnumSet(ProtocolType),
    active_protocols: std.EnumSet(ProtocolType),
    protocol_streams: std.HashMap(ProtocolType, u64, std.hash_map.AutoContext(ProtocolType), std.hash_map.default_max_load_percentage),
    
    // Crypto features
    zero_rtt_context: ?ZeroRttContext,
    pq_tls_context: ?HybridPQTlsContext,
    supports_migration: bool,
    
    // Performance metrics
    health: ConnectionHealth,
    use_count: std.atomic.Atomic(u64),
    bytes_sent: std.atomic.Atomic(u64),
    bytes_received: std.atomic.Atomic(u64),
    requests_served: std.atomic.Atomic(u64),
    
    // State management
    reference_count: std.atomic.Atomic(u32),
    is_available: std.atomic.Atomic(bool),
    current_priority: std.atomic.Atomic(u8), // ConnectionPriority as u8
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, connection: *Connection, id: u64, protocols: std.EnumSet(ProtocolType)) !Self {
        const now = std.time.microTimestamp();
        
        return Self{
            .connection = connection,
            .id = id,
            .created_at = now,
            .last_used = std.atomic.Atomic(i64).init(now),
            .supported_protocols = protocols,
            .active_protocols = std.EnumSet(ProtocolType).initEmpty(),
            .protocol_streams = std.HashMap(ProtocolType, u64, std.hash_map.AutoContext(ProtocolType), std.hash_map.default_max_load_percentage).init(allocator),
            .zero_rtt_context = null,
            .pq_tls_context = null,
            .supports_migration = true,
            .health = ConnectionHealth{
                .latency_us = 0,
                .packet_loss_rate = 0.0,
                .congestion_window = 0,
                .bandwidth_estimate = 0,
                .zero_rtt_success_rate = 1.0,
                .last_health_check = now,
                .consecutive_failures = 0,
            },
            .use_count = std.atomic.Atomic(u64).init(0),
            .bytes_sent = std.atomic.Atomic(u64).init(0),
            .bytes_received = std.atomic.Atomic(u64).init(0),
            .requests_served = std.atomic.Atomic(u64).init(0),
            .reference_count = std.atomic.Atomic(u32).init(1),
            .is_available = std.atomic.Atomic(bool).init(true),
            .current_priority = std.atomic.Atomic(u8).init(@intFromEnum(ConnectionPriority.normal)),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.zero_rtt_context) |*ctx| {
            ctx.deinit();
        }
        if (self.pq_tls_context) |*ctx| {
            ctx.deinit();
        }
        self.protocol_streams.deinit();
    }
    
    /// Enable protocol on this connection
    pub fn enableProtocol(self: *Self, protocol: ProtocolType) !void {
        if (!self.supported_protocols.contains(protocol)) {
            return Error.ZquicError.UnsupportedProtocol;
        }
        
        self.active_protocols.insert(protocol);
        try self.protocol_streams.put(protocol, 0); // Start with stream 0
        
        std.log.info("Enabled protocol {} on connection {}", .{ protocol, self.id });
    }
    
    /// Get next stream ID for protocol
    pub fn getNextStreamId(self: *Self, protocol: ProtocolType) !u64 {
        if (!self.active_protocols.contains(protocol)) {
            return Error.ZquicError.ProtocolNotActive;
        }
        
        const entry = self.protocol_streams.getPtr(protocol) orelse return Error.ZquicError.ProtocolNotFound;
        const stream_id = entry.*;
        entry.* += 4; // QUIC stream ID increment
        
        return stream_id;
    }
    
    /// Update connection health metrics
    pub fn updateHealth(self: *Self, latency_us: u64, loss_rate: f32, cwnd: u64, bandwidth: u64) void {
        self.health.latency_us = latency_us;
        self.health.packet_loss_rate = loss_rate;
        self.health.congestion_window = cwnd;
        self.health.bandwidth_estimate = bandwidth;
        self.health.last_health_check = std.time.microTimestamp();
        
        // Reset failure count on successful health update
        if (self.health.isHealthy()) {
            self.health.consecutive_failures = 0;
        }
    }
    
    /// Mark connection as used for specific priority
    pub fn markUsed(self: *Self, priority: ConnectionPriority) void {
        _ = self.last_used.store(std.time.microTimestamp(), .Monotonic);
        _ = self.use_count.fetchAdd(1, .Monotonic);
        _ = self.requests_served.fetchAdd(1, .Monotonic);
        _ = self.current_priority.store(@intFromEnum(priority), .Monotonic);
    }
    
    /// Check if connection can handle new requests
    pub fn canAcceptRequest(self: *const Self, protocol: ProtocolType, priority: ConnectionPriority) bool {
        _ = priority;
        
        if (!self.is_available.load(.Monotonic)) return false;
        if (!self.active_protocols.contains(protocol)) return false;
        if (!self.health.isHealthy()) return false;
        
        // Check if connection is overloaded
        const current_load = self.use_count.load(.Monotonic);
        return current_load < 1000; // Max concurrent requests per connection
    }
    
    /// Get connection efficiency score for load balancing
    pub fn getEfficiencyScore(self: *const Self) f32 {
        const health_score = self.health.getHealthScore();
        const load_factor = 1.0 - (@as(f32, @floatFromInt(self.use_count.load(.Monotonic))) / 1000.0);
        const age_factor = 1.0 - (@as(f32, @floatFromInt(std.time.microTimestamp() - self.created_at)) / 3600_000_000.0); // 1 hour
        
        return health_score * load_factor * @max(age_factor, 0.1);
    }
};

/// High-performance connection multiplexer for crypto workloads
pub const CryptoConnectionMultiplexer = struct {
    config: CryptoConnectionPoolConfig,
    
    // Connection management
    connections: std.ArrayList(*MultiplexedConnection),
    connection_map: std.HashMap(u64, *MultiplexedConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_connection_id: std.atomic.Atomic(u64),
    
    // Protocol-specific pools
    protocol_pools: std.EnumMap(ProtocolType, std.ArrayList(*MultiplexedConnection)),
    
    // Priority queues for load balancing
    priority_queues: std.EnumMap(ConnectionPriority, std.ArrayList(*MultiplexedConnection)),
    
    // Statistics
    total_connections: std.atomic.Atomic(u32),
    active_connections: std.atomic.Atomic(u32),
    connections_created: std.atomic.Atomic(u64),
    connections_destroyed: std.atomic.Atomic(u64),
    protocol_requests: std.EnumMap(ProtocolType, std.atomic.Atomic(u64)),
    
    // Synchronization
    pool_mutex: std.Thread.Mutex,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, config: CryptoConnectionPoolConfig) Self {
        var multiplexer = Self{
            .config = config,
            .connections = std.ArrayList(*MultiplexedConnection).init(allocator),
            .connection_map = std.HashMap(u64, *MultiplexedConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_connection_id = std.atomic.Atomic(u64).init(1),
            .protocol_pools = std.EnumMap(ProtocolType, std.ArrayList(*MultiplexedConnection)).init(.{}),
            .priority_queues = std.EnumMap(ConnectionPriority, std.ArrayList(*MultiplexedConnection)).init(.{}),
            .total_connections = std.atomic.Atomic(u32).init(0),
            .active_connections = std.atomic.Atomic(u32).init(0),
            .connections_created = std.atomic.Atomic(u64).init(0),
            .connections_destroyed = std.atomic.Atomic(u64).init(0),
            .protocol_requests = std.EnumMap(ProtocolType, std.atomic.Atomic(u64)).init(.{}),
            .pool_mutex = std.Thread.Mutex{},
            .allocator = allocator,
        };
        
        // Initialize protocol pools
        var protocol_iter = std.enums.values(ProtocolType);
        while (protocol_iter.next()) |protocol| {
            multiplexer.protocol_pools.put(protocol, std.ArrayList(*MultiplexedConnection).init(allocator));
            multiplexer.protocol_requests.put(protocol, std.atomic.Atomic(u64).init(0));
        }
        
        // Initialize priority queues
        var priority_iter = std.enums.values(ConnectionPriority);
        while (priority_iter.next()) |priority| {
            multiplexer.priority_queues.put(priority, std.ArrayList(*MultiplexedConnection).init(allocator));
        }
        
        return multiplexer;
    }
    
    pub fn deinit(self: *Self) void {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();
        
        // Clean up all connections
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        
        self.connections.deinit();
        self.connection_map.deinit();
        
        // Clean up protocol pools
        var protocol_iter = std.enums.values(ProtocolType);
        while (protocol_iter.next()) |protocol| {
            self.protocol_pools.getPtr(protocol).?.deinit();
        }
        
        // Clean up priority queues
        var priority_iter = std.enums.values(ConnectionPriority);
        while (priority_iter.next()) |priority| {
            self.priority_queues.getPtr(priority).?.deinit();
        }
    }
    
    /// Acquire connection for specific protocol and priority
    pub fn acquireConnection(self: *Self, protocol: ProtocolType, priority: ConnectionPriority, workload: WorkloadPattern) !*MultiplexedConnection {
        _ = self.protocol_requests.getPtr(protocol).?.fetchAdd(1, .Monotonic);
        
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();
        
        // Try to find existing suitable connection
        if (self.findBestConnection(protocol, priority, workload)) |conn| {
            conn.markUsed(priority);
            return conn;
        }
        
        // Create new connection if needed and allowed
        if (self.total_connections.load(.Monotonic) < self.config.max_pool_size) {
            return try self.createConnection(protocol, priority, workload);
        }
        
        return Error.ZquicError.PoolExhausted;
    }
    
    /// Find best available connection for request
    fn findBestConnection(self: *Self, protocol: ProtocolType, priority: ConnectionPriority, workload: WorkloadPattern) ?*MultiplexedConnection {
        _ = workload;
        
        var best_connection: ?*MultiplexedConnection = null;
        var best_score: f32 = 0.0;
        
        // Check protocol-specific pool first
        const protocol_pool = self.protocol_pools.getPtr(protocol).?;
        for (protocol_pool.items) |conn| {
            if (conn.canAcceptRequest(protocol, priority)) {
                const score = conn.getEfficiencyScore();
                if (score > best_score) {
                    best_score = score;
                    best_connection = conn;
                }
            }
        }
        
        // Check priority queue if no protocol-specific connection found
        if (best_connection == null) {
            const priority_queue = self.priority_queues.getPtr(priority).?;
            for (priority_queue.items) |conn| {
                if (conn.canAcceptRequest(protocol, priority)) {
                    const score = conn.getEfficiencyScore();
                    if (score > best_score) {
                        best_score = score;
                        best_connection = conn;
                    }
                }
            }
        }
        
        return best_connection;
    }
    
    /// Create new multiplexed connection
    fn createConnection(self: *Self, protocol: ProtocolType, priority: ConnectionPriority, workload: WorkloadPattern) !*MultiplexedConnection {
        const connection_id = self.next_connection_id.fetchAdd(1, .Monotonic);
        
        // Create underlying QUIC connection (simplified)
        const quic_connection = try self.allocator.create(Connection);
        // TODO: Initialize actual QUIC connection with crypto features
        
        // Determine supported protocols based on workload
        var supported_protocols = std.EnumSet(ProtocolType).initEmpty();
        supported_protocols.insert(protocol);
        
        // Add additional protocols for multiplexing
        if (self.config.enable_protocol_multiplexing) {
            switch (workload) {
                .high_frequency_trading => {
                    supported_protocols.insert(.dns_over_quic);
                    supported_protocols.insert(.custom);
                },
                .blockchain_sync => {
                    supported_protocols.insert(.http3);
                    supported_protocols.insert(.grpc_over_quic);
                },
                .defi_api => {
                    supported_protocols.insert(.http3);
                    supported_protocols.insert(.dns_over_quic);
                },
                .consensus_voting => {
                    supported_protocols.insert(.grpc_over_quic);
                    supported_protocols.insert(.custom);
                },
                .mempool_gossip => {
                    supported_protocols.insert(.grpc_over_quic);
                    supported_protocols.insert(.http3);
                },
            }
        }
        
        // Create multiplexed connection
        const mux_conn = try self.allocator.create(MultiplexedConnection);
        mux_conn.* = try MultiplexedConnection.init(self.allocator, quic_connection, connection_id, supported_protocols);
        
        // Configure crypto features
        if (self.config.enable_zero_rtt) {
            mux_conn.zero_rtt_context = ZeroRttContext.init(self.allocator);
        }
        
        if (self.config.enable_post_quantum) {
            // TODO: Initialize PQ-TLS context
        }
        
        // Enable requested protocol
        try mux_conn.enableProtocol(protocol);
        
        // Add to pools
        try self.connections.append(mux_conn);
        try self.connection_map.put(connection_id, mux_conn);
        try self.protocol_pools.getPtr(protocol).?.append(mux_conn);
        try self.priority_queues.getPtr(priority).?.append(mux_conn);
        
        // Update statistics
        _ = self.total_connections.fetchAdd(1, .Monotonic);
        _ = self.active_connections.fetchAdd(1, .Monotonic);
        _ = self.connections_created.fetchAdd(1, .Monotonic);
        
        mux_conn.markUsed(priority);
        
        std.log.info("Created new multiplexed connection {} for protocol {} with priority {}", .{ connection_id, protocol, priority });
        
        return mux_conn;
    }
    
    /// Release connection back to pool
    pub fn releaseConnection(self: *Self, conn: *MultiplexedConnection) void {
        _ = conn.reference_count.fetchSub(1, .Monotonic);
        
        // Connection is still in use by others
        if (conn.reference_count.load(.Monotonic) > 0) {
            return;
        }
        
        // Mark as available for reuse
        _ = conn.is_available.store(true, .Monotonic);
        
        std.log.debug("Released connection {} back to pool", .{conn.id});
    }
    
    /// Perform health checks and cleanup
    pub fn performMaintenance(self: *Self) !void {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();
        
        const now = std.time.microTimestamp();
        var connections_to_remove = std.ArrayList(usize).init(self.allocator);
        defer connections_to_remove.deinit();
        
        // Check each connection
        for (self.connections.items, 0..) |conn, i| {
            const idle_time = now - conn.last_used.load(.Monotonic);
            
            // Remove idle connections
            if (idle_time > self.config.idle_timeout_ms * 1000) {
                try connections_to_remove.append(i);
                continue;
            }
            
            // Perform health check
            self.performHealthCheck(conn);
            
            // Remove unhealthy connections
            if (!conn.health.isHealthy() and conn.health.consecutive_failures > 5) {
                try connections_to_remove.append(i);
            }
        }
        
        // Remove marked connections in reverse order
        std.mem.reverse(usize, connections_to_remove.items);
        for (connections_to_remove.items) |index| {
            const conn = self.connections.orderedRemove(index);
            self.removeConnectionFromPools(conn);
            conn.deinit();
            self.allocator.destroy(conn);
            
            _ = self.total_connections.fetchSub(1, .Monotonic);
            _ = self.connections_destroyed.fetchAdd(1, .Monotonic);
        }
        
        std.log.info("Maintenance completed: removed {} idle/unhealthy connections", .{connections_to_remove.items.len});
    }
    
    /// Perform health check on connection
    fn performHealthCheck(self: *Self, conn: *MultiplexedConnection) void {
        _ = self;
        // TODO: Implement actual health check logic
        // For now, simulate basic health check
        
        // Update health metrics (simplified)
        const random_latency = 10_000 + (std.crypto.random.int(u32) % 50_000); // 10-60ms
        const random_loss = @as(f32, @floatFromInt(std.crypto.random.int(u8) % 10)) / 100.0; // 0-10%
        
        conn.updateHealth(random_latency, random_loss, 65536, 100_000_000);
        
        if (!conn.health.isHealthy()) {
            conn.health.consecutive_failures += 1;
        }
    }
    
    /// Remove connection from all pools
    fn removeConnectionFromPools(self: *Self, conn: *MultiplexedConnection) void {
        _ = self.connection_map.remove(conn.id);
        
        // Remove from protocol pools
        var protocol_iter = std.enums.values(ProtocolType);
        while (protocol_iter.next()) |protocol| {
            const pool = self.protocol_pools.getPtr(protocol).?;
            for (pool.items, 0..) |pool_conn, i| {
                if (pool_conn.id == conn.id) {
                    _ = pool.orderedRemove(i);
                    break;
                }
            }
        }
        
        // Remove from priority queues
        var priority_iter = std.enums.values(ConnectionPriority);
        while (priority_iter.next()) |priority| {
            const queue = self.priority_queues.getPtr(priority).?;
            for (queue.items, 0..) |queue_conn, i| {
                if (queue_conn.id == conn.id) {
                    _ = queue.orderedRemove(i);
                    break;
                }
            }
        }
    }
    
    /// Get multiplexer statistics
    pub fn getStats(self: *const Self) struct {
        total_connections: u32,
        active_connections: u32,
        connections_created: u64,
        connections_destroyed: u64,
        protocol_requests: std.EnumMap(ProtocolType, u64),
        avg_efficiency_score: f32,
        pool_utilization: f32,
    } {
        var protocol_req_map = std.EnumMap(ProtocolType, u64).init(.{});
        var total_efficiency: f32 = 0.0;
        var healthy_connections: u32 = 0;
        
        // Calculate protocol requests and efficiency
        var protocol_iter = std.enums.values(ProtocolType);
        while (protocol_iter.next()) |protocol| {
            protocol_req_map.put(protocol, self.protocol_requests.get(protocol).?.load(.Monotonic));
        }
        
        self.pool_mutex.lock();
        for (self.connections.items) |conn| {
            if (conn.health.isHealthy()) {
                total_efficiency += conn.getEfficiencyScore();
                healthy_connections += 1;
            }
        }
        self.pool_mutex.unlock();
        
        const avg_efficiency = if (healthy_connections > 0) total_efficiency / @as(f32, @floatFromInt(healthy_connections)) else 0.0;
        const utilization = @as(f32, @floatFromInt(self.total_connections.load(.Monotonic))) / @as(f32, @floatFromInt(self.config.max_pool_size));
        
        return .{
            .total_connections = self.total_connections.load(.Monotonic),
            .active_connections = self.active_connections.load(.Monotonic),
            .connections_created = self.connections_created.load(.Monotonic),
            .connections_destroyed = self.connections_destroyed.load(.Monotonic),
            .protocol_requests = protocol_req_map,
            .avg_efficiency_score = avg_efficiency,
            .pool_utilization = utilization,
        };
    }
};