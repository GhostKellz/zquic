//! Crypto-Optimized Connection Multiplexer for ZQUIC
//!
//! High-performance connection pooling and multiplexing specifically designed for
//! crypto/blockchain workloads with support for DoQ, HTTP/3, and gRPC-over-QUIC

const std = @import("std");
const Time = @import("../utils/time.zig");
const Error = @import("../utils/error.zig");
const SpinMutex = @import("../utils/sync.zig").SpinMutex;
const Connection = @import("../core/connection.zig").Connection;
const zero_rtt = @import("../crypto/zero_rtt_resumption.zig");
const ZeroRttContext = zero_rtt.ZeroRttContext;
const SessionTicket = zero_rtt.SessionTicket;
const TicketIssuer = zero_rtt.TicketIssuer;
const TicketIssuerMaterial = zero_rtt.TicketIssuerMaterial;
const TicketIssuerRing = zero_rtt.TicketIssuerRing;
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

/// Lifecycle state for experimental post-quantum pooled connections.
pub const PQPoolState = enum(u8) {
    disabled,
    keypair_ready,
    handshake_pending,
    established,
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
    enable_post_quantum: bool = false, // Experimental: requires -Dpost-quantum=true -Dexperimental-crypto=true
    allow_zero_rtt_with_post_quantum: bool = false,
    pq_ticket_issuer: ?TicketIssuerMaterial = null,
    pq_previous_ticket_issuer: ?TicketIssuerMaterial = null,
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
    last_used: std.atomic.Value(i64),

    // Protocol support
    supported_protocols: std.EnumSet(ProtocolType),
    active_protocols: std.EnumSet(ProtocolType),
    protocol_streams: std.HashMap(ProtocolType, u64, std.hash_map.AutoContext(ProtocolType), std.hash_map.default_max_load_percentage),

    // Crypto features
    zero_rtt_context: ?ZeroRttContext,
    pq_tls_context: ?HybridPQTlsContext,
    pq_resumption_ticket: ?SessionTicket,
    pq_pool_state: PQPoolState,
    supports_migration: bool,

    // Performance metrics
    health: ConnectionHealth,
    use_count: std.atomic.Value(u64),
    bytes_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),
    requests_served: std.atomic.Value(u64),

    // State management
    reference_count: std.atomic.Value(u32),
    is_available: std.atomic.Value(bool),
    current_priority: std.atomic.Value(u8), // ConnectionPriority as u8

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, connection: *Connection, id: u64, protocols: std.EnumSet(ProtocolType)) !Self {
        const now = Time.nowMicros();

        return Self{
            .connection = connection,
            .id = id,
            .created_at = now,
            .last_used = std.atomic.Value(i64).init(now),
            .supported_protocols = protocols,
            .active_protocols = .empty,
            .protocol_streams = std.HashMap(ProtocolType, u64, std.hash_map.AutoContext(ProtocolType), std.hash_map.default_max_load_percentage).init(allocator),
            .zero_rtt_context = null,
            .pq_tls_context = null,
            .pq_resumption_ticket = null,
            .pq_pool_state = .disabled,
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
            .use_count = std.atomic.Value(u64).init(0),
            .bytes_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),
            .requests_served = std.atomic.Value(u64).init(0),
            .reference_count = std.atomic.Value(u32).init(0),
            .is_available = std.atomic.Value(bool).init(true),
            .current_priority = std.atomic.Value(u8).init(@intFromEnum(ConnectionPriority.normal)),
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
        if (self.pq_resumption_ticket) |*ticket| {
            std.crypto.secureZero(u8, std.mem.asBytes(&ticket.resumption_secret));
            std.crypto.secureZero(u8, std.mem.asBytes(&ticket.pq_binder));
            std.crypto.secureZero(u8, std.mem.asBytes(&ticket.ticket_mac));
        }
        self.connection.deinit();
        self.allocator.destroy(self.connection);
        self.protocol_streams.deinit();
    }

    pub fn enablePostQuantum(self: *Self) !void {
        if (self.pq_tls_context != null) {
            self.pq_pool_state = .keypair_ready;
            return;
        }

        self.pq_tls_context = try HybridPQTlsContext.init(self.allocator, false, .{
            .enable_ml_kem = true,
            .enable_x25519 = true,
            .prefer_pq = true,
            .fallback_to_classical = false,
        });
        try self.pq_tls_context.?.initializeHandshake();
        self.pq_pool_state = .keypair_ready;
    }

    pub fn isPostQuantumCapable(self: *const Self) bool {
        return self.pq_tls_context != null and self.pq_pool_state != .disabled;
    }

    pub fn issuePostQuantumResumptionTicket(self: *Self, issuer: *const TicketIssuer, allow_early_data: bool) !SessionTicket {
        const ctx = &(self.pq_tls_context orelse return Error.ZquicError.InvalidState);
        const hybrid_secret = ctx.hybrid_kx.getSharedSecret();
        const binder = self.computePostQuantumBinder();
        const ticket = SessionTicket.createPostQuantum(issuer, hybrid_secret, binder, 86_400, allow_early_data);
        self.pq_resumption_ticket = ticket;
        self.pq_pool_state = .established;
        return ticket;
    }

    pub fn validatePostQuantumResumptionTicket(self: *const Self, issuers: *const TicketIssuerRing, ticket: SessionTicket, allow_early_data: bool) bool {
        const expected_policy: zero_rtt.ResumptionPolicy = if (allow_early_data) .hybrid_pq_early_data else .hybrid_pq_no_early_data;
        return ticket.isValid() and
            ticket.isAuthenticInRing(issuers) and
            ticket.matchesPolicy(expected_policy) and
            ticket.matchesPostQuantumBinder(self.computePostQuantumBinder());
    }

    pub fn canReuseForPostQuantumPool(self: *const Self, issuers: *const TicketIssuerRing, allow_early_data: bool, require_migration: bool) bool {
        if (!self.isPostQuantumCapable()) return false;
        if (self.pq_pool_state != .established) return false;
        if (require_migration and !self.supports_migration) return false;
        if (!allow_early_data and self.zero_rtt_context != null) return false;
        const ticket = self.pq_resumption_ticket orelse return false;
        return self.validatePostQuantumResumptionTicket(issuers, ticket, allow_early_data);
    }

    fn computePostQuantumBinder(self: *const Self) [32]u8 {
        var input: [64]u8 = undefined;
        std.mem.writeInt(u64, input[0..8], self.id, .big);
        @memset(input[8..], 0);
        if (self.pq_tls_context) |ctx| {
            const pk = ctx.hybrid_kx.ml_kem_public[0..@min(ctx.hybrid_kx.ml_kem_public.len, 32)];
            @memcpy(input[32..][0..pk.len], pk);
        }
        return zcryptoHash(&input);
    }

    /// Enable protocol on this connection
    pub fn enableProtocol(self: *Self, protocol: ProtocolType) !void {
        if (!self.supported_protocols.contains(protocol)) {
            return Error.ZquicError.NotSupported;
        }

        self.active_protocols.insert(protocol);
        try self.protocol_streams.put(protocol, 0); // Start with stream 0

        std.log.info("Enabled protocol {} on connection {}", .{ protocol, self.id });
    }

    /// Get next stream ID for protocol
    pub fn getNextStreamId(self: *Self, protocol: ProtocolType) !u64 {
        if (!self.active_protocols.contains(protocol)) {
            return Error.ZquicError.InvalidState;
        }

        const entry = self.protocol_streams.getPtr(protocol) orelse return Error.ZquicError.InvalidState;
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
        self.health.last_health_check = Time.nowMicros();

        // Reset failure count on successful health update
        if (self.health.isHealthy()) {
            self.health.consecutive_failures = 0;
        }
    }

    /// Mark connection as used for specific priority
    pub fn markUsed(self: *Self, priority: ConnectionPriority) void {
        _ = self.last_used.store(Time.nowMicros(), .monotonic);
        _ = self.reference_count.fetchAdd(1, .monotonic);
        _ = self.use_count.fetchAdd(1, .monotonic);
        _ = self.requests_served.fetchAdd(1, .monotonic);
        _ = self.current_priority.store(@intFromEnum(priority), .monotonic);
    }

    /// Check if connection can handle new requests
    pub fn canAcceptRequest(self: *const Self, protocol: ProtocolType, priority: ConnectionPriority) bool {
        _ = priority;

        if (!self.is_available.load(.monotonic)) return false;
        if (!self.active_protocols.contains(protocol)) return false;
        if (!self.health.isHealthy()) return false;

        // Check if connection is overloaded
        const current_load = self.use_count.load(.monotonic);
        return current_load < 1000; // Max concurrent requests per connection
    }

    /// Get connection efficiency score for load balancing
    pub fn getEfficiencyScore(self: *const Self) f32 {
        const health_score = self.health.getHealthScore();
        const load_factor = 1.0 - (@as(f32, @floatFromInt(self.use_count.load(.monotonic))) / 1000.0);
        const age_factor = 1.0 - (@as(f32, @floatFromInt(Time.nowMicros() - self.created_at)) / 3600_000_000.0); // 1 hour

        return health_score * load_factor * @max(age_factor, 0.1);
    }
};

/// High-performance connection multiplexer for crypto workloads
pub const CryptoConnectionMultiplexer = struct {
    config: CryptoConnectionPoolConfig,

    // Connection management
    connections: std.ArrayList(*MultiplexedConnection),
    connection_map: std.HashMap(u64, *MultiplexedConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_connection_id: std.atomic.Value(u64),

    // Protocol-specific pools
    protocol_pools: std.EnumMap(ProtocolType, std.ArrayList(*MultiplexedConnection)),

    // Priority queues for load balancing
    priority_queues: std.EnumMap(ConnectionPriority, std.ArrayList(*MultiplexedConnection)),

    // Statistics
    total_connections: std.atomic.Value(u32),
    active_connections: std.atomic.Value(u32),
    connections_created: std.atomic.Value(u64),
    connections_destroyed: std.atomic.Value(u64),
    pq_connections_active: std.atomic.Value(u32),
    pq_connections_created: std.atomic.Value(u64),
    pq_zero_rtt_suppressed: std.atomic.Value(u64),
    protocol_requests: std.EnumMap(ProtocolType, std.atomic.Value(u64)),
    pq_ticket_issuers: TicketIssuerRing,

    // Synchronization
    pool_mutex: SpinMutex,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: CryptoConnectionPoolConfig) Self {
        var multiplexer = Self{
            .config = config,
            .connections = .empty,
            .connection_map = std.HashMap(u64, *MultiplexedConnection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_connection_id = std.atomic.Value(u64).init(1),
            .protocol_pools = std.EnumMap(ProtocolType, std.ArrayList(*MultiplexedConnection)).init(.{}),
            .priority_queues = std.EnumMap(ConnectionPriority, std.ArrayList(*MultiplexedConnection)).init(.{}),
            .total_connections = std.atomic.Value(u32).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .connections_created = std.atomic.Value(u64).init(0),
            .connections_destroyed = std.atomic.Value(u64).init(0),
            .pq_connections_active = std.atomic.Value(u32).init(0),
            .pq_connections_created = std.atomic.Value(u64).init(0),
            .pq_zero_rtt_suppressed = std.atomic.Value(u64).init(0),
            .protocol_requests = std.EnumMap(ProtocolType, std.atomic.Value(u64)).init(.{}),
            .pq_ticket_issuers = if (config.pq_ticket_issuer) |active|
                TicketIssuerRing.initFromMaterial(active, config.pq_previous_ticket_issuer)
            else
                TicketIssuerRing.initRandom(),
            .pool_mutex = .{},
            .allocator = allocator,
        };

        // Initialize protocol pools
        for (std.enums.values(ProtocolType)) |protocol| {
            multiplexer.protocol_pools.put(protocol, .empty);
            multiplexer.protocol_requests.put(protocol, std.atomic.Value(u64).init(0));
        }

        // Initialize priority queues
        for (std.enums.values(ConnectionPriority)) |priority| {
            multiplexer.priority_queues.put(priority, .empty);
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

        self.connections.deinit(self.allocator);
        self.connection_map.deinit();

        // Clean up protocol pools
        for (std.enums.values(ProtocolType)) |protocol| {
            self.protocol_pools.getPtr(protocol).?.deinit(self.allocator);
        }

        // Clean up priority queues
        for (std.enums.values(ConnectionPriority)) |priority| {
            self.priority_queues.getPtr(priority).?.deinit(self.allocator);
        }

        self.pq_ticket_issuers.deinit();
    }

    /// Acquire connection for specific protocol and priority
    pub fn acquireConnection(self: *Self, protocol: ProtocolType, priority: ConnectionPriority, workload: WorkloadPattern) !*MultiplexedConnection {
        _ = self.protocol_requests.getPtr(protocol).?.fetchAdd(1, .monotonic);

        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        // Try to find existing suitable connection
        if (self.findBestConnection(protocol, priority, workload)) |conn| {
            conn.markUsed(priority);
            return conn;
        }

        // Create new connection if needed and allowed
        if (self.total_connections.load(.monotonic) < self.config.max_pool_size) {
            return try self.createConnection(protocol, priority, workload);
        }

        return Error.ZquicError.ResourceExhausted;
    }

    /// Find best available connection for request
    fn findBestConnection(self: *Self, protocol: ProtocolType, priority: ConnectionPriority, workload: WorkloadPattern) ?*MultiplexedConnection {
        _ = workload;

        var best_connection: ?*MultiplexedConnection = null;
        var best_score: f32 = 0.0;

        // Check protocol-specific pool first
        const protocol_pool = self.protocol_pools.getPtr(protocol).?;
        for (protocol_pool.items) |conn| {
            if (self.config.enable_post_quantum and !conn.canReuseForPostQuantumPool(&self.pq_ticket_issuers, self.config.allow_zero_rtt_with_post_quantum, self.config.enable_connection_migration)) continue;
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
                if (self.config.enable_post_quantum and !conn.canReuseForPostQuantumPool(&self.pq_ticket_issuers, self.config.allow_zero_rtt_with_post_quantum, self.config.enable_connection_migration)) continue;
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
        const connection_id = self.next_connection_id.fetchAdd(1, .monotonic);

        // Create underlying QUIC connection (simplified)
        const quic_connection = try self.allocator.create(Connection);
        var connection_owned_by_mux = false;
        errdefer if (!connection_owned_by_mux) self.allocator.destroy(quic_connection);
        quic_connection.* = try Connection.init(self.allocator, .client, .{});
        errdefer if (!connection_owned_by_mux) quic_connection.deinit();

        // Determine supported protocols based on workload
        var supported_protocols: std.EnumSet(ProtocolType) = .empty;
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
        errdefer self.allocator.destroy(mux_conn);
        mux_conn.* = try MultiplexedConnection.init(self.allocator, quic_connection, connection_id, supported_protocols);
        connection_owned_by_mux = true;
        errdefer mux_conn.deinit();

        // Configure crypto features
        if (self.config.enable_post_quantum) {
            try mux_conn.enablePostQuantum();
            mux_conn.supports_migration = false;
            _ = self.pq_connections_active.fetchAdd(1, .monotonic);
            _ = self.pq_connections_created.fetchAdd(1, .monotonic);

            if (self.config.enable_zero_rtt and !self.config.allow_zero_rtt_with_post_quantum) {
                _ = self.pq_zero_rtt_suppressed.fetchAdd(1, .monotonic);
            } else if (self.config.enable_zero_rtt) {
                mux_conn.zero_rtt_context = ZeroRttContext.init(self.allocator);
            }
            _ = try mux_conn.issuePostQuantumResumptionTicket(self.pq_ticket_issuers.signer(), self.config.allow_zero_rtt_with_post_quantum);
        } else if (self.config.enable_zero_rtt) {
            mux_conn.zero_rtt_context = ZeroRttContext.init(self.allocator);
        }

        // Enable requested protocol
        try mux_conn.enableProtocol(protocol);

        // Add to pools
        try self.connections.append(self.allocator, mux_conn);
        try self.connection_map.put(connection_id, mux_conn);
        try self.protocol_pools.getPtr(protocol).?.append(self.allocator, mux_conn);
        try self.priority_queues.getPtr(priority).?.append(self.allocator, mux_conn);

        // Update statistics
        _ = self.total_connections.fetchAdd(1, .monotonic);
        _ = self.active_connections.fetchAdd(1, .monotonic);
        _ = self.connections_created.fetchAdd(1, .monotonic);

        mux_conn.markUsed(priority);

        std.log.info("Created new multiplexed connection {} for protocol {} with priority {}", .{ connection_id, protocol, priority });

        return mux_conn;
    }

    /// Release connection back to pool
    pub fn releaseConnection(self: *Self, conn: *MultiplexedConnection) void {
        _ = self;
        _ = conn.reference_count.fetchSub(1, .monotonic);

        // Connection is still in use by others
        if (conn.reference_count.load(.monotonic) > 0) {
            return;
        }

        // Mark as available for reuse
        _ = conn.is_available.store(true, .monotonic);

        std.log.debug("Released connection {} back to pool", .{conn.id});
    }

    /// Perform health checks and cleanup
    pub fn performMaintenance(self: *Self) !void {
        self.pool_mutex.lock();
        defer self.pool_mutex.unlock();

        const now = Time.nowMicros();
        var connections_to_remove: std.ArrayList(usize) = .empty;
        defer connections_to_remove.deinit(self.allocator);

        // Check each connection
        for (self.connections.items, 0..) |conn, i| {
            const idle_time = now - conn.last_used.load(.monotonic);

            // Remove idle connections
            if (idle_time > self.config.idle_timeout_ms * 1000) {
                try connections_to_remove.append(self.allocator, i);
                continue;
            }

            // Perform health check
            self.performHealthCheck(conn);

            // Remove unhealthy connections
            if (!conn.health.isHealthy() and conn.health.consecutive_failures > 5) {
                try connections_to_remove.append(self.allocator, i);
            }
        }

        // Remove marked connections in reverse order
        std.mem.reverse(usize, connections_to_remove.items);
        for (connections_to_remove.items) |index| {
            const conn = self.connections.orderedRemove(index);
            const was_pq = conn.isPostQuantumCapable();
            self.removeConnectionFromPools(conn);
            conn.deinit();
            self.allocator.destroy(conn);

            _ = self.total_connections.fetchSub(1, .monotonic);
            _ = self.active_connections.fetchSub(1, .monotonic);
            if (was_pq) _ = self.pq_connections_active.fetchSub(1, .monotonic);
            _ = self.connections_destroyed.fetchAdd(1, .monotonic);
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
        for (std.enums.values(ProtocolType)) |protocol| {
            const pool = self.protocol_pools.getPtr(protocol).?;
            for (pool.items, 0..) |pool_conn, i| {
                if (pool_conn.id == conn.id) {
                    _ = pool.orderedRemove(i);
                    break;
                }
            }
        }

        // Remove from priority queues
        for (std.enums.values(ConnectionPriority)) |priority| {
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
    pub fn getStats(self: *Self) struct {
        total_connections: u32,
        active_connections: u32,
        connections_created: u64,
        connections_destroyed: u64,
        pq_connections_active: u32,
        pq_connections_created: u64,
        pq_zero_rtt_suppressed: u64,
        protocol_requests: std.EnumMap(ProtocolType, u64),
        avg_efficiency_score: f32,
        pool_utilization: f32,
    } {
        var protocol_req_map = std.EnumMap(ProtocolType, u64).init(.{});
        var total_efficiency: f32 = 0.0;
        var healthy_connections: u32 = 0;

        // Calculate protocol requests and efficiency
        for (std.enums.values(ProtocolType)) |protocol| {
            protocol_req_map.put(protocol, self.protocol_requests.get(protocol).?.load(.monotonic));
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
        const utilization = @as(f32, @floatFromInt(self.total_connections.load(.monotonic))) / @as(f32, @floatFromInt(self.config.max_pool_size));

        return .{
            .total_connections = self.total_connections.load(.monotonic),
            .active_connections = self.active_connections.load(.monotonic),
            .connections_created = self.connections_created.load(.monotonic),
            .connections_destroyed = self.connections_destroyed.load(.monotonic),
            .pq_connections_active = self.pq_connections_active.load(.monotonic),
            .pq_connections_created = self.pq_connections_created.load(.monotonic),
            .pq_zero_rtt_suppressed = self.pq_zero_rtt_suppressed.load(.monotonic),
            .protocol_requests = protocol_req_map,
            .avg_efficiency_score = avg_efficiency,
            .pool_utilization = utilization,
        };
    }
};

fn zcryptoHash(data: []const u8) [32]u8 {
    return @import("zcrypto").hash.sha256(data);
}

test "crypto multiplexer creates PQ-capable pooled connections" {
    const allocator = std.testing.allocator;
    var mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
    });
    defer mux.deinit();

    const conn = try mux.acquireConnection(.http3, .normal, .defi_api);
    defer mux.releaseConnection(conn);

    try std.testing.expect(conn.isPostQuantumCapable());
    try std.testing.expect(conn.pq_tls_context != null);
    try std.testing.expectEqual(PQPoolState.established, conn.pq_pool_state);
    try std.testing.expect(conn.pq_resumption_ticket != null);
    try std.testing.expect(conn.validatePostQuantumResumptionTicket(&mux.pq_ticket_issuers, conn.pq_resumption_ticket.?, false));
    try std.testing.expect(conn.zero_rtt_context == null);

    const stats = mux.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.total_connections);
    try std.testing.expectEqual(@as(u64, 1), stats.connections_created);
    try std.testing.expectEqual(@as(u32, 1), stats.pq_connections_active);
    try std.testing.expectEqual(@as(u64, 1), stats.pq_connections_created);
    try std.testing.expectEqual(@as(u64, 1), stats.pq_zero_rtt_suppressed);
}

test "crypto multiplexer rejects forged PQ resumption tickets" {
    const allocator = std.testing.allocator;
    var mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
    });
    defer mux.deinit();

    const conn = try mux.acquireConnection(.http3, .normal, .defi_api);
    defer mux.releaseConnection(conn);

    const ticket = conn.pq_resumption_ticket.?;
    try std.testing.expect(conn.validatePostQuantumResumptionTicket(&mux.pq_ticket_issuers, ticket, false));

    var forged_mac = ticket;
    forged_mac.ticket_mac[0] ^= 0x7F;
    try std.testing.expect(!conn.validatePostQuantumResumptionTicket(&mux.pq_ticket_issuers, forged_mac, false));

    var forged_binder = ticket;
    forged_binder.pq_binder[0] ^= 0x7F;
    try std.testing.expect(!conn.validatePostQuantumResumptionTicket(&mux.pq_ticket_issuers, forged_binder, false));

    var unrelated_issuers = TicketIssuerRing.initRandom();
    defer unrelated_issuers.deinit();
    try std.testing.expect(!conn.validatePostQuantumResumptionTicket(&unrelated_issuers, ticket, false));
}

test "crypto multiplexer supports configured PQ ticket issuer rotation" {
    const allocator = std.testing.allocator;
    const old_key_id: [8]u8 = @splat(0x41);
    const old_mac_key: [32]u8 = @splat(0x42);
    const new_key_id: [8]u8 = @splat(0x43);
    const new_mac_key: [32]u8 = @splat(0x44);
    const old_material = TicketIssuerMaterial.init(old_key_id, old_mac_key);
    const new_material = TicketIssuerMaterial.init(new_key_id, new_mac_key);

    var old_mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
        .pq_ticket_issuer = old_material,
    });
    defer old_mux.deinit();

    const old_conn = try old_mux.acquireConnection(.http3, .normal, .defi_api);
    defer old_mux.releaseConnection(old_conn);
    const old_ticket = old_conn.pq_resumption_ticket.?;

    var rotated_mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
        .pq_ticket_issuer = new_material,
        .pq_previous_ticket_issuer = old_material,
    });
    defer rotated_mux.deinit();

    try std.testing.expect(old_conn.validatePostQuantumResumptionTicket(&rotated_mux.pq_ticket_issuers, old_ticket, false));

    const new_conn = try rotated_mux.acquireConnection(.http3, .normal, .defi_api);
    defer rotated_mux.releaseConnection(new_conn);
    try std.testing.expect(std.mem.eql(u8, &new_conn.pq_resumption_ticket.?.issuer_key_id, &new_material.key_id));
}

test "crypto multiplexer enforces PQ pool lifecycle before reuse" {
    const allocator = std.testing.allocator;
    var mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
    });
    defer mux.deinit();

    const conn = try mux.acquireConnection(.http3, .normal, .defi_api);
    defer mux.releaseConnection(conn);

    try std.testing.expect(conn.canReuseForPostQuantumPool(&mux.pq_ticket_issuers, false, false));

    conn.pq_pool_state = .handshake_pending;
    try std.testing.expect(!conn.canReuseForPostQuantumPool(&mux.pq_ticket_issuers, false, false));
    conn.pq_pool_state = .established;

    const saved_ticket = conn.pq_resumption_ticket.?;
    conn.pq_resumption_ticket = null;
    try std.testing.expect(!conn.canReuseForPostQuantumPool(&mux.pq_ticket_issuers, false, false));
    conn.pq_resumption_ticket = saved_ticket;

    try std.testing.expect(!conn.canReuseForPostQuantumPool(&mux.pq_ticket_issuers, false, true));
}

test "crypto multiplexer suppresses PQ 0-RTT unless policy allows" {
    const allocator = std.testing.allocator;
    var default_mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
    });
    defer default_mux.deinit();

    const default_conn = try default_mux.acquireConnection(.http3, .normal, .defi_api);
    defer default_mux.releaseConnection(default_conn);
    try std.testing.expect(default_conn.zero_rtt_context == null);
    try std.testing.expect(default_conn.pq_resumption_ticket.?.resumption_policy == .hybrid_pq_no_early_data);

    var early_mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .allow_zero_rtt_with_post_quantum = true,
        .enable_connection_migration = false,
    });
    defer early_mux.deinit();

    const early_conn = try early_mux.acquireConnection(.http3, .normal, .defi_api);
    defer early_mux.releaseConnection(early_conn);
    try std.testing.expect(early_conn.zero_rtt_context != null);
    try std.testing.expect(early_conn.pq_resumption_ticket.?.resumption_policy == .hybrid_pq_early_data);
    try std.testing.expect(early_conn.canReuseForPostQuantumPool(&early_mux.pq_ticket_issuers, true, false));
    try std.testing.expect(!early_conn.canReuseForPostQuantumPool(&early_mux.pq_ticket_issuers, false, false));
}

test "crypto multiplexer rejects PQ reuse after key policy mismatch" {
    const allocator = std.testing.allocator;
    var mux = CryptoConnectionMultiplexer.init(allocator, .{
        .enable_post_quantum = true,
        .enable_zero_rtt = true,
        .enable_connection_migration = false,
    });
    defer mux.deinit();

    const first = try mux.acquireConnection(.http3, .normal, .defi_api);
    defer mux.releaseConnection(first);
    const first_ticket = first.pq_resumption_ticket.?;

    first.is_available.store(false, .monotonic);
    const second = try mux.acquireConnection(.http3, .normal, .defi_api);
    defer mux.releaseConnection(second);

    try std.testing.expect(!second.validatePostQuantumResumptionTicket(&mux.pq_ticket_issuers, first_ticket, false));
}
