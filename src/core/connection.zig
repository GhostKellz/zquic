//! QUIC Connection with async channel support
//!
//! ZQUIC v0.9.4 - High-performance connection management without external dependencies

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const Packet = @import("packet.zig");
const Stream = @import("stream.zig");

/// Connection states according to RFC 9000
pub const ConnectionState = enum {
    initial,
    handshake,
    established,
    closing,
    draining,
    closed,
};

/// Connection role
pub const Role = enum {
    client,
    server,
};

/// Stream event for async processing
pub const StreamEvent = union(enum) {
    new_stream: struct {
        stream_id: u64,
        stream_type: Stream.StreamType,
    },
    stream_data: struct {
        stream_id: u64,
        data: []const u8,
        fin: bool,
    },
    stream_closed: struct {
        stream_id: u64,
        error_code: u64,
    },
    flow_control_update: struct {
        stream_id: u64,
        max_data: u64,
    },
};

/// Crypto operation for async processing
pub const CryptoOperation = union(enum) {
    pq_encrypt: struct {
        plaintext: []const u8,
        public_key: []const u8,
    },
    pq_decrypt: struct {
        ciphertext: []const u8,
        private_key: []const u8,
    },
    tls_handshake: struct {
        handshake_data: []const u8,
    },
};

/// Connection parameters
pub const ConnectionParams = struct {
    max_idle_timeout: u64 = 30_000, // 30 seconds in milliseconds
    max_udp_payload_size: u64 = 1472, // Safe MTU size
    initial_max_data: u64 = 1048576, // 1MB
    initial_max_stream_data_bidi_local: u64 = 65536, // 64KB
    initial_max_stream_data_bidi_remote: u64 = 65536, // 64KB
    initial_max_stream_data_uni: u64 = 65536, // 64KB
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25, // 25ms
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
};

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    packets_lost: u64 = 0,
    rtt: u64 = 0, // Round-trip time in microseconds
    rtt_variance: u64 = 0,
    congestion_window: u64 = 14720, // Initial congestion window (10 * MSS)
    bytes_in_flight: u64 = 0,
    ssthresh: u64 = std.math.maxInt(u64),

    // Performance metrics
    async_tasks_spawned: u64 = 0,
    channel_operations: u64 = 0,
    crypto_operations: u64 = 0,
};

/// High-performance QUIC connection
pub const SuperConnection = struct {
    // Core connection data
    role: Role,
    state: ConnectionState,
    local_conn_id: Packet.ConnectionId,
    remote_conn_id: ?Packet.ConnectionId,
    params: ConnectionParams,
    stats: ConnectionStats,
    next_stream_id: u64,

    // Internal packet queues
    incoming_packets: std.ArrayListUnmanaged(Packet.Packet),
    outgoing_packets: std.ArrayListUnmanaged(Packet.Packet),
    stream_events: std.ArrayListUnmanaged(StreamEvent),

    // Stream management
    streams: std.AutoHashMapUnmanaged(u64, *Stream.SuperStream),
    allocator: std.mem.Allocator,
    is_running: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, role: Role, params: ConnectionParams) !Self {
        const local_conn_id = try Packet.ConnectionId.init(&[_]u8{ 0x12, 0x34, 0x56, 0x78 });

        const initial_stream_id: u64 = switch (role) {
            .client => 0, // Client-initiated bidirectional streams start at 0
            .server => 1, // Server-initiated bidirectional streams start at 1
        };

        return Self{
            .role = role,
            .state = .initial,
            .local_conn_id = local_conn_id,
            .remote_conn_id = null,
            .params = params,
            .stats = ConnectionStats{},
            .next_stream_id = initial_stream_id,
            .incoming_packets = .{},
            .outgoing_packets = .{},
            .stream_events = .{},
            .streams = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.is_running = false;

        // Clean up streams
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit(self.allocator);

        // Clean up queues
        self.incoming_packets.deinit(self.allocator);
        self.outgoing_packets.deinit(self.allocator);
        self.stream_events.deinit(self.allocator);
    }

    /// Run connection event loop
    pub fn runConnectionLoop(self: *Self) !void {
        self.is_running = true;

        // Main connection event loop
        while (self.is_running and self.state != .closed) {
            // Process pending events
            while (self.stream_events.items.len > 0) {
                const event = self.stream_events.orderedRemove(0);
                try self.handleStreamEvent(event);
                self.stats.channel_operations += 1;
            }

            // Process packets
            while (self.incoming_packets.items.len > 0) {
                const packet = self.incoming_packets.orderedRemove(0);
                try self.processPacket(packet);
                self.stats.packets_received += 1;
            }

            // Small sleep to prevent busy loop
            Time.sleep(std.time.ns_per_ms);
        }
    }

    /// Handle stream events
    fn handleStreamEvent(self: *Self, event: StreamEvent) !void {
        switch (event) {
            .new_stream => |new| {
                try self.createStreamAsync(new.stream_id, new.stream_type);
            },
            .stream_data => |data| {
                try self.handleStreamData(data.stream_id, data.data, data.fin);
            },
            .stream_closed => |closed| {
                try self.closeStream(closed.stream_id, closed.error_code);
            },
            .flow_control_update => |update| {
                try self.updateStreamFlowControl(update.stream_id, update.max_data);
            },
        }
    }

    /// Create stream asynchronously
    fn createStreamAsync(self: *Self, stream_id: u64, stream_type: Stream.StreamType) !void {
        const stream = try self.allocator.create(Stream.SuperStream);
        stream.* = try Stream.SuperStream.init(self.allocator, stream_id, stream_type);

        try self.streams.put(self.allocator, stream_id, stream);
    }

    /// Handle stream data
    fn handleStreamData(self: *Self, stream_id: u64, data: []const u8, fin: bool) !void {
        if (self.streams.get(stream_id)) |stream| {
            _ = try stream.write(data, fin);
            if (fin) {
                try stream.close();
            }
        }
    }

    /// Close stream
    fn closeStream(self: *Self, stream_id: u64, error_code: u64) !void {
        if (self.streams.fetchRemove(stream_id)) |kv| {
            _ = error_code;
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// Update stream flow control
    fn updateStreamFlowControl(self: *Self, stream_id: u64, max_data: u64) !void {
        if (self.streams.get(stream_id)) |stream| {
            try stream.updateFlowControl(max_data);
        }
    }

    /// Process packet
    fn processPacket(self: *Self, packet: Packet.Packet) !void {
        _ = self;
        _ = packet;
        // Packet processing logic
    }

    /// Send packet
    pub fn sendPacketAsync(self: *Self, packet: Packet.Packet) !void {
        try self.outgoing_packets.append(self.allocator, packet);
        self.stats.packets_sent += 1;
    }

    /// Receive packet
    pub fn receivePacketAsync(self: *Self, packet: Packet.Packet) !void {
        try self.incoming_packets.append(self.allocator, packet);
    }

    /// Get connection statistics
    pub fn getStats(self: *const Self) ConnectionStats {
        return self.stats;
    }
};

/// Legacy connection wrapper for backward compatibility
pub const Connection = struct {
    super_connection: SuperConnection,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, role: Role, params: ConnectionParams) !Self {
        return Self{
            .super_connection = try SuperConnection.init(allocator, role, params),
        };
    }

    pub fn deinit(self: *Self) void {
        self.super_connection.deinit();
    }

    /// Create a new stream (legacy interface)
    pub fn createStream(self: *Self, stream_type: Stream.StreamType) !*Stream.Stream {
        const stream_id = self.super_connection.next_stream_id;
        self.super_connection.next_stream_id += 4; // Increment by 4 for proper stream ID space

        self.super_connection.createStreamAsync(stream_id, stream_type) catch return error.InternalError;

        if (self.super_connection.streams.get(stream_id)) |stream| {
            return stream;
        }
        return error.InternalError;
    }

    /// Get connection state
    pub fn getState(self: *const Self) ConnectionState {
        return self.super_connection.state;
    }

    /// Get connection statistics
    pub fn getStats(self: *const Self) ConnectionStats {
        return self.super_connection.getStats();
    }

    /// Check if connection is established
    pub fn isEstablished(self: *const Self) bool {
        return self.super_connection.state == .established;
    }
};

/// Connection pool for managing multiple connections
pub const SuperConnectionPool = struct {
    available: std.ArrayListUnmanaged(*SuperConnection),
    active: std.ArrayListUnmanaged(*SuperConnection),
    allocator: std.mem.Allocator,
    stats: PoolStats,
    mutex: std.Thread.Mutex,

    pub const PoolStats = struct {
        connections_created: u64 = 0,
        connections_active: u64 = 0,
        connections_pooled: u64 = 0,
        peak_active: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .available = .{},
            .active = .{},
            .allocator = allocator,
            .stats = PoolStats{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Clean up all connections
        for (self.available.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.available.deinit(self.allocator);

        for (self.active.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.active.deinit(self.allocator);
    }

    /// Acquire connection from pool
    pub fn acquire(self: *Self, role: Role, params: ConnectionParams) !*SuperConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to get from available pool first
        if (self.available.popOrNull()) |conn| {
            try self.active.append(self.allocator, conn);
            self.stats.connections_active += 1;
            return conn;
        }

        // Create new connection
        const conn = try self.allocator.create(SuperConnection);
        conn.* = try SuperConnection.init(self.allocator, role, params);

        try self.active.append(self.allocator, conn);
        self.stats.connections_created += 1;
        self.stats.connections_active += 1;
        self.stats.peak_active = @max(self.stats.peak_active, self.stats.connections_active);

        return conn;
    }

    /// Release connection back to pool
    pub fn release(self: *Self, conn: *SuperConnection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Reset connection state
        conn.state = .initial;
        conn.is_running = false;

        // Remove from active
        for (self.active.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.active.swapRemove(i);
                break;
            }
        }

        // Return to available pool
        try self.available.append(self.allocator, conn);
        self.stats.connections_active -= 1;
        self.stats.connections_pooled += 1;
    }

    /// Get pool statistics
    pub fn getStats(self: *const Self) PoolStats {
        return self.stats;
    }
};

test "connection creation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const params = ConnectionParams{};
    var conn = try SuperConnection.init(allocator, .client, params);
    defer conn.deinit();

    try std.testing.expect(conn.state == .initial);
    try std.testing.expect(conn.role == .client);
}

test "connection pool operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pool = SuperConnectionPool.init(allocator);
    defer pool.deinit();

    const params = ConnectionParams{};
    const conn = try pool.acquire(.client, params);

    try pool.release(conn);

    const stats = pool.getStats();
    try std.testing.expect(stats.connections_created == 1);
}
