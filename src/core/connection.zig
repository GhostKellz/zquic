//! QUIC connection management
//!
//! Implements QUIC connection state and lifecycle according to RFC 9000

const std = @import("std");
const Error = @import("../utils/error.zig");
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
};

/// QUIC connection
pub const Connection = struct {
    role: Role,
    state: ConnectionState,
    local_conn_id: Packet.ConnectionId,
    remote_conn_id: ?Packet.ConnectionId,
    params: ConnectionParams,
    stats: ConnectionStats,
    streams: std.ArrayList(Stream.Stream),
    allocator: std.mem.Allocator,
    next_stream_id: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, role: Role, local_conn_id: Packet.ConnectionId) Self {
        const initial_stream_id: u64 = switch (role) {
            .client => 0, // Client-initiated bidirectional streams start at 0
            .server => 1, // Server-initiated bidirectional streams start at 1
        };

        return Self{
            .role = role,
            .state = .initial,
            .local_conn_id = local_conn_id,
            .remote_conn_id = null,
            .params = ConnectionParams{},
            .stats = ConnectionStats{},
            .streams = std.ArrayList(Stream.Stream).init(allocator),
            .allocator = allocator,
            .next_stream_id = initial_stream_id,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.streams.items) |*stream| {
            stream.deinit();
        }
        self.streams.deinit();
    }

    /// Create a new stream
    pub fn createStream(self: *Self, stream_type: Stream.StreamType) Error.ZquicError!*Stream.Stream {
        if (self.state != .established) {
            return Error.ZquicError.ConnectionClosed;
        }

        const stream_id = self.generateStreamId(stream_type);
        var stream = Stream.Stream.init(self.allocator, stream_id);
        stream.state = .open;

        try self.streams.append(stream);
        return &self.streams.items[self.streams.items.len - 1];
    }

    /// Get an existing stream
    pub fn getStream(self: *Self, stream_id: u64) ?*Stream.Stream {
        for (self.streams.items) |*stream| {
            if (stream.id.id == stream_id) {
                return stream;
            }
        }
        return null;
    }

    /// Get an existing stream or create a new one if it doesn't exist
    pub fn getOrCreateStream(self: *Self, stream_id: u64) Error.ZquicError!*Stream.Stream {
        // First try to get existing stream
        if (self.getStream(stream_id)) |stream| {
            return stream;
        }
        
        // Stream doesn't exist, create a new one
        // For HTTP/3, we typically use bidirectional streams
        _ = if (stream_id % 4 < 2) 
            Stream.StreamType.client_bidirectional 
        else 
            Stream.StreamType.server_bidirectional;
            
        var stream = Stream.Stream.init(self.allocator, stream_id);
        stream.state = .open;
        
        try self.streams.append(stream);
        
        // Return pointer to the last added stream
        return &self.streams.items[self.streams.items.len - 1];
    }

    /// Close a stream
    pub fn closeStream(self: *Self, stream_id: u64) Error.ZquicError!void {
        for (self.streams.items) |*stream| {
            if (stream.id.id == stream_id) {
                stream.state = .closed;
                return;
            }
        }
        return Error.ZquicError.InvalidArgument;
    }

    /// Process an incoming packet
    pub fn processPacket(self: *Self, packet: Packet.Packet) Error.ZquicError!void {
        // Update statistics
        self.stats.packets_received += 1;
        self.stats.bytes_received += packet.payload.len;

        // Validate connection ID
        if (!packet.header.dest_conn_id.eql(&self.local_conn_id)) {
            return Error.ZquicError.InvalidConnectionId;
        }

        // Update remote connection ID if not set
        if (self.remote_conn_id == null and packet.header.src_conn_id != null) {
            self.remote_conn_id = packet.header.src_conn_id;
        }

        // Process based on packet type and connection state
        switch (self.state) {
            .initial => {
                if (packet.header.packet_type == .initial) {
                    // Process Initial packet - would contain CRYPTO frames
                    self.state = .handshake;
                }
            },
            .handshake => {
                if (packet.header.packet_type == .handshake) {
                    // Process Handshake packet - would complete TLS handshake
                    self.state = .established;
                }
            },
            .established => {
                if (packet.header.packet_type == .one_rtt) {
                    // Process 1-RTT packet - would contain STREAM frames, etc.
                    try self.processFrames(packet.payload);
                }
            },
            else => {
                // Handle other states
            },
        }
    }

    /// Send data on a stream
    pub fn sendStreamData(self: *Self, stream_id: u64, data: []const u8, fin: bool) Error.ZquicError!usize {
        if (self.state != .established) {
            return Error.ZquicError.ConnectionClosed;
        }

        if (self.getStream(stream_id)) |stream| {
            return stream.write(data, fin);
        } else {
            return Error.ZquicError.InvalidArgument;
        }
    }

    /// Read data from a stream
    pub fn readStreamData(self: *Self, stream_id: u64, buffer: []u8) usize {
        if (self.getStream(stream_id)) |stream| {
            return stream.read(buffer);
        }
        return 0;
    }

    /// Close the connection
    pub fn close(self: *Self, error_code: Error.TransportError, reason: []const u8) void {
        _ = error_code;
        _ = reason;
        self.state = .closing;
        // In real implementation, would send CONNECTION_CLOSE frame
    }

    /// Check if connection is established
    pub fn isEstablished(self: *const Self) bool {
        return self.state == .established;
    }

    /// Check if connection is closed
    pub fn isClosed(self: *const Self) bool {
        return self.state == .closed or self.state == .draining;
    }

    /// Generate the next stream ID for the given type
    fn generateStreamId(self: *Self, stream_type: Stream.StreamType) u64 {
        const base_id = self.next_stream_id;

        // Calculate the next stream ID based on type and role
        const id = switch (stream_type) {
            .client_bidirectional => if (self.role == .client) base_id else base_id + 1,
            .server_bidirectional => if (self.role == .server) base_id else base_id + 1,
            .client_unidirectional => if (self.role == .client) base_id + 2 else base_id + 3,
            .server_unidirectional => if (self.role == .server) base_id + 2 else base_id + 3,
        };

        // Update next stream ID
        self.next_stream_id += 4; // Stream IDs increment by 4

        return id;
    }

    /// Process frames within a packet payload (simplified)
    fn processFrames(self: *Self, payload: []const u8) Error.ZquicError!void {
        _ = self;
        _ = payload;
        // In a real implementation, this would parse and process QUIC frames
        // such as STREAM, ACK, WINDOW_UPDATE, etc.
    }
};

test "connection creation and basic operations" {
    const local_cid = try Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    var conn = Connection.init(std.testing.allocator, .client, local_cid);
    defer conn.deinit();

    try std.testing.expect(conn.role == .client);
    try std.testing.expect(conn.state == .initial);
    try std.testing.expect(!conn.isEstablished());
    try std.testing.expect(!conn.isClosed());
}

test "stream creation and management" {
    const local_cid = try Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    var conn = Connection.init(std.testing.allocator, .client, local_cid);
    defer conn.deinit();

    // Simulate established connection
    conn.state = .established;

    const stream = try conn.createStream(.client_bidirectional);
    try std.testing.expect(stream.id.id == 0); // First client bidirectional stream

    const written = try conn.sendStreamData(0, "hello", false);
    try std.testing.expect(written == 5);

    // Simulate receiving data
    try stream.receiveData("world", 0, true);

    var buffer: [10]u8 = undefined;
    const read_len = conn.readStreamData(0, &buffer);
    try std.testing.expect(read_len == 5);
    try std.testing.expectEqualStrings("world", buffer[0..read_len]);
}
