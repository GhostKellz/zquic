//! UDP Multiplexer for QUIC connections
//!
//! Handles multiple QUIC connections over a single UDP socket with connection demultiplexing

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const Connection = @import("../core/connection.zig");
const Packet = @import("../core/packet.zig");
const UdpSocket = @import("udp.zig").UdpSocket;
const NetAddress = @import("address.zig");

/// Connection routing entry
pub const ConnectionEntry = struct {
    connection_id: Packet.ConnectionId,
    connection: *Connection.Connection,
    remote_address: NetAddress.Address,
    last_activity: i64, // timestamp in microseconds

    pub fn isExpired(self: *const @This(), current_time: i64, timeout_us: i64) bool {
        return current_time - self.last_activity > timeout_us;
    }
};

/// UDP Multiplexer configuration
pub const MultiplexerConfig = struct {
    max_connections: u32 = 1000,
    connection_timeout_ms: u32 = 300_000, // 5 minutes
    buffer_size: u32 = 65536, // 64KB receive buffer
    send_queue_size: u32 = 1000,
};

/// Outbound packet for sending
pub const OutboundPacket = struct {
    data: []const u8,
    destination: NetAddress.Address,
    connection_id: ?Packet.ConnectionId = null,
};

/// UDP Multiplexer for handling multiple QUIC connections
pub const UdpMultiplexer = struct {
    socket: UdpSocket,
    connections: std.HashMap(u64, ConnectionEntry, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    config: MultiplexerConfig,
    allocator: std.mem.Allocator,

    // Async operation support
    receive_buffer: []u8,
    send_queue: std.ArrayListUnmanaged(OutboundPacket),

    // Statistics
    packets_received: u64 = 0,
    packets_sent: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    connection_count: u32 = 0,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, local_address: NetAddress.Address, config: MultiplexerConfig) Error.ZquicError!Self {
        const socket = UdpSocket.init(local_address) catch |err| switch (err) {
            error.AddressInUse => return Error.ZquicError.AddressInUse,
            error.AddressNotAvailable => return Error.ZquicError.InvalidArgument,
            else => return Error.ZquicError.NetworkError,
        };

        const receive_buffer = allocator.alloc(u8, config.buffer_size) catch return Error.ZquicError.OutOfMemory;

        return Self{
            .socket = socket,
            .connections = std.HashMap(u64, ConnectionEntry, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .config = config,
            .allocator = allocator,
            .receive_buffer = receive_buffer,
            .send_queue = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.socket.deinit();
        self.connections.deinit();
        self.allocator.free(self.receive_buffer);
        for (self.send_queue.items) |packet| {
            self.allocator.free(packet.data);
        }
        self.send_queue.deinit(self.allocator);
    }

    /// Add a new connection to the multiplexer
    pub fn addConnection(self: *Self, connection_id: Packet.ConnectionId, connection: *Connection.Connection, remote_address: NetAddress.Address) Error.ZquicError!void {
        if (self.connection_count >= self.config.max_connections) {
            return Error.ZquicError.ConnectionLimitReached;
        }

        const conn_id_hash = self.hashConnectionId(&connection_id);
        const current_time = Time.nowMicros();

        const entry = ConnectionEntry{
            .connection_id = connection_id,
            .connection = connection,
            .remote_address = remote_address,
            .last_activity = current_time,
        };

        self.connections.put(conn_id_hash, entry) catch return Error.ZquicError.OutOfMemory;
        self.connection_count += 1;
    }

    /// Remove a connection from the multiplexer
    pub fn removeConnection(self: *Self, connection_id: *const Packet.ConnectionId) void {
        const conn_id_hash = self.hashConnectionId(connection_id);
        if (self.connections.remove(conn_id_hash)) {
            self.connection_count -= 1;
        }
    }

    /// Route an incoming packet to the appropriate connection
    pub fn routePacket(self: *Self, packet_data: []const u8, source_address: NetAddress.Address) Error.ZquicError!void {
        // Parse packet header to extract connection ID
        const packet = Packet.PacketHeader.parse(packet_data, self.allocator) catch return Error.ZquicError.InvalidPacket;

        const conn_id_hash = self.hashConnectionId(&packet.dest_conn_id);

        if (self.connections.getPtr(conn_id_hash)) |entry| {
            // Update last activity
            entry.last_activity = Time.nowMicros();

            try entry.connection.super_connection.queueIncomingRawPacket(packet_data);

            // Update connection's remote address if it changed (connection migration)
            if (!std.meta.eql(entry.remote_address, source_address)) {
                std.log.info("Connection {} migrated from {} to {}", .{ conn_id_hash, entry.remote_address, source_address });
                entry.remote_address = source_address;
            }
        } else {
            // No existing connection - this might be a new connection attempt
            std.log.debug("Received packet for unknown connection ID: {}", .{conn_id_hash});
            return Error.ZquicError.UnknownConnection;
        }

        self.packets_received += 1;
        self.bytes_received += packet_data.len;
    }

    /// Drain protected raw packets from a connection and send them to its peer.
    pub fn flushConnectionRawPackets(self: *Self, connection_id: *const Packet.ConnectionId) Error.ZquicError!u32 {
        const conn_id_hash = self.hashConnectionId(connection_id);
        const entry = self.connections.getPtr(conn_id_hash) orelse return Error.ZquicError.UnknownConnection;

        const outgoing = try entry.connection.super_connection.drainOutgoingRawPackets(self.allocator);
        defer self.allocator.free(outgoing);

        var sent: u32 = 0;
        for (outgoing) |*packet| {
            defer packet.deinit(self.allocator);
            try self.sendPacket(packet.data, entry.remote_address, connection_id.*);
            sent += 1;
        }
        return sent;
    }

    /// Receive and route packets from the UDP socket
    pub fn receiveAndRoute(self: *Self) Error.ZquicError!void {
        const result = self.socket.receiveFrom(self.receive_buffer) catch return Error.ZquicError.NetworkError;

        if (result.bytes_received > 0) {
            try self.routePacket(self.receive_buffer[0..result.bytes_received], result.remote_address);
        }
    }

    /// Try to receive and route one datagram without blocking.
    pub fn tryReceiveAndRoute(self: *Self) Error.ZquicError!bool {
        const result = self.socket.tryReceiveFrom(self.receive_buffer) catch return Error.ZquicError.NetworkError;
        const packet = result orelse return false;
        if (packet.bytes_received == 0) return false;
        try self.routePacket(self.receive_buffer[0..packet.bytes_received], packet.remote_address);
        return true;
    }

    /// Send a packet through the multiplexer
    pub fn sendPacket(self: *Self, packet_data: []const u8, destination: NetAddress.Address, connection_id: ?Packet.ConnectionId) Error.ZquicError!void {
        _ = self.socket.sendTo(packet_data, destination) catch return Error.ZquicError.NetworkError;

        self.packets_sent += 1;
        self.bytes_sent += packet_data.len;

        // Update connection activity if connection ID provided
        if (connection_id) |conn_id| {
            const conn_id_hash = self.hashConnectionId(&conn_id);
            if (self.connections.getPtr(conn_id_hash)) |entry| {
                entry.last_activity = Time.nowMicros();
            }
        }
    }

    /// Queue a packet for sending (for async operation)
    pub fn queuePacket(self: *Self, packet_data: []const u8, destination: NetAddress.Address, connection_id: ?Packet.ConnectionId) Error.ZquicError!void {
        if (self.send_queue.items.len >= self.config.send_queue_size) {
            return Error.ZquicError.SendQueueFull;
        }

        const packet_copy = self.allocator.dupe(u8, packet_data) catch return Error.ZquicError.OutOfMemory;

        const outbound_packet = OutboundPacket{
            .data = packet_copy,
            .destination = destination,
            .connection_id = connection_id,
        };

        self.send_queue.append(self.allocator, outbound_packet) catch {
            self.allocator.free(packet_copy);
            return Error.ZquicError.OutOfMemory;
        };
    }

    /// Process queued outbound packets
    pub fn processSendQueue(self: *Self) Error.ZquicError!u32 {
        var packets_sent: u32 = 0;

        while (self.send_queue.items.len > 0) {
            const packet = self.send_queue.orderedRemove(0);
            defer self.allocator.free(packet.data);

            self.sendPacket(packet.data, packet.destination, packet.connection_id) catch |err| {
                std.log.warn("Failed to send queued packet: {}", .{err});
                continue;
            };

            packets_sent += 1;
        }

        return packets_sent;
    }

    /// Clean up expired connections
    pub fn cleanupExpiredConnections(self: *Self) u32 {
        const current_time = Time.nowMicros();
        const timeout_us = @as(i64, self.config.connection_timeout_ms) * 1000;

        var expired_connections = std.array_list.Managed(u64).init(self.allocator);
        defer expired_connections.deinit();

        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired(current_time, timeout_us)) {
                expired_connections.append(entry.key_ptr.*) catch continue;
            }
        }

        for (expired_connections.items) |conn_id_hash| {
            if (self.connections.remove(conn_id_hash)) {
                self.connection_count -= 1;
                std.log.info("Removed expired connection: {}", .{conn_id_hash});
            }
        }

        return @intCast(expired_connections.items.len);
    }

    /// Get connection by connection ID
    pub fn getConnection(self: *Self, connection_id: *const Packet.ConnectionId) ?*Connection.Connection {
        const conn_id_hash = self.hashConnectionId(connection_id);
        if (self.connections.getPtr(conn_id_hash)) |entry| {
            return entry.connection;
        }
        return null;
    }

    /// Get multiplexer statistics
    pub fn getStats(self: *const Self) struct {
        packets_received: u64,
        packets_sent: u64,
        bytes_received: u64,
        bytes_sent: u64,
        active_connections: u32,
        send_queue_size: usize,
    } {
        return .{
            .packets_received = self.packets_received,
            .packets_sent = self.packets_sent,
            .bytes_received = self.bytes_received,
            .bytes_sent = self.bytes_sent,
            .active_connections = self.connection_count,
            .send_queue_size = self.send_queue.items.len,
        };
    }

    /// Hash a connection ID for use as HashMap key
    fn hashConnectionId(self: *const Self, connection_id: *const Packet.ConnectionId) u64 {
        _ = self;
        return std.hash_map.hashString(connection_id.bytes());
    }
};

test "multiplexer initialization" {
    const config = MultiplexerConfig{};
    const local_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0); // Port 0 = OS assigns

    var multiplexer = UdpMultiplexer.init(std.testing.allocator, local_addr, config) catch return; // Skip if bind fails
    defer multiplexer.deinit();

    const stats = multiplexer.getStats();
    try std.testing.expect(stats.active_connections == 0);
}

test "connection management" {
    const config = MultiplexerConfig{};
    const local_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0); // Port 0 = OS assigns

    var multiplexer = UdpMultiplexer.init(std.testing.allocator, local_addr, config) catch return; // Skip if bind fails
    defer multiplexer.deinit();

    const conn_id = try Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    var connection = try Connection.Connection.init(std.testing.allocator, .client, .{});
    defer connection.deinit();

    const remote_addr = NetAddress.initIp4([4]u8{ 192, 168, 1, 1 }, 4433);

    try multiplexer.addConnection(conn_id, &connection, remote_addr);
    try std.testing.expect(multiplexer.connection_count == 1);

    const retrieved_conn = multiplexer.getConnection(&conn_id);
    try std.testing.expect(retrieved_conn != null);

    multiplexer.removeConnection(&conn_id);
    try std.testing.expect(multiplexer.connection_count == 0);
}

test "multiplexer routes ingress into owned raw packet queue" {
    const config = MultiplexerConfig{};
    const local_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);

    var multiplexer = UdpMultiplexer.init(std.testing.allocator, local_addr, config) catch return;
    defer multiplexer.deinit();

    const conn_id = try Packet.ConnectionId.init(&[_]u8{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 });
    var connection = try Connection.Connection.init(std.testing.allocator, .server, .{});
    defer connection.deinit();

    const first_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 4433);
    const migrated_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 4434);
    try multiplexer.addConnection(conn_id, &connection, first_addr);

    const datagram = [_]u8{
        0x40,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x01,
        0xaa,
        0xbb,
        0xcc,
    };
    try multiplexer.routePacket(&datagram, migrated_addr);

    try std.testing.expectEqual(@as(usize, 1), connection.super_connection.incoming_raw_packets.items.len);
    try std.testing.expectEqualSlices(u8, &datagram, connection.super_connection.incoming_raw_packets.items[0].data);

    const entry = multiplexer.connections.getPtr(multiplexer.hashConnectionId(&conn_id)).?;
    try std.testing.expect(std.meta.eql(entry.remote_address, migrated_addr));

    const stats = multiplexer.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.packets_received);
    try std.testing.expectEqual(@as(u64, datagram.len), stats.bytes_received);
}

test "multiplexer flushes connection owned raw packets through socket" {
    const config = MultiplexerConfig{};
    const local_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);

    var multiplexer = UdpMultiplexer.init(std.testing.allocator, local_addr, config) catch return;
    defer multiplexer.deinit();

    const conn_id = try Packet.ConnectionId.init(&[_]u8{ 1, 3, 5, 7, 9, 11, 13, 15 });
    var connection = try Connection.Connection.init(std.testing.allocator, .client, .{});
    defer connection.deinit();

    try multiplexer.addConnection(conn_id, &connection, multiplexer.socket.local_address);
    try connection.super_connection.queueOutgoingRawPacket("protected datagram");

    const sent = try multiplexer.flushConnectionRawPackets(&conn_id);
    try std.testing.expectEqual(@as(u32, 1), sent);
    try std.testing.expectEqual(@as(usize, 0), connection.super_connection.outgoing_raw_packets.items.len);

    const stats = multiplexer.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, "protected datagram".len), stats.bytes_sent);
}
