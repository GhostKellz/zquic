//! UDP socket implementation using std.posix
//!
//! Simple, reliable UDP networking for QUIC

const std = @import("std");
const posix = std.posix;
const net_sys = @import("sys.zig");
const NetAddress = @import("address.zig");
const Address = NetAddress.Address;
const PosixAddress = NetAddress.PosixAddress;

/// UDP socket for QUIC transport
pub const UdpSocket = struct {
    socket_fd: posix.socket_t,
    local_address: Address,
    is_non_blocking: bool = false,
    packet_info_enabled: bool = false,

    const Self = @This();

    pub fn init(local_address: Address) !Self {
        const socket_fd = try net_sys.createDatagramSocket(&local_address);
        errdefer net_sys.close(socket_fd);

        // Allow address reuse
        try net_sys.setReuseAddress(socket_fd, true);

        // Bind to address
        var bind_addr: PosixAddress = undefined;
        const bind_addr_len = NetAddress.toPosix(&local_address, &bind_addr);
        try net_sys.bind(socket_fd, &bind_addr, bind_addr_len);

        // Get actual bound address (useful when port is 0)
        var bound_addr_storage: PosixAddress = undefined;
        var addr_len: posix.socklen_t = @sizeOf(PosixAddress);
        try net_sys.getSocketName(socket_fd, &bound_addr_storage, &addr_len);
        const bound_addr = NetAddress.fromPosix(&bound_addr_storage);

        return Self{
            .socket_fd = socket_fd,
            .local_address = bound_addr,
            .is_non_blocking = false,
            .packet_info_enabled = false,
        };
    }

    pub fn deinit(self: *Self) void {
        net_sys.close(self.socket_fd);
    }

    /// Set socket to non-blocking mode
    pub fn setNonBlocking(self: *Self, non_blocking: bool) !void {
        try net_sys.setNonBlocking(self.socket_fd, non_blocking);
        self.is_non_blocking = non_blocking;
    }

    pub fn setReceiveBufferSize(self: *Self, size: usize) !void {
        try net_sys.setReceiveBufferSize(self.socket_fd, size);
    }

    pub fn setSendBufferSize(self: *Self, size: usize) !void {
        try net_sys.setSendBufferSize(self.socket_fd, size);
    }

    pub fn setPacketInfo(self: *Self, enabled: bool) !void {
        // Packet-info support is platform-specific. Keep the API stable while
        // the Linux-specific ancillary-data receive path is implemented.
        self.packet_info_enabled = enabled;
    }

    /// Send data to a specific address
    pub fn sendTo(self: *Self, data: []const u8, dest_addr: Address) !usize {
        var dest_addr_storage: PosixAddress = undefined;
        const dest_addr_len = NetAddress.toPosix(&dest_addr, &dest_addr_storage);
        return net_sys.sendTo(self.socket_fd, data, &dest_addr_storage, dest_addr_len);
    }

    /// Receive data and get source address
    pub fn receiveFrom(self: *Self, buffer: []u8) !struct { bytes_received: usize, remote_address: Address } {
        var src_addr_storage: PosixAddress = undefined;
        var addr_len: posix.socklen_t = @sizeOf(PosixAddress);

        const received = try net_sys.receiveFrom(self.socket_fd, buffer, &src_addr_storage, &addr_len);

        return .{
            .bytes_received = received,
            .remote_address = NetAddress.fromPosix(&src_addr_storage),
        };
    }

    /// Try to receive without blocking (returns null if no data)
    pub fn tryReceiveFrom(self: *Self, buffer: []u8) !?struct { bytes_received: usize, remote_address: Address } {
        if (!self.is_non_blocking) {
            try self.setNonBlocking(true);
        }

        var src_addr_storage: PosixAddress = undefined;
        var addr_len: posix.socklen_t = @sizeOf(PosixAddress);

        const received = net_sys.receiveFrom(self.socket_fd, buffer, &src_addr_storage, &addr_len) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };

        return .{
            .bytes_received = received,
            .remote_address = NetAddress.fromPosix(&src_addr_storage),
        };
    }

    /// Get the file descriptor for polling
    pub fn getFd(self: *const Self) posix.socket_t {
        return self.socket_fd;
    }
};

/// UDP platform feature posture used by tests and higher-level transports.
pub const UdpCapabilities = struct {
    receive_batching: bool,
    send_batching: bool,
    packet_info: bool,
    ecn: bool,
    buffer_sizing: bool,
    ipv4: bool,
    ipv6: bool,
    portable_fallback: bool,
};

pub fn platformCapabilities() UdpCapabilities {
    return switch (@import("builtin").os.tag) {
        .linux => .{
            .receive_batching = false,
            .send_batching = false,
            .packet_info = false,
            .ecn = false,
            .buffer_sizing = true,
            .ipv4 = true,
            .ipv6 = true,
            .portable_fallback = true,
        },
        else => .{
            .receive_batching = false,
            .send_batching = false,
            .packet_info = false,
            .ecn = false,
            .buffer_sizing = false,
            .ipv4 = true,
            .ipv6 = true,
            .portable_fallback = true,
        },
    };
}

/// Simple packet batch for efficient processing
pub const PacketBatch = struct {
    pub const capacity = 32;

    packets: [capacity]Packet,
    count: u8,

    pub const Packet = struct {
        data: []u8,
        addr: Address,
        len: usize,
    };

    pub fn init() PacketBatch {
        return PacketBatch{
            .packets = undefined,
            .count = 0,
        };
    }

    pub fn clear(self: *PacketBatch) void {
        self.count = 0;
    }

    pub fn append(self: *PacketBatch, data: []u8, addr: Address, len: usize) !void {
        if (self.count >= capacity) {
            return error.BatchFull;
        }

        self.packets[self.count] = .{
            .data = data,
            .addr = addr,
            .len = len,
        };
        self.count += 1;
    }

    pub fn isFull(self: *const PacketBatch) bool {
        return self.count == capacity;
    }

    pub fn remainingCapacity(self: *const PacketBatch) u8 {
        return capacity - self.count;
    }
};

test "udp socket creation" {
    const address = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var socket = UdpSocket.init(address) catch return; // Skip if bind fails
    defer socket.deinit();

    // Should have been assigned a port
    try std.testing.expect(socket.local_address.getPort() != 0);
}

test "udp send to self" {
    const address = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var socket = UdpSocket.init(address) catch return;
    defer socket.deinit();

    const data = "test packet";
    const sent = try socket.sendTo(data, socket.local_address);
    try std.testing.expect(sent == data.len);
}

test "udp packet batch enforces capacity and preserves address metadata" {
    var batch = PacketBatch.init();
    const ipv4 = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 4433);
    const ipv6 = NetAddress.initIp6([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 4434, 0, 0);
    var first = [_]u8{ 0xaa, 0xbb };
    var second = [_]u8{0xcc};

    try batch.append(&first, ipv4, first.len);
    try batch.append(&second, ipv6, second.len);

    try std.testing.expectEqual(@as(u8, 2), batch.count);
    try std.testing.expectEqual(@as(usize, 2), batch.packets[0].len);
    try std.testing.expectEqual(@as(u16, 4433), batch.packets[0].addr.getPort());
    try std.testing.expectEqual(@as(u16, 4434), batch.packets[1].addr.getPort());

    while (!batch.isFull()) {
        try batch.append(&second, ipv4, second.len);
    }
    try std.testing.expectError(error.BatchFull, batch.append(&second, ipv4, second.len));

    batch.clear();
    try std.testing.expectEqual(@as(u8, 0), batch.count);
    try std.testing.expectEqual(@as(u8, PacketBatch.capacity), batch.remainingCapacity());
}

test "udp platform capabilities document fallback posture" {
    const caps = platformCapabilities();
    try std.testing.expect(caps.ipv4);
    try std.testing.expect(caps.ipv6);
    try std.testing.expect(caps.portable_fallback);
    try std.testing.expect(caps.receive_batching == false);
    try std.testing.expect(caps.send_batching == false);
    try std.testing.expect(caps.packet_info == false);
    try std.testing.expect(caps.ecn == false);
}

test "udp packet info fallback state is deterministic without live socket" {
    var socket = UdpSocket{
        .socket_fd = -1,
        .local_address = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0),
        .is_non_blocking = false,
        .packet_info_enabled = false,
    };

    try socket.setPacketInfo(true);
    try std.testing.expect(socket.packet_info_enabled);
    try socket.setPacketInfo(false);
    try std.testing.expect(!socket.packet_info_enabled);
}
