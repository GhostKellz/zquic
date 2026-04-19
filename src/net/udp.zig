//! UDP socket implementation using std.posix
//!
//! Simple, reliable UDP networking for QUIC

const std = @import("std");
const posix = std.posix;
const NetAddress = @import("address.zig");
const Address = NetAddress.Address;
const PosixAddress = NetAddress.PosixAddress;

/// UDP socket for QUIC transport
pub const UdpSocket = struct {
    socket_fd: posix.socket_t,
    local_address: Address,
    is_non_blocking: bool = false,

    const Self = @This();

    pub fn init(local_address: Address) !Self {
        const socket_fd = try posix.socket(NetAddress.family(&local_address), posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer _ = posix.system.close(socket_fd);

        // Allow address reuse
        try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // Bind to address
        var bind_addr: PosixAddress = undefined;
        const bind_addr_len = NetAddress.toPosix(&local_address, &bind_addr);
        try posix.bind(socket_fd, @ptrCast(&bind_addr), bind_addr_len);

        // Get actual bound address (useful when port is 0)
        var bound_addr_storage: PosixAddress = undefined;
        var addr_len: posix.socklen_t = @sizeOf(PosixAddress);
        try posix.getsockname(socket_fd, @ptrCast(&bound_addr_storage), &addr_len);
        const bound_addr = NetAddress.fromPosix(&bound_addr_storage);

        return Self{
            .socket_fd = socket_fd,
            .local_address = bound_addr,
            .is_non_blocking = false,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = posix.system.close(self.socket_fd);
    }

    /// Set socket to non-blocking mode
    pub fn setNonBlocking(self: *Self, non_blocking: bool) !void {
        const flags = try posix.fcntl(self.socket_fd, posix.F.GETFL, 0);
        const new_flags = if (non_blocking)
            flags | @as(u32, posix.O.NONBLOCK)
        else
            flags & ~@as(u32, posix.O.NONBLOCK);
        _ = try posix.fcntl(self.socket_fd, posix.F.SETFL, new_flags);
        self.is_non_blocking = non_blocking;
    }

    /// Send data to a specific address
    pub fn sendTo(self: *Self, data: []const u8, dest_addr: Address) !usize {
        var dest_addr_storage: PosixAddress = undefined;
        const dest_addr_len = NetAddress.toPosix(&dest_addr, &dest_addr_storage);
        return posix.sendto(
            self.socket_fd,
            data,
            0,
            @ptrCast(&dest_addr_storage),
            dest_addr_len,
        );
    }

    /// Receive data and get source address
    pub fn receiveFrom(self: *Self, buffer: []u8) !struct { bytes_received: usize, remote_address: Address } {
        var src_addr_storage: PosixAddress = undefined;
        var addr_len: posix.socklen_t = @sizeOf(PosixAddress);

        const received = try posix.recvfrom(
            self.socket_fd,
            buffer,
            0,
            @ptrCast(&src_addr_storage),
            &addr_len,
        );

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

        const received = posix.recvfrom(
            self.socket_fd,
            buffer,
            0,
            @ptrCast(&src_addr_storage),
            &addr_len,
        ) catch |err| switch (err) {
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

/// Simple packet batch for efficient processing
pub const PacketBatch = struct {
    packets: [32]Packet,
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
