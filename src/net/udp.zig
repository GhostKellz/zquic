//! UDP socket abstraction
//!
//! Provides UDP socket functionality for QUIC with real socket implementation

const std = @import("std");
const net = std.net;
const os = std.os;
const Error = @import("../utils/error.zig");

/// UDP socket receive result
pub const ReceiveResult = struct {
    bytes_received: usize,
    remote_address: std.net.Address,
};

/// UDP socket wrapper with real implementation
pub const UdpSocket = struct {
    socket_fd: std.posix.socket_t,
    local_address: std.net.Address,
    is_non_blocking: bool = false,

    const Self = @This();

    pub fn init(local_address: std.net.Address) !Self {
        // Create UDP socket
        const socket_fd = try os.socket(local_address.any.family, os.SOCK.DGRAM, os.IPPROTO.UDP);
        errdefer os.closeSocket(socket_fd);

        // Set socket options
        try os.setsockopt(socket_fd, os.SOL.SOCKET, os.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

        // Bind to local address
        try os.bind(socket_fd, &local_address.any, local_address.getOsSockLen());

        // Get actual bound address (in case port was 0)
        var bound_addr: std.net.Address = undefined;
        var addr_len: os.socklen_t = @sizeOf(std.net.Address);
        try os.getsockname(socket_fd, &bound_addr.any, &addr_len);

        return Self{
            .socket_fd = socket_fd,
            .local_address = bound_addr,
            .is_non_blocking = false,
        };
    }

    pub fn deinit(self: *Self) void {
        os.closeSocket(self.socket_fd);
    }

    /// Send data to remote address
    pub fn sendTo(self: *Self, data: []const u8, remote_address: std.net.Address) Error.ZquicError!usize {
        const bytes_sent = os.sendto(
            self.socket_fd,
            data,
            0,
            &remote_address.any,
            remote_address.getOsSockLen(),
        ) catch |err| switch (err) {
            error.WouldBlock => return Error.ZquicError.WouldBlock,
            error.ConnectionResetByPeer => return Error.ZquicError.ConnectionReset,
            error.NetworkUnreachable => return Error.ZquicError.NetworkUnreachable,
            error.MessageTooBig => return Error.ZquicError.PacketTooLarge,
            else => return Error.ZquicError.NetworkError,
        };

        return bytes_sent;
    }

    /// Receive data from socket
    pub fn receiveFrom(self: *Self, buffer: []u8) Error.ZquicError!ReceiveResult {
        var remote_address: std.net.Address = undefined;
        var addr_len: os.socklen_t = @sizeOf(std.net.Address);

        const bytes_received = os.recvfrom(
            self.socket_fd,
            buffer,
            0,
            &remote_address.any,
            &addr_len,
        ) catch |err| switch (err) {
            error.WouldBlock => return Error.ZquicError.WouldBlock,
            error.ConnectionRefused => return Error.ZquicError.ConnectionRefused,
            error.ConnectionResetByPeer => return Error.ZquicError.ConnectionReset,
            else => return Error.ZquicError.NetworkError,
        };

        return ReceiveResult{
            .bytes_received = bytes_received,
            .remote_address = remote_address,
        };
    }

    /// Set socket to non-blocking mode
    pub fn setNonBlocking(self: *Self, non_blocking: bool) Error.ZquicError!void {
        const flags = os.fcntl(self.socket_fd, os.F.GETFL, 0) catch return Error.ZquicError.NetworkError;

        const new_flags = if (non_blocking) flags | os.O.NONBLOCK else flags & ~@as(u32, os.O.NONBLOCK);

        _ = os.fcntl(self.socket_fd, os.F.SETFL, new_flags) catch return Error.ZquicError.NetworkError;

        self.is_non_blocking = non_blocking;
    }

    /// Get local address the socket is bound to
    pub fn getLocalAddress(self: *const Self) std.net.Address {
        return self.local_address;
    }

    /// Check if socket is in non-blocking mode
    pub fn isNonBlocking(self: *const Self) bool {
        return self.is_non_blocking;
    }

    /// Set receive buffer size
    pub fn setReceiveBufferSize(self: *Self, size: u32) Error.ZquicError!void {
        const size_bytes = std.mem.toBytes(size);
        os.setsockopt(self.socket_fd, os.SOL.SOCKET, os.SO.RCVBUF, &size_bytes) catch
            return Error.ZquicError.NetworkError;
    }

    /// Set send buffer size
    pub fn setSendBufferSize(self: *Self, size: u32) Error.ZquicError!void {
        const size_bytes = std.mem.toBytes(size);
        os.setsockopt(self.socket_fd, os.SOL.SOCKET, os.SO.SNDBUF, &size_bytes) catch
            return Error.ZquicError.NetworkError;
    }

    /// Enable/disable packet info reception (for getting destination address)
    pub fn setPacketInfo(self: *Self, enable: bool) Error.ZquicError!void {
        const value = @as(c_int, if (enable) 1 else 0);
        const value_bytes = std.mem.toBytes(value);

        switch (self.local_address.any.family) {
            os.AF.INET => {
                os.setsockopt(self.socket_fd, os.IPPROTO.IP, os.IP.PKTINFO, &value_bytes) catch
                    return Error.ZquicError.NetworkError;
            },
            os.AF.INET6 => {
                os.setsockopt(self.socket_fd, os.IPPROTO.IPV6, os.IPV6.RECVPKTINFO, &value_bytes) catch
                    return Error.ZquicError.NetworkError;
            },
            else => return Error.ZquicError.NotSupported,
        }
    }

    /// Perform async receive operation (returns immediately if no data available)
    pub fn tryReceive(self: *Self, buffer: []u8) ?ReceiveResult {
        if (!self.is_non_blocking) {
            // Temporarily set to non-blocking for this operation
            const original_flags = os.fcntl(self.socket_fd, os.F.GETFL, 0) catch return null;
            _ = os.fcntl(self.socket_fd, os.F.SETFL, original_flags | os.O.NONBLOCK) catch return null;
            defer _ = os.fcntl(self.socket_fd, os.F.SETFL, original_flags) catch {};
        }

        return self.receiveFrom(buffer) catch null;
    }

    /// Try to send data without blocking
    pub fn trySend(self: *Self, data: []const u8, remote_address: std.net.Address) ?usize {
        if (!self.is_non_blocking) {
            // Temporarily set to non-blocking for this operation
            const original_flags = os.fcntl(self.socket_fd, os.F.GETFL, 0) catch return null;
            _ = os.fcntl(self.socket_fd, os.F.SETFL, original_flags | os.O.NONBLOCK) catch return null;
            defer _ = os.fcntl(self.socket_fd, os.F.SETFL, original_flags) catch {};
        }

        return self.sendTo(data, remote_address) catch null;
    }
};

test "udp socket creation" {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0); // Use port 0 for auto-assignment
    var socket = UdpSocket.init(address) catch |err| switch (err) {
        error.AddressInUse, error.AccessDenied, error.PermissionDenied => {
            // Skip test if we can't bind to the address (common in CI environments)
            return;
        },
        else => return err,
    };
    defer socket.deinit();

    try std.testing.expect(socket.local_address.any.family == std.os.AF.INET);
    try std.testing.expect(!socket.isNonBlocking());
}

test "udp socket non-blocking mode" {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var socket = UdpSocket.init(address) catch |err| switch (err) {
        error.AddressInUse, error.AccessDenied, error.PermissionDenied => return,
        else => return err,
    };
    defer socket.deinit();

    try socket.setNonBlocking(true);
    try std.testing.expect(socket.isNonBlocking());

    try socket.setNonBlocking(false);
    try std.testing.expect(!socket.isNonBlocking());
}
