//! Socket abstraction layer
//!
//! Higher-level socket interface for QUIC

const std = @import("std");
const Error = @import("../utils/error.zig");
const UdpSocket = @import("udp.zig").UdpSocket;

/// Socket abstraction
pub const Socket = struct {
    udp_socket: UdpSocket,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, address: std.net.Address) Error.ZquicError!Self {
        return Self{
            .udp_socket = try UdpSocket.init(allocator, address),
        };
    }

    pub fn deinit(self: *Self) void {
        self.udp_socket.deinit();
    }

    pub fn send(self: *Self, data: []const u8, address: std.net.Address) Error.ZquicError!usize {
        return self.udp_socket.sendTo(data, address);
    }

    pub fn receive(self: *Self, buffer: []u8) Error.ZquicError!struct { bytes_received: usize, remote_address: std.net.Address } {
        return self.udp_socket.receiveFrom(buffer);
    }
};

test "socket abstraction" {
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8080);
    var socket = try Socket.init(std.testing.allocator, address);
    defer socket.deinit();

    const data = "test data";
    const sent = try socket.send(data, address);
    try std.testing.expect(sent == data.len);
}
