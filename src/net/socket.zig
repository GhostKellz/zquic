//! Socket abstraction layer
//!
//! Higher-level socket interface for QUIC

const std = @import("std");
const Error = @import("../utils/error.zig");
const UdpSocket = @import("udp.zig").UdpSocket;
const NetAddress = @import("address.zig");
const Address = NetAddress.Address;

/// Socket abstraction
pub const Socket = struct {
    udp_socket: UdpSocket,

    const Self = @This();

    pub fn init(_: std.mem.Allocator, address: Address) Error.ZquicError!Self {
        const udp_sock = UdpSocket.init(address) catch return Error.ZquicError.NetworkError;
        return Self{
            .udp_socket = udp_sock,
        };
    }

    pub fn deinit(self: *Self) void {
        self.udp_socket.deinit();
    }

    pub fn send(self: *Self, data: []const u8, address: Address) Error.ZquicError!usize {
        return self.udp_socket.sendTo(data, address);
    }

    pub fn receive(self: *Self, buffer: []u8) Error.ZquicError!struct { bytes_received: usize, remote_address: Address } {
        return self.udp_socket.receiveFrom(buffer);
    }
};

test "socket abstraction" {
    const address = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0); // Port 0 = OS assigns
    var socket = Socket.init(std.testing.allocator, address) catch return; // Skip if bind fails
    defer socket.deinit();

    const data = "test data";
    // Send to self (UDP doesn't require receiver)
    const sent = socket.send(data, socket.udp_socket.local_address) catch return;
    try std.testing.expect(sent == data.len);
}
