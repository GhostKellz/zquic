const std = @import("std");

pub const Address = std.Io.net.IpAddress;
pub const PosixAddress = std.Io.Threaded.PosixAddress;

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

pub fn initIp6(bytes: [16]u8, port: u16, flow: u32, scope_id: u32) Address {
    return .{ .ip6 = .{
        .port = port,
        .bytes = bytes,
        .flow = flow,
        .interface = .{ .index = scope_id },
    } };
}

pub fn resolveIp(text: []const u8, port: u16) !Address {
    return std.Io.net.IpAddress.parse(text, port);
}

pub fn family(address: *const Address) std.posix.sa_family_t {
    return std.Io.Threaded.posixAddressFamily(address);
}

pub fn toPosix(address: *const Address, storage: *PosixAddress) std.posix.socklen_t {
    return std.Io.Threaded.addressToPosix(address, storage);
}

pub fn fromPosix(storage: *const PosixAddress) Address {
    return std.Io.Threaded.addressFromPosix(storage);
}

pub fn isIp4(address: Address) bool {
    return switch (address) {
        .ip4 => true,
        .ip6 => false,
    };
}

pub fn isIp6(address: Address) bool {
    return switch (address) {
        .ip4 => false,
        .ip6 => true,
    };
}
