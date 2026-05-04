//! IPv6 utilities
//!
//! IPv6 address handling and utilities

const std = @import("std");
const Error = @import("../utils/error.zig");
const NetAddress = @import("address.zig");
const Address = NetAddress.Address;

/// IPv6 address utilities
pub const IPv6 = struct {
    /// Check if an address is IPv6
    pub fn isIPv6(address: Address) bool {
        return NetAddress.isIp6(address);
    }

    /// Check if an address is IPv4
    pub fn isIPv4(address: Address) bool {
        return NetAddress.isIp4(address);
    }

    /// Get address family string
    pub fn getAddressFamilyString(address: Address) []const u8 {
        return if (isIPv6(address)) "IPv6" else "IPv4";
    }

    /// Create IPv6 address from bytes
    pub fn fromBytes(bytes: [16]u8, port: u16) Address {
        return NetAddress.initIp6(bytes, port, 0, 0);
    }

    /// Create IPv4 address from bytes
    pub fn fromBytesIPv4(bytes: [4]u8, port: u16) Address {
        return NetAddress.initIp4(bytes, port);
    }
};

test "ipv6 utilities" {
    const ipv4_addr = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 8080);
    const ipv6_addr = NetAddress.initIp6(std.mem.zeroes([15]u8) ++ [1]u8{1}, 8080, 0, 0);

    try std.testing.expect(IPv6.isIPv4(ipv4_addr));
    try std.testing.expect(!IPv6.isIPv6(ipv4_addr));

    try std.testing.expect(IPv6.isIPv6(ipv6_addr));
    try std.testing.expect(!IPv6.isIPv4(ipv6_addr));

    try std.testing.expectEqualStrings("IPv4", IPv6.getAddressFamilyString(ipv4_addr));
    try std.testing.expectEqualStrings("IPv6", IPv6.getAddressFamilyString(ipv6_addr));
}
