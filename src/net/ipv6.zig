//! IPv6 utilities
//!
//! IPv6 address handling and utilities

const std = @import("std");
const Error = @import("../utils/error.zig");

/// IPv6 address utilities
pub const IPv6 = struct {
    /// Check if an address is IPv6
    pub fn isIPv6(address: std.net.Address) bool {
        return address.any.family == std.os.AF.INET6;
    }

    /// Check if an address is IPv4
    pub fn isIPv4(address: std.net.Address) bool {
        return address.any.family == std.os.AF.INET;
    }

    /// Get address family string
    pub fn getAddressFamilyString(address: std.net.Address) []const u8 {
        return if (isIPv6(address)) "IPv6" else "IPv4";
    }

    /// Create IPv6 address from bytes
    pub fn fromBytes(bytes: [16]u8, port: u16) std.net.Address {
        return std.net.Address.initIp6(bytes, port, 0, 0);
    }

    /// Create IPv4 address from bytes
    pub fn fromBytesIPv4(bytes: [4]u8, port: u16) std.net.Address {
        return std.net.Address.initIp4(bytes, port);
    }
};

test "ipv6 utilities" {
    const ipv4_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8080);
    const ipv6_addr = std.net.Address.initIp6([16]u8{0} ** 15 ++ [1]u8{1}, 8080, 0, 0);

    try std.testing.expect(IPv6.isIPv4(ipv4_addr));
    try std.testing.expect(!IPv6.isIPv6(ipv4_addr));

    try std.testing.expect(IPv6.isIPv6(ipv6_addr));
    try std.testing.expect(!IPv6.isIPv4(ipv6_addr));

    try std.testing.expectEqualStrings("IPv4", IPv6.getAddressFamilyString(ipv4_addr));
    try std.testing.expectEqualStrings("IPv6", IPv6.getAddressFamilyString(ipv6_addr));
}
