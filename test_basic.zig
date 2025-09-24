//! Basic functionality test for ZQUIC v0.9.0-RC1

const std = @import("std");
const zquic = @import("src/root.zig");

test "basic zquic functionality" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Test that we can import and access basic types
    const version = zquic.version;
    const quic_version = zquic.quic_version;

    std.testing.expect(version.len > 0) catch unreachable;
    std.testing.expect(quic_version > 0) catch unreachable;

    // Test basic initialization
    try zquic.init(allocator);
    defer zquic.deinit();

    std.debug.print("✅ ZQUIC v{s} basic test passed!\n", .{version});
}

test "connection id functionality" {
    // Test connection ID creation
    const test_data = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const cid = try zquic.Packet.ConnectionId.init(&test_data);

    try std.testing.expect(cid.data.len == test_data.len);
    try std.testing.expectEqualSlices(u8, cid.data, &test_data);

    std.debug.print("✅ Connection ID test passed!\n");
}
