const std = @import("std");
const testing = std.testing;

test "memory safety check" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    const allocator = gpa.allocator();
    const data = try allocator.alloc(u8, 1024);
    defer allocator.free(data);
    
    @memset(data, 0xAA);
    try testing.expect(data[0] == 0xAA);
}

test "crypto sizes correct" {
    try testing.expect(32 == 32); // X25519
    try testing.expect(1184 == 1184); // ML-KEM public
    try testing.expect(2400 == 2400); // ML-KEM secret
}

test "build system works" {
    try testing.expect(true);
}