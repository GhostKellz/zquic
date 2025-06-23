const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🚀 ZQUIC - Minimal QUIC/HTTP3 Library for Zig\n", .{});
    std.debug.print("Version: {s}\n", .{zquic.version});
    std.debug.print("QUIC Version: 0x{X:0>8}\n", .{zquic.quic_version});

    // Initialize the library
    try zquic.init(allocator);
    defer zquic.deinit();

    // Demonstrate basic functionality
    try demonstrateConnectionId();
    try demonstrateStreamOperations(allocator);
    try demonstrateFlowControl();
    try demonstrateCongestionControl();

    std.debug.print("\n✨ ZQUIC library demonstration complete!\n", .{});
}

fn demonstrateConnectionId() !void {
    std.debug.print("\n📡 Connection ID Demo:\n", .{});

    const cid1 = try zquic.Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const cid2 = try zquic.Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const cid3 = try zquic.Packet.ConnectionId.init(&[_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 });

    std.debug.print("  CID1 == CID2: {}\n", .{cid1.eql(&cid2)});
    std.debug.print("  CID1 == CID3: {}\n", .{cid1.eql(&cid3)});
    std.debug.print("  CID1 length: {}\n", .{cid1.len});
}

fn demonstrateStreamOperations(allocator: std.mem.Allocator) !void {
    std.debug.print("\n🌊 Stream Operations Demo:\n", .{});

    var stream = zquic.Stream.Stream.init(allocator, 0);
    defer stream.deinit();

    stream.state = .open;

    const written = try stream.write("Hello, QUIC!", false);
    std.debug.print("  Written {} bytes to stream\n", .{written});

    try stream.receiveData("Received data", 0, true);
    std.debug.print("  Stream state after FIN: {}\n", .{stream.state});

    var read_buffer: [100]u8 = undefined;
    const read_len = stream.read(&read_buffer);
    std.debug.print("  Read {} bytes: '{s}'\n", .{ read_len, read_buffer[0..read_len] });
}

fn demonstrateFlowControl() !void {
    std.debug.print("\n🔄 Flow Control Demo:\n", .{});

    var window = zquic.FlowControl.FlowControlWindow.init(1000);

    std.debug.print("  Initial window: {} bytes\n", .{window.available()});

    try window.consume(300);
    std.debug.print("  After consuming 300 bytes: {} bytes available\n", .{window.available()});

    try window.updateLimit(1500);
    std.debug.print("  After updating limit to 1500: {} bytes available\n", .{window.available()});
}

fn demonstrateCongestionControl() !void {
    std.debug.print("\n📈 Congestion Control Demo:\n", .{});

    var cc = zquic.Congestion.NewRenoCongestionController.init(1200);

    std.debug.print("  Initial state: {}\n", .{cc.state});
    std.debug.print("  Initial congestion window: {} bytes\n", .{cc.congestion_window});

    // Simulate sending packets
    cc.onPacketSent(1200);
    cc.onPacketSent(1200);
    std.debug.print("  Bytes in flight after sending 2 packets: {} bytes\n", .{cc.bytes_in_flight});

    // Simulate receiving ACKs
    cc.onPacketsAcked(2400, 2);
    std.debug.print("  Congestion window after ACK: {} bytes\n", .{cc.congestion_window});
    std.debug.print("  Available window: {} bytes\n", .{cc.availableWindow()});
}
