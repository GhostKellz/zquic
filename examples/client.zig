//! QUIC client example
//!
//! Demonstrates how to create a basic QUIC client using ZQUIC

const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🔗 ZQUIC Client Example\n", .{});

    // Initialize ZQUIC
    try zquic.init(allocator);
    defer zquic.deinit();

    // Create a connection ID
    const local_cid = try zquic.Packet.ConnectionId.init(&[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 });

    // Create a client connection
    var connection = try zquic.Connection.Connection.init(allocator, .client, zquic.Connection.ConnectionParams{});
    defer connection.deinit();

    std.debug.print("Created client connection with ID: {any}\n", .{connection.super_connection.local_conn_id});
    for (local_cid.bytes()) |byte| {
        std.debug.print("{X:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Simulate connection establishment
    connection.super_connection.state = .established;
    std.debug.print("Connection established!\n", .{});

    // Create a bidirectional stream
    const stream = try connection.createStream(.client_bidirectional);
    std.debug.print("Created stream with ID: {}\n", .{stream.id});

    // Send some data
    const message = "Hello from ZQUIC client!";
    const written = try stream.write(message, false);
    std.debug.print("Sent {} bytes: '{s}'\n", .{ written, message });

    // Simulate receiving a response
    try stream.handleIncomingData("Hello from ZQUIC server!");

    var buffer: [100]u8 = undefined;
    const read_len = try stream.read(&buffer);
    std.debug.print("Received {} bytes: '{s}'\n", .{ read_len, buffer[0..read_len] });

    // Demonstrate flow control
    var fc = zquic.FlowControl.FlowController.init(allocator, 65536, 65536);
    defer fc.deinit();

    try fc.addStream(stream.id, 32768, 32768);

    if (fc.canSendStreamData(stream.id, 1000)) {
        try fc.consumeSendCredit(stream.id, 1000);
        std.debug.print("Flow control: consumed 1000 bytes of send credit\n", .{});
    }

    // Demonstrate congestion control
    var cc = zquic.Congestion.CongestionController.init(.new_reno, 1200);

    if (cc.canSend(1200)) {
        cc.onPacketSent(1200);
        std.debug.print("Congestion control: sent 1200 byte packet\n", .{});
    }

    std.debug.print("Available congestion window: {} bytes\n", .{cc.availableWindow()});

    std.debug.print("✅ Client example completed successfully!\n", .{});
}
