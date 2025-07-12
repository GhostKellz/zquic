//! QUIC server example
//!
//! Demonstrates how to create a basic QUIC server using ZQUIC

const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("🖥️  ZQUIC Server Example\n", .{});

    // Initialize ZQUIC
    try zquic.init(allocator);
    defer zquic.deinit();

    // Create a connection ID
    const local_cid = try zquic.Packet.ConnectionId.init(&[_]u8{ 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12 });

    // Create a server connection
    var connection = try zquic.Connection.Connection.init(allocator, .server, zquic.Connection.ConnectionParams{});
    defer connection.deinit();

    std.debug.print("Created server connection with ID: {any}\n", .{connection.local_conn_id});
    for (local_cid.bytes()) |byte| {
        std.debug.print("{X:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Simulate TLS handshake
    var handshake_manager = zquic.Handshake.HandshakeManager.init(allocator, true);
    defer handshake_manager.deinit();

    const conn_id_bytes = local_cid.bytes();
    try handshake_manager.startHandshake(conn_id_bytes);

    // Simulate processing client hello
    const client_hello = "ClientHello from client";
    try handshake_manager.processCryptoFrame(client_hello, 0);

    const server_response = handshake_manager.getPendingCryptoData();
    if (server_response.len > 0) {
        std.debug.print("Generated {} bytes of handshake data\n", .{server_response.len});
        handshake_manager.clearSentCryptoData();
    }

    // Simulate handshake completion
    connection.state = .established;
    std.debug.print("Handshake completed, connection established!\n", .{});

    // Create a server-initiated stream
    const stream = try connection.createStream(.server_bidirectional);
    std.debug.print("Created server stream with ID: {}\n", .{stream.id.id});

    // Simulate receiving client data
    try stream.receiveData("Hello from client!", 0, false);

    var buffer: [100]u8 = undefined;
    const read_len = connection.readStreamData(stream.id.id, &buffer);
    std.debug.print("Received {} bytes from client: '{s}'\n", .{ read_len, buffer[0..read_len] });

    // Send response
    const response = "Hello from ZQUIC server!";
    const written = try connection.sendStreamData(stream.id.id, response, true);
    std.debug.print("Sent {} bytes response: '{s}'\n", .{ written, response });

    // Demonstrate key management
    const initial_secret = "initial_secret_for_server";
    const initial_keys = try zquic.Crypto.CryptoKeys.deriveFromSecret(initial_secret);

    var key_manager = zquic.Keys.KeyManager.init(initial_keys);
    std.debug.print("Key manager initialized with phase: {}\n", .{key_manager.getCurrentKeyPhase()});

    // Simulate key update
    try key_manager.initiateKeyUpdate();
    std.debug.print("Key update initiated, pending: {}\n", .{key_manager.isUpdatePending()});

    key_manager.completeKeyUpdate();
    std.debug.print("Key update completed, new phase: {}\n", .{key_manager.getCurrentKeyPhase()});

    // Connection statistics
    std.debug.print("\nConnection Statistics:\n", .{});
    std.debug.print("  Packets sent: {}\n", .{connection.stats.packets_sent});
    std.debug.print("  Packets received: {}\n", .{connection.stats.packets_received});
    std.debug.print("  Bytes sent: {}\n", .{connection.stats.bytes_sent});
    std.debug.print("  Bytes received: {}\n", .{connection.stats.bytes_received});
    std.debug.print("  RTT: {} μs\n", .{connection.stats.rtt});
    std.debug.print("  Congestion window: {} bytes\n", .{connection.stats.congestion_window});

    std.debug.print("✅ Server example completed successfully!\n", .{});
}
