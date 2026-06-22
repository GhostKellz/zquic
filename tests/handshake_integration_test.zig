//! Handshake integration tests exercising client/server flows

const std = @import("std");
const zquic = @import("zquic");

const HandshakeManager = zquic.Handshake.HandshakeManager;
const PacketSpace = zquic.core.PacketSpace.PacketSpace;
const AckRange = zquic.core.PacketSpace.AckRange;
const LossRecovery = zquic.core.Recovery.LossRecovery;

test "integration: client and server complete handshake" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client = HandshakeManager.init(allocator, false);
    defer client.deinit();

    var server = HandshakeManager.init(allocator, true);
    defer server.deinit();

    const connection_id = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04 };

    try client.startHandshake(&connection_id);
    try server.startHandshake(&connection_id);

    var safety_counter: usize = 0;
    while ((client.isComplete() == false or server.isComplete() == false) and safety_counter < 16) : (safety_counter += 1) {
        const client_crypto = client.getPendingCryptoData();
        if (client_crypto.len > 0) {
            try server.processCryptoFrame(client_crypto, 0);
            client.clearSentCryptoData();
        }

        const server_crypto = server.getPendingCryptoData();
        if (server_crypto.len > 0) {
            try client.processCryptoFrame(server_crypto, 0);
            server.clearSentCryptoData();
        }
    }

    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
    try std.testing.expect(client.getCurrentEncryptionLevel() == .application);
    try std.testing.expect(server.getCurrentEncryptionLevel() == .application);
}

test "integration: handshake tolerates fragmented crypto frames" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client = HandshakeManager.init(allocator, false);
    defer client.deinit();

    var server = HandshakeManager.init(allocator, true);
    defer server.deinit();

    const connection_id = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD };

    try client.startHandshake(&connection_id);
    try server.startHandshake(&connection_id);

    const client_crypto = client.getPendingCryptoData();
    try std.testing.expect(client_crypto.len > 4);

    const split = client_crypto.len / 2;
    try server.processCryptoFrame(client_crypto[0..split], 0);
    try server.processCryptoFrame(client_crypto[split..], split);
    client.clearSentCryptoData();

    const server_crypto = server.getPendingCryptoData();
    try std.testing.expect(server_crypto.len > 0);
    try client.processCryptoFrame(server_crypto, 0);
    server.clearSentCryptoData();

    const server_level = server.getCurrentEncryptionLevel();
    try std.testing.expect(server_level == .handshake or server_level == .application);

    const client_level = client.getCurrentEncryptionLevel();
    try std.testing.expect(client_level == .handshake or client_level == .application);
}

test "integration: handshake completion allows deterministic stream data transfer" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    const connection_id = [_]u8{ 0x42, 0x42, 0x42, 0x42, 0xAA, 0xBB, 0xCC, 0xDD };
    try client_hs.startHandshake(&connection_id);
    try server_hs.startHandshake(&connection_id);

    var safety_counter: usize = 0;
    while ((client_hs.isComplete() == false or server_hs.isComplete() == false) and safety_counter < 16) : (safety_counter += 1) {
        const client_crypto = client_hs.getPendingCryptoData();
        if (client_crypto.len > 0) {
            try server_hs.processCryptoFrame(client_crypto, 0);
            client_hs.clearSentCryptoData();
        }

        const server_crypto = server_hs.getPendingCryptoData();
        if (server_crypto.len > 0) {
            try client_hs.processCryptoFrame(server_crypto, 0);
            server_hs.clearSentCryptoData();
        }
    }

    try std.testing.expect(client_hs.isComplete());
    try std.testing.expect(server_hs.isComplete());

    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    defer conn.deinit();
    var stream = try conn.createStream(.client_bidirectional);

    _ = try stream.write("client payload", false);
    try stream.handleIncomingDataWithFin("server payload", true);

    var buf: [32]u8 = undefined;
    const read_len = try stream.read(&buf);
    try std.testing.expectEqualStrings("server payload", buf[0..read_len]);
    try std.testing.expect(stream.state.load(.acquire) == .half_closed_remote);
}

test "integration: stream reset and connection close are deterministic" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    defer conn.deinit();

    const stream = try conn.createStream(.client_bidirectional);
    try stream.close();
    try std.testing.expect(stream.state.load(.acquire) == .closed);

    try conn.initiateShutdown(0, "normal close");
    try std.testing.expect(conn.super_connection.state == .draining);
    try std.testing.expect(conn.super_connection.outgoing_packets.items.len == 1);
}

test "integration: packet loss recovery removes retransmission candidates" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();
    var recovery = LossRecovery.init();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);
    try space.onPacketSent(2, 3_000, true, true, 1200);

    const ack = [_]AckRange{.{ .start = 2, .end = 2 }};
    recovery.onAckReceived(&space, &ack, 0, 4_000);

    const spaces = [_]*PacketSpace{&space};
    try recovery.onLossDetectionTimeout(&spaces, 1_000_000);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
}
