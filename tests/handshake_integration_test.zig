//! Handshake integration tests exercising client/server flows

const std = @import("std");
const zquic = @import("zquic");

const HandshakeManager = zquic.Handshake.HandshakeManager;
const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;
const PacketCrypto = zquic.PacketCrypto;
const TransportParameters = zquic.core.TransportParameters;
const QuicFrames = zquic.core.QuicFrames;
const PacketSpace = zquic.core.PacketSpace.PacketSpace;
const AckRange = zquic.core.PacketSpace.AckRange;
const LossRecovery = zquic.core.Recovery.LossRecovery;
const PtoProbePlan = zquic.core.Recovery.PtoProbePlan;
const FlowController = zquic.core.FlowControl.FlowController;
const ComprehensiveTls = zquic.ComprehensiveTls;
const UdpMultiplexer = zquic.UdpMultiplexer.UdpMultiplexer;
const MultiplexerConfig = zquic.UdpMultiplexer.MultiplexerConfig;
const NetAddress = zquic.NetAddress;

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

test "integration: handshake syncs packet crypto application keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client = HandshakeManager.init(allocator, false);
    defer client.deinit();

    var server = HandshakeManager.init(allocator, true);
    defer server.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();
    try client_tls.deriveApplicationKeys("owned raw queue application packet");
    try server_tls.deriveApplicationKeys("owned raw queue application packet");
    _ = try client_packets.refreshKeysFromTlsContext();
    _ = try server_packets.refreshKeysFromTlsContext();

    const connection_id = [_]u8{ 0xD0, 0xD1, 0xD2, 0xD3, 0x10, 0x11, 0x12, 0x13 };

    try client.startHandshake(&connection_id);
    try server.startHandshake(&connection_id);
    _ = try client.syncPacketCrypto(&client_tls, &client_packets, &connection_id);
    _ = try server.syncPacketCrypto(&server_tls, &server_packets, &connection_id);

    var safety_counter: usize = 0;
    while ((client.isComplete() == false or server.isComplete() == false) and safety_counter < 16) : (safety_counter += 1) {
        const client_crypto = client.getPendingCryptoData();
        if (client_crypto.len > 0) {
            try server.processCryptoFrame(client_crypto, 0);
            client.clearSentCryptoData();
            _ = try server.syncPacketCrypto(&server_tls, &server_packets, &connection_id);
        }

        const server_crypto = server.getPendingCryptoData();
        if (server_crypto.len > 0) {
            try client.processCryptoFrame(server_crypto, 0);
            server.clearSentCryptoData();
            _ = try client.syncPacketCrypto(&client_tls, &client_packets, &connection_id);
        }
    }

    _ = try client.syncPacketCrypto(&client_tls, &client_packets, &connection_id);
    _ = try server.syncPacketCrypto(&server_tls, &server_packets, &connection_id);

    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
    try std.testing.expect(client_tls.application_keys != null);
    try std.testing.expect(server_tls.application_keys != null);

    const header = [_]u8{ 0x40, 0xD0, 0xD1, 0xD2, 0xD3 };
    const payload = "application payload after live handshake sync";
    const ciphertext = try client_packets.encryptPacket(.application, 1337, &header, payload);
    defer allocator.free(ciphertext);

    const plaintext = try server_packets.decryptPacket(.application, 1337, &header, ciphertext);
    defer allocator.free(plaintext);
    try std.testing.expectEqualStrings(payload, plaintext);

    var wrong_server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer wrong_server_tls.deinit();
    var wrong_server_packets = try PacketCrypto.init(allocator, &wrong_server_tls, null);
    defer wrong_server_packets.deinit();
    const wrong_connection_id = [_]u8{ 0xD0, 0xD1, 0xD2, 0xD3, 0x10, 0x11, 0x12, 0x99 };
    try server.deriveEnhancedPacketKeys(&wrong_server_tls, &wrong_connection_id);
    _ = try wrong_server_packets.refreshKeysFromTlsContext();

    try std.testing.expectError(
        error.CryptoError,
        wrong_server_packets.decryptPacket(.application, 1337, &header, ciphertext),
    );
}

test "integration: protected stream payload is decrypted and dispatched by connection" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("connection protected packet path");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("connection protected packet path");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var payload_buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{ .stream = QuicFrames.StreamFrame.init(0, 0, "protected stream payload", true, false, true) }).serialize(&writer);
    const plaintext_payload = std.Io.Writer.buffered(&writer);

    const header = [_]u8{ 0x40, 0x01, 0x02, 0x03, 0x04 };
    const ciphertext = try client_conn.protectPacketPayloadForSend(&client_packets, .application, 44, &header, plaintext_payload);
    defer allocator.free(ciphertext);

    try server_conn.processProtectedPacketPayload(&server_packets, .application, 44, &header, ciphertext);

    const stream = server_conn.streams.get(0).?;
    var read_buf: [64]u8 = undefined;
    const read_len = try stream.read(&read_buf);
    try std.testing.expectEqualStrings("protected stream payload", read_buf[0..read_len]);
    try std.testing.expect(stream.state.load(.acquire) == .half_closed_remote);
}

test "integration: owned raw packet queue decrypts and dispatches stream data" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("owned raw queue application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("owned raw queue application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var payload_buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{ .stream = QuicFrames.StreamFrame.init(0, 0, "owned raw packet payload", true, false, true) }).serialize(&writer);
    const plaintext_payload = std.Io.Writer.buffered(&writer);

    const dcid = [_]u8{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };
    try client_conn.sendProtectedRawPacket(&client_packets, .application, .one_rtt, &dcid, &.{}, plaintext_payload);

    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 1), outgoing.len);
    defer outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(outgoing[0].data);
    var processed = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);
    try std.testing.expectEqual(.application, processed.encryption_level);

    const stream = server_conn.streams.get(0).?;
    var read_buf: [64]u8 = undefined;
    const read_len = try stream.read(&read_buf);
    try std.testing.expectEqualStrings("owned raw packet payload", read_buf[0..read_len]);
    try std.testing.expect(stream.state.load(.acquire) == .half_closed_remote);
}

test "integration: 0-RTT raw stream data fails closed unless explicitly accepted" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var rejecting_server = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer rejecting_server.deinit();
    var accepting_server = try zquic.Connection.SuperConnection.init(allocator, .server, .{ .accept_early_data = true });
    defer accepting_server.deinit();

    for ([_]*zquic.Connection.SuperConnection{ &rejecting_server, &accepting_server }) |server| {
        try server.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
        try server.processPendingStreamEvents();
    }

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var payload_buf: [160]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{ .stream_len = QuicFrames.StreamFrame.init(0, 0, "early bytes", false, false, true) }).serialize(&writer);
    const early_payload = std.Io.Writer.buffered(&writer);

    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const scid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };

    try client_conn.sendProtectedRawPacket(&client_packets, .early_data, .zero_rtt, &dcid, &scid, early_payload);
    var rejected_packets = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(rejected_packets);
    defer rejected_packets[0].deinit(allocator);

    try rejecting_server.queueIncomingRawPacket(rejected_packets[0].data);
    try std.testing.expectError(
        error.ProtocolViolation,
        rejecting_server.processNextIncomingRawPacket(&server_packets, null),
    );

    try client_conn.sendProtectedRawPacket(&client_packets, .early_data, .zero_rtt, &dcid, &scid, early_payload);
    var accepted_packets = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(accepted_packets);
    defer accepted_packets[0].deinit(allocator);

    try accepting_server.queueIncomingRawPacket(accepted_packets[0].data);
    var processed = (try accepting_server.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed.deinit(allocator);
    try std.testing.expectEqual(.early_data, processed.encryption_level);

    const stream = accepting_server.streams.get(0).?;
    var read_buf: [32]u8 = undefined;
    const read_len = try stream.read(&read_buf);
    try std.testing.expectEqualStrings("early bytes", read_buf[0..read_len]);
}

test "integration: application packet key rollover rejects old packets until sender updates" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    var old_client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer old_client_tls.deinit();
    try old_client_tls.deriveApplicationKeys("old application traffic secret");
    var old_server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer old_server_tls.deinit();
    try old_server_tls.deriveApplicationKeys("old application traffic secret");
    var old_client_packets = try PacketCrypto.init(allocator, &old_client_tls, null);
    defer old_client_packets.deinit();
    var old_server_packets = try PacketCrypto.init(allocator, &old_server_tls, null);
    defer old_server_packets.deinit();

    var new_client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer new_client_tls.deinit();
    try new_client_tls.deriveApplicationKeys("new application traffic secret");
    var new_server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer new_server_tls.deinit();
    try new_server_tls.deriveApplicationKeys("new application traffic secret");
    var new_client_packets = try PacketCrypto.init(allocator, &new_client_tls, null);
    defer new_client_packets.deinit();
    var new_server_packets = try PacketCrypto.init(allocator, &new_server_tls, null);
    defer new_server_packets.deinit();

    var old_payload_buf: [160]u8 = undefined;
    var old_writer = std.Io.Writer.fixed(&old_payload_buf);
    try (QuicFrames.Frame{ .stream_len = QuicFrames.StreamFrame.init(0, 0, "old key bytes", false, false, true) }).serialize(&old_writer);

    const dcid = [_]u8{ 0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1 };
    try client_conn.sendProtectedRawPacket(&old_client_packets, .application, .one_rtt, &dcid, &.{}, std.Io.Writer.buffered(&old_writer));
    var old_packets = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(old_packets);
    defer old_packets[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(old_packets[0].data);
    try std.testing.expectError(
        error.CryptoError,
        server_conn.processNextIncomingRawPacket(&new_server_packets, null),
    );

    try server_conn.queueIncomingRawPacket(old_packets[0].data);
    var old_processed = (try server_conn.processNextIncomingRawPacket(&old_server_packets, null)).?;
    defer old_processed.deinit(allocator);

    var new_payload_buf: [160]u8 = undefined;
    var new_writer = std.Io.Writer.fixed(&new_payload_buf);
    try (QuicFrames.Frame{ .stream_len = QuicFrames.StreamFrame.init(0, @intCast("old key bytes".len), "new key bytes", false, true, true) }).serialize(&new_writer);
    try client_conn.sendProtectedRawPacket(&new_client_packets, .application, .one_rtt, &dcid, &.{}, std.Io.Writer.buffered(&new_writer));
    var new_packets = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(new_packets);
    defer new_packets[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(new_packets[0].data);
    var new_processed = (try server_conn.processNextIncomingRawPacket(&new_server_packets, old_processed.packet_number)).?;
    defer new_processed.deinit(allocator);

    const stream = server_conn.streams.get(0).?;
    var read_buf: [64]u8 = undefined;
    const read_len = try stream.read(&read_buf);
    try std.testing.expectEqualStrings("old key bytesnew key bytes", read_buf[0..read_len]);
}

test "integration: scheduler sends flow-control frames through raw packet path" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("scheduler flow control application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("scheduler flow control application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var flow = FlowController.init(allocator, 1_000, 1_000);
    defer flow.deinit();
    try flow.addStream(0, 1_000, 1_000);
    try flow.consumeRecvCredit(0, 600);
    try flow.queueReceiveWindowUpdates();

    const dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const scheduled = try client_conn.scheduleFlowControlFrames(&client_packets, &flow, &dcid);
    try std.testing.expect(scheduled >= 1);
    try std.testing.expectEqual(@as(usize, 1), client_conn.outgoing_raw_packets.items.len);

    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    defer outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(outgoing[0].data);
    var processed = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed.deinit(allocator);

    try std.testing.expectEqual(.application, processed.encryption_level);
    try std.testing.expect(server_conn.params.initial_max_data > 1_000);
    try std.testing.expectEqual(@as(usize, 0), flow.pending_frames.items.len);
}

test "integration: scheduler sends PTO probe pings through raw packet path" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("scheduler pto application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("scheduler pto application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    const dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const scid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const scheduled = try client_conn.schedulePtoProbePackets(
        &client_packets,
        PtoProbePlan{ .initial = true, .application = true, .count = 2 },
        &dcid,
        &scid,
    );
    try std.testing.expectEqual(@as(usize, 2), scheduled);
    try std.testing.expectEqual(@as(usize, 2), client_conn.outgoing_raw_packets.items.len);

    const outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    defer {
        for (outgoing) |packet| {
            var owned = packet;
            owned.deinit(allocator);
        }
    }

    for (outgoing) |packet| {
        try server_conn.queueIncomingRawPacket(packet.data);
    }

    var initial = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer initial.deinit(allocator);
    var application = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer application.deinit(allocator);

    try std.testing.expectEqual(.initial, initial.encryption_level);
    try std.testing.expectEqual(.application, application.encryption_level);
    try std.testing.expectEqual(@as(u64, 2), server_conn.stats.packets_received);
}

test "integration: raw packet receive schedules ack and peer processes it" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("raw ack feedback application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("raw ack feedback application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var payload_buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{ .stream_len = QuicFrames.StreamFrame.init(0, 0, "ack me", false, false, true) }).serialize(&writer);
    const dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };

    try client_conn.sendProtectedRawPacket(&client_packets, .application, .one_rtt, &dcid, &.{}, std.Io.Writer.buffered(&writer));
    try std.testing.expectEqual(@as(usize, 1), client_conn.packet_spaces.application.sent_packets.count());

    var client_to_server = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(client_to_server);
    defer client_to_server[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(client_to_server[0].data);
    var processed_stream = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed_stream.deinit(allocator);

    try std.testing.expect(server_conn.ack_trackers[2].ack_required);
    const ack_count = try server_conn.schedulePendingAckFrames(&server_packets, &dcid, &.{});
    try std.testing.expectEqual(@as(usize, 1), ack_count);

    var server_to_client = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_to_client);
    defer server_to_client[0].deinit(allocator);

    try client_conn.queueIncomingRawPacket(server_to_client[0].data);
    var processed_ack = (try client_conn.processNextIncomingRawPacket(&client_packets, null)).?;
    defer processed_ack.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), client_conn.packet_spaces.application.sent_packets.count());
}

test "integration: scheduler sends stream write buffers through raw packet path" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try client_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try client_conn.processPendingStreamEvents();
    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    const client_stream = client_conn.streams.get(0).?;
    _ = try client_stream.write("scheduled stream bytes", false);

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("scheduler stream data application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("scheduler stream data application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    const dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const scheduled = try client_conn.scheduleStreamDataFrames(&client_packets, &dcid, 1200);
    try std.testing.expectEqual(@as(usize, 1), scheduled);
    try std.testing.expectEqual(@as(usize, 0), client_stream.pendingWriteData().len);

    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    defer outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(outgoing[0].data);
    var processed = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed.deinit(allocator);

    const server_stream = server_conn.streams.get(0).?;
    var read_buf: [64]u8 = undefined;
    const read_len = try server_stream.read(&read_buf);
    try std.testing.expectEqualStrings("scheduled stream bytes", read_buf[0..read_len]);
}

test "integration: UDP loopback routes protected datagram into raw queue" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const local = NetAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    var client_mux = UdpMultiplexer.init(allocator, local, MultiplexerConfig{}) catch return;
    defer client_mux.deinit();
    var server_mux = UdpMultiplexer.init(allocator, local, MultiplexerConfig{}) catch return;
    defer server_mux.deinit();

    var client_conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.Connection.init(allocator, .server, .{});
    defer server_conn.deinit();

    try server_conn.queueStreamEvent(.{ .new_stream = .{ .stream_id = 0, .stream_type = .client_bidirectional } });
    try server_conn.processPendingStreamEvents();

    const client_cid = try zquic.Packet.ConnectionId.init(&[_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 });
    const server_cid = try zquic.Packet.ConnectionId.init(&[_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 });
    try client_mux.addConnection(client_cid, &client_conn, server_mux.socket.local_address);
    try server_mux.addConnection(server_cid, &server_conn, client_mux.socket.local_address);

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("udp loopback application packet");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("udp loopback application packet");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var payload_buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{ .stream_len = QuicFrames.StreamFrame.init(0, 0, "udp loopback", false, false, true) }).serialize(&writer);

    try client_conn.super_connection.sendProtectedRawPacket(
        &client_packets,
        .application,
        .one_rtt,
        server_cid.bytes(),
        &.{},
        std.Io.Writer.buffered(&writer),
    );
    try std.testing.expectEqual(@as(u32, 1), try client_mux.flushConnectionRawPackets(&client_cid));

    var routed = false;
    for (0..16) |_| {
        if (try server_mux.tryReceiveAndRoute()) {
            routed = true;
            break;
        }
        zquic.core.Time.sleep(std.time.ns_per_ms);
    }
    try std.testing.expect(routed);
    try std.testing.expectEqual(@as(usize, 1), server_conn.super_connection.incoming_raw_packets.items.len);

    var processed = (try server_conn.super_connection.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed.deinit(allocator);

    const server_stream = server_conn.getStream(0).?;
    var read_buf: [32]u8 = undefined;
    const read_len = try server_stream.read(&read_buf);
    try std.testing.expectEqualStrings("udp loopback", read_buf[0..read_len]);
}

test "integration: owned raw initial crypto packet advances handshake through long header" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    const connection_id = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const server_scid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4 };
    try client_hs.startHandshake(&connection_id);
    try server_hs.startHandshake(&connection_id);

    var crypto_payload_buf: [512]u8 = undefined;
    var crypto_writer = std.Io.Writer.fixed(&crypto_payload_buf);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, client_hs.getPendingCryptoData()) }).serialize(&crypto_writer);
    const crypto_payload = std.Io.Writer.buffered(&crypto_writer);

    try client_conn.sendProtectedRawPacket(&client_packets, .initial, .initial, &connection_id, &server_scid, crypto_payload);
    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 1), outgoing.len);
    defer outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(outgoing[0].data);
    var processed = (try server_conn.processNextIncomingRawCryptoPacket(
        &server_packets,
        &server_hs,
        &server_tls,
        &connection_id,
        null,
    )).?;
    defer processed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);
    try std.testing.expectEqual(.initial, processed.encryption_level);
    try std.testing.expect(server_hs.getPendingCryptoData().len > 0);
    try std.testing.expect(server_conn.state == .handshake);
}

test "integration: connection path schedules protected server initial crypto flight" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    const original_dcid = [_]u8{ 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 };
    const client_scid = [_]u8{ 0xC1, 0xC2, 0xC3, 0xC4 };
    const server_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    try client_hs.startHandshake(&original_dcid);
    try server_hs.startHandshake(&original_dcid);
    try client_packets.installRfc9001ClientInitialKeys(&original_dcid);
    try server_packets.installRfc9001ServerInitialKeys(&original_dcid);

    var client_crypto_payload_buf: [512]u8 = undefined;
    var client_crypto_writer = std.Io.Writer.fixed(&client_crypto_payload_buf);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, client_hs.getPendingCryptoData()) }).serialize(&client_crypto_writer);
    const client_crypto_payload = std.Io.Writer.buffered(&client_crypto_writer);

    try client_conn.sendProtectedRawPacket(&client_packets, .initial, .initial, &original_dcid, &client_scid, client_crypto_payload);
    var client_outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(client_outgoing);
    try std.testing.expectEqual(@as(usize, 1), client_outgoing.len);
    defer client_outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(client_outgoing[0].data);
    const scheduled = try server_conn.processNextIncomingInitialCryptoAndScheduleServerFlight(
        &server_packets,
        &server_hs,
        &client_scid,
        &server_scid,
        null,
    );
    try std.testing.expectEqual(@as(usize, 1), scheduled);
    try std.testing.expectEqual(@as(usize, 0), server_hs.getPendingCryptoData().len);
    try std.testing.expect(server_conn.state == .handshake);

    var server_outgoing = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_outgoing);
    try std.testing.expectEqual(@as(usize, 1), server_outgoing.len);
    defer server_outgoing[0].deinit(allocator);

    var processed = try client_packets.processProtectedRawPacket(server_outgoing[0].data, null);
    defer processed.deinit(allocator);
    try std.testing.expectEqual(.initial, processed.encryption_level);
    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);

    var reader = std.Io.Reader.fixed(processed.payload);
    const frame = try QuicFrames.Frame.parse(&reader, allocator);
    defer switch (frame) {
        .crypto => |crypto| allocator.free(crypto.data),
        else => {},
    };
    try std.testing.expect(frame == .crypto);
    try std.testing.expect(frame.crypto.data.len > 0);
}

test "integration: owned raw handshake crypto packet uses long-header handshake keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    const connection_id = [_]u8{ 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8 };
    try client_hs.startHandshake(&connection_id);
    try server_hs.startHandshake(&connection_id);

    try server_hs.processCryptoFrame(client_hs.getPendingCryptoData(), 0);
    client_hs.clearSentCryptoData();
    try client_hs.processCryptoFrame(server_hs.getPendingCryptoData(), 0);
    server_hs.clearSentCryptoData();

    try client_tls.deriveHandshakeKeys("owned raw long header handshake secret");
    try server_tls.deriveHandshakeKeys("owned raw long header handshake secret");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var crypto_payload_buf: [128]u8 = undefined;
    var crypto_writer = std.Io.Writer.fixed(&crypto_payload_buf);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, client_hs.getPendingCryptoData()) }).serialize(&crypto_writer);
    const crypto_payload = std.Io.Writer.buffered(&crypto_writer);

    try client_conn.sendProtectedRawPacket(&client_packets, .handshake, .handshake, &connection_id, &.{ 0xC1, 0xC2, 0xC3, 0xC4 }, crypto_payload);
    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 1), outgoing.len);
    defer outgoing[0].deinit(allocator);

    try server_conn.queueIncomingRawPacket(outgoing[0].data);
    var processed = (try server_conn.processNextIncomingRawCryptoPacket(
        &server_packets,
        &server_hs,
        &server_tls,
        &connection_id,
        null,
    )).?;
    defer processed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);
    try std.testing.expectEqual(.handshake, processed.encryption_level);
}

test "integration: connection path schedules protected handshake crypto flight" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    const connection_id = [_]u8{ 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8 };
    try client_hs.startHandshake(&connection_id);
    try server_hs.startHandshake(&connection_id);

    try server_hs.processCryptoFrame(client_hs.getPendingCryptoData(), 0);
    client_hs.clearSentCryptoData();
    try client_hs.processCryptoFrame(server_hs.getPendingCryptoData(), 0);
    server_hs.clearSentCryptoData();
    try std.testing.expect(client_hs.getPendingCryptoData().len > 0);

    try client_tls.deriveHandshakeKeys("connection path handshake flight secret");
    try server_tls.deriveHandshakeKeys("connection path handshake flight secret");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();

    const scheduled = try client_conn.schedulePendingCryptoAsProtectedRawPacket(
        &client_packets,
        &client_hs,
        .handshake,
        .handshake,
        &connection_id,
        &.{ 0xE9, 0xEA, 0xEB, 0xEC },
    );
    try std.testing.expect(scheduled);
    try std.testing.expectEqual(@as(usize, 0), client_hs.getPendingCryptoData().len);

    var outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 1), outgoing.len);
    defer outgoing[0].deinit(allocator);

    var processed = try server_packets.processProtectedRawPacket(outgoing[0].data, null);
    defer processed.deinit(allocator);
    try std.testing.expectEqual(.handshake, processed.encryption_level);
    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);

    var reader = std.Io.Reader.fixed(processed.payload);
    const frame = try QuicFrames.Frame.parse(&reader, allocator);
    defer switch (frame) {
        .crypto => |crypto| allocator.free(crypto.data),
        else => {},
    };
    try std.testing.expect(frame == .crypto);
    try std.testing.expect(frame.crypto.data.len > 0);
}

test "integration: protected crypto payload advances handshake and refreshes packet keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    const connection_id = [_]u8{ 0xC1, 0xC2, 0xC3, 0xC4, 0xA0, 0xA1, 0xA2, 0xA3 };
    try client_hs.startHandshake(&connection_id);
    try server_hs.startHandshake(&connection_id);
    _ = try client_hs.syncPacketCrypto(&client_tls, &client_packets, &connection_id);
    _ = try server_hs.syncPacketCrypto(&server_tls, &server_packets, &connection_id);

    var crypto_payload_buf: [512]u8 = undefined;
    var crypto_writer = std.Io.Writer.fixed(&crypto_payload_buf);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, client_hs.getPendingCryptoData()) }).serialize(&crypto_writer);
    const crypto_payload = std.Io.Writer.buffered(&crypto_writer);

    const header = [_]u8{ 0xc0, 0xC1, 0xC2, 0xC3, 0xC4 };
    const ciphertext = try client_packets.encryptPacket(.initial, 1, &header, crypto_payload);
    defer allocator.free(ciphertext);

    const installed = try server_conn.processProtectedCryptoPacketPayload(
        &server_packets,
        &server_hs,
        &server_tls,
        &connection_id,
        .initial,
        1,
        &header,
        ciphertext,
    );
    try std.testing.expect(installed >= 1);
    try std.testing.expect(server_hs.getPendingCryptoData().len > 0);
    try std.testing.expect(server_conn.state == .handshake);
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

    var close_reader = std.Io.Reader.fixed(conn.super_connection.outgoing_packets.items[0].payload);
    const frame = try QuicFrames.Frame.parse(&close_reader, allocator);
    switch (frame) {
        .connection_close => |close| {
            defer allocator.free(close.reason_phrase);
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqualStrings("normal close", close.reason_phrase);
        },
        else => return error.UnexpectedFrame,
    }
    try std.testing.expect(conn.super_connection.isShuttingDown());
    try std.testing.expect(!conn.super_connection.isTerminated());
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

test "interop: transport parameters round trip negotiated fields" {
    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const initial_scid = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    const params = TransportParameters.TransportParameters{
        .max_idle_timeout = 45_000,
        .max_udp_payload_size = 1350,
        .initial_max_data = 4 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 384 * 1024,
        .initial_max_stream_data_uni = 128 * 1024,
        .initial_max_streams_bidi = 64,
        .initial_max_streams_uni = 32,
        .ack_delay_exponent = 10,
        .max_ack_delay = 50,
        .disable_active_migration = true,
        .active_connection_id_limit = 6,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &initial_scid,
        .retry_source_connection_id = &retry_scid,
    };

    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try TransportParameters.encode(params, &writer);

    const decoded = try TransportParameters.decode(std.Io.Writer.buffered(&writer));
    try std.testing.expectEqual(@as(u64, 45_000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1350), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 256 * 1024), decoded.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u64, 384 * 1024), decoded.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 128 * 1024), decoded.initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 64), decoded.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 32), decoded.initial_max_streams_uni);
    try std.testing.expectEqual(@as(u8, 10), decoded.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 50), decoded.max_ack_delay);
    try std.testing.expect(decoded.disable_active_migration);
    try std.testing.expectEqual(@as(u64, 6), decoded.active_connection_id_limit);
    try std.testing.expectEqualSlices(u8, &original_dcid, decoded.original_destination_connection_id);
    try std.testing.expectEqualSlices(u8, &initial_scid, decoded.initial_source_connection_id);
    try std.testing.expectEqualSlices(u8, &retry_scid, decoded.retry_source_connection_id);
    try std.testing.expectEqual(TransportParameters.PreferredAddressPosture.absent, decoded.preferred_address);
}

test "interop: transport parameters decode peer vector" {
    const vector = [_]u8{
        0x04, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_data = 1048576
        0x08, 0x02, 0x40, 0x80, // initial_max_streams_bidi = 128
        0x09, 0x02, 0x40, 0x40, // initial_max_streams_uni = 64
        0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout = 30000
        0x0a, 0x01, 0x03, // ack_delay_exponent = 3
        0x0e, 0x01, 0x04, // active_connection_id_limit = 4
        0x0c, 0x00, // disable_active_migration
    };

    const decoded = try TransportParameters.decode(&vector);
    try std.testing.expectEqual(@as(u64, 1_048_576), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 128), decoded.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 64), decoded.initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 30_000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u8, 3), decoded.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 4), decoded.active_connection_id_limit);
    try std.testing.expect(decoded.disable_active_migration);
}

test "interop: transport parameters reject malformed inputs" {
    const duplicate_initial_max_data = [_]u8{
        0x04, 0x01, 0x3f,
        0x04, 0x01, 0x3e,
    };
    try std.testing.expectError(error.ProtocolViolation, TransportParameters.decode(&duplicate_initial_max_data));

    const disable_migration_with_value = [_]u8{ 0x0c, 0x01, 0x00 };
    try std.testing.expectError(error.InvalidData, TransportParameters.decode(&disable_migration_with_value));

    const bad_ack_delay_exponent = [_]u8{ 0x0a, 0x02, 0x40, 0x15 };
    try std.testing.expectError(error.InvalidArgument, TransportParameters.decode(&bad_ack_delay_exponent));

    const active_cid_limit_too_low = [_]u8{ 0x0e, 0x01, 0x01 };
    try std.testing.expectError(error.InvalidArgument, TransportParameters.decode(&active_cid_limit_too_low));
}

test "interop: transport parameters reject preferred address until supported" {
    const preferred_address = [_]u8{
        0x0d, 0x01, 0x01,
    };
    try std.testing.expectError(error.NotSupported, TransportParameters.decode(&preferred_address));
}

test "phase3: transport parameter negotiation validates server remembered connection ids" {
    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const server_initial_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    const server_params = TransportParameters.TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &retry_scid,
        .disable_active_migration = true,
    };

    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try TransportParameters.encode(server_params, &writer);
    const decoded = try TransportParameters.decode(std.Io.Writer.buffered(&writer));

    try TransportParameters.validateForHandshake(decoded, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &retry_scid,
        .require_disable_active_migration = true,
    });

    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(decoded, .{
        .peer_role = .server,
        .original_destination_connection_id = &[_]u8{ 0x00, 0x01, 0x02, 0x03 },
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &retry_scid,
    }));

    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(decoded, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
    }));
}

test "phase3: transport parameter negotiation rejects role-invalid connection ids" {
    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const client_initial_scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    const client_params = TransportParameters.TransportParameters{
        .initial_source_connection_id = &client_initial_scid,
        .disable_active_migration = true,
    };
    try TransportParameters.validateForHandshake(client_params, .{
        .peer_role = .client,
        .initial_source_connection_id = &client_initial_scid,
        .require_disable_active_migration = true,
    });

    const client_with_server_only_params = TransportParameters.TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &client_initial_scid,
    };
    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(client_with_server_only_params, .{
        .peer_role = .client,
        .initial_source_connection_id = &client_initial_scid,
    }));

    const server_missing_original_dcid = TransportParameters.TransportParameters{
        .initial_source_connection_id = &client_initial_scid,
    };
    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(server_missing_original_dcid, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &client_initial_scid,
    }));

    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(client_params, .{
        .peer_role = .client,
        .initial_source_connection_id = &[_]u8{ 0x05, 0x06, 0x07, 0x08 },
    }));
}

test "phase3: transport parameter negotiation enforces migration flags and invalid limits" {
    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const server_initial_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };

    const migration_enabled = TransportParameters.TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .disable_active_migration = false,
    };
    try std.testing.expectError(error.ProtocolViolation, TransportParameters.validateForHandshake(migration_enabled, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .require_disable_active_migration = true,
    }));

    const invalid_active_cid_limit = TransportParameters.TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .active_connection_id_limit = 1,
    };
    try std.testing.expectError(error.InvalidArgument, TransportParameters.validateForHandshake(invalid_active_cid_limit, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    }));
}

test "integration: connection retains validated TLS peer transport parameters" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    defer conn.deinit();

    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const server_initial_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    const server_params = TransportParameters.TransportParameters{
        .max_idle_timeout = 9_000,
        .max_udp_payload_size = 1350,
        .initial_max_data = 512 * 1024,
        .initial_max_streams_bidi = 16,
        .active_connection_id_limit = 4,
        .disable_active_migration = true,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &retry_scid,
    };

    try conn.applyPeerTransportParameters(server_params, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .retry_source_connection_id = &retry_scid,
        .require_disable_active_migration = true,
    });

    const retained = conn.getPeerTransportParameters().?;
    try std.testing.expectEqual(@as(u64, 9_000), retained.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1350), retained.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 512 * 1024), retained.initial_max_data);
    try std.testing.expectEqual(@as(u64, 16), retained.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 4), retained.active_connection_id_limit);
    try std.testing.expect(retained.disable_active_migration);
    try std.testing.expectEqualSlices(u8, &original_dcid, retained.originalDestinationConnectionId());
    try std.testing.expectEqualSlices(u8, &server_initial_scid, retained.initialSourceConnectionId());
    try std.testing.expectEqualSlices(u8, &retry_scid, retained.retrySourceConnectionId());

    const mismatched_params = TransportParameters.TransportParameters{
        .original_destination_connection_id = &[_]u8{ 0xca, 0xfe },
        .initial_source_connection_id = &server_initial_scid,
    };
    try std.testing.expectError(error.ProtocolViolation, conn.applyPeerTransportParameters(mismatched_params, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    }));

    const still_retained = conn.getPeerTransportParameters().?;
    try std.testing.expectEqualSlices(u8, &original_dcid, still_retained.originalDestinationConnectionId());
}

test "integration: connection applies Comprehensive TLS peer transport parameters" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer conn.deinit();

    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, false);
    defer tls.deinit();

    const original_dcid = [_]u8{ 0x44, 0x45, 0x46, 0x47 };
    const server_initial_scid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    tls.peer_quic_transport_params = TransportParameters.TransportParameters{
        .max_idle_timeout = 12_000,
        .max_udp_payload_size = 1400,
        .initial_max_data = 2 * 1024 * 1024,
        .initial_max_streams_bidi = 32,
        .active_connection_id_limit = 5,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    };

    try conn.applyPeerTransportParametersFromTls(&tls, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    });

    const retained = conn.getPeerTransportParameters().?;
    try std.testing.expectEqual(@as(u64, 12_000), retained.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1400), retained.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), retained.initial_max_data);
    try std.testing.expectEqual(@as(u64, 32), retained.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 5), retained.active_connection_id_limit);
    try std.testing.expectEqualSlices(u8, &original_dcid, retained.originalDestinationConnectionId());
    try std.testing.expectEqualSlices(u8, &server_initial_scid, retained.initialSourceConnectionId());
}
