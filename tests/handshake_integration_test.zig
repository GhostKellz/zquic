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
const Tls13Messages = zquic.Tls13Messages;
const Tls13KeySchedule = zquic.Tls13KeySchedule;
const Tls13Identity = zquic.Tls13Identity;
const MinimalHttp3 = zquic.Http3.MinimalInterop;
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

    const client_to_server = try client_conn.drainOutgoingRawPackets(allocator);
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

test "integration: discontiguous receive history produces exact ACK ranges" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("discontiguous ack ranges");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("discontiguous ack ranges");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    const dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const ping_payload = [_]u8{ 0x01, 0x00, 0x00, 0x00 };

    try client_conn.sendProtectedRawPacket(&client_packets, .application, .one_rtt, &dcid, &.{}, &ping_payload);
    const skipped_packet = try client_packets.createProtectedRawPacket(.application, .one_rtt, &dcid, &.{}, &ping_payload);
    defer allocator.free(skipped_packet);
    try client_conn.sendProtectedRawPacket(&client_packets, .application, .one_rtt, &dcid, &.{}, &ping_payload);

    const client_to_server = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(client_to_server);
    defer for (client_to_server) |*packet| packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client_to_server.len);

    try server_conn.queueIncomingRawPacket(client_to_server[0].data);
    try server_conn.queueIncomingRawPacket(client_to_server[1].data);
    var first = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer first.deinit(allocator);
    var second = (try server_conn.processNextIncomingRawPacket(&server_packets, first.packet_number)).?;
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet_number);
    try std.testing.expectEqual(@as(u64, 2), second.packet_number);

    const scheduled = try server_conn.schedulePendingAckFramesWithMetadata(&server_packets, &dcid, &.{});
    try std.testing.expectEqual(@as(usize, 1), scheduled.count);
    try std.testing.expectEqual(.application, scheduled.slice()[0].encryption_level);
    try std.testing.expectEqual(@as(u64, 2), scheduled.slice()[0].largest_acknowledged);
    try std.testing.expectEqual(@as(usize, 2), scheduled.slice()[0].range_count);

    var server_to_client = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_to_client);
    defer server_to_client[0].deinit(allocator);
    var processed_ack = try client_packets.processProtectedRawPacket(server_to_client[0].data, null);
    defer processed_ack.deinit(allocator);

    var reader = std.Io.Reader.fixed(processed_ack.payload);
    const frame = try QuicFrames.Frame.parse(&reader, allocator);
    defer if (frame == .ack) frame.ack.deinit(allocator);
    try std.testing.expect(frame == .ack);
    try std.testing.expectEqual(@as(u64, 2), frame.ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), frame.ack.first_ack_range);
    try std.testing.expectEqual(@as(u64, 1), frame.ack.ack_range_count);
    try std.testing.expectEqual(@as(u64, 0), frame.ack.ack_ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), frame.ack.ack_ranges[0].ack_range_length);
}

test "integration: ACK processing is isolated by packet number space" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveHandshakeKeys("ack packet number space isolation");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveHandshakeKeys("ack packet number space isolation");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    const dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const scid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    try client_packets.installRfc9001ClientInitialKeys(&dcid);
    try server_packets.installRfc9001ServerInitialKeys(&dcid);
    const ping_payload = [_]u8{ 0x01, 0x00, 0x00, 0x00 };

    try client_conn.sendProtectedRawPacket(&client_packets, .initial, .initial, &dcid, &scid, &ping_payload);
    try client_conn.sendProtectedRawPacket(&client_packets, .handshake, .handshake, &dcid, &scid, &ping_payload);
    try std.testing.expectEqual(@as(usize, 1), client_conn.packet_spaces.initial.sent_packets.count());
    try std.testing.expectEqual(@as(usize, 1), client_conn.packet_spaces.handshake.sent_packets.count());

    const client_to_server = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(client_to_server);
    defer for (client_to_server) |*packet| packet.deinit(allocator);
    try server_conn.queueIncomingRawPacket(client_to_server[0].data);
    var processed_initial = (try server_conn.processNextIncomingRawPacket(&server_packets, null)).?;
    defer processed_initial.deinit(allocator);
    try std.testing.expectEqual(.initial, processed_initial.encryption_level);

    const scheduled = try server_conn.schedulePendingAckFramesWithMetadata(&server_packets, &scid, &dcid);
    try std.testing.expectEqual(@as(usize, 1), scheduled.count);
    try std.testing.expectEqual(.initial, scheduled.slice()[0].encryption_level);

    var server_to_client = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_to_client);
    defer server_to_client[0].deinit(allocator);
    try client_conn.queueIncomingRawPacket(server_to_client[0].data);
    var processed_ack = (try client_conn.processNextIncomingRawPacket(&client_packets, null)).?;
    defer processed_ack.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), client_conn.packet_spaces.initial.sent_packets.count());
    try std.testing.expectEqual(@as(usize, 1), client_conn.packet_spaces.handshake.sent_packets.count());
    client_conn.discardPacketNumberSpace(.handshake);
    try std.testing.expectEqual(.discarded, client_conn.packet_spaces.handshake.state);
    try std.testing.expectEqual(@as(usize, 0), client_conn.packet_spaces.handshake.sent_packets.count());
    try std.testing.expectEqual(@as(?u64, null), client_conn.recoveryDeadline());
}

test "integration: PTO retransmits retained CRYPTO at its original offset" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();
    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();

    const original_dcid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_scid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_scid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const crypto_offset: u64 = 37;
    const crypto_bytes = "retained handshake bytes for deterministic PTO retransmission";
    try server_packets.installRfc9001ServerInitialKeys(&original_dcid);
    try client_packets.installRfc9001ClientInitialKeys(&original_dcid);

    const original = (try server_conn.scheduleCryptoBytesAsProtectedRawPacket(
        &server_packets,
        .initial,
        .initial,
        &client_scid,
        &server_scid,
        crypto_offset,
        crypto_bytes,
    )).?;
    try std.testing.expectEqual(crypto_bytes.len, original.crypto_len);
    try std.testing.expectEqual(crypto_bytes.len, server_conn.retainedCryptoLen(.initial));

    var first_flight = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(first_flight);
    defer first_flight[0].deinit(allocator);

    const deadline = server_conn.recoveryDeadline().?;
    const recovery = try server_conn.pollLossRecovery(&server_packets, deadline, &client_scid, &server_scid);
    try std.testing.expectEqual(@as(usize, 1), recovery.count);
    try std.testing.expectEqual(@as(u32, 1), recovery.pto_count);
    try std.testing.expectEqual(.initial, recovery.slice()[0].encryption_level);
    try std.testing.expect(recovery.slice()[0].retransmitted_crypto);
    try std.testing.expectEqual(crypto_bytes.len, recovery.slice()[0].crypto_len);

    var retransmission = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(retransmission);
    defer retransmission[0].deinit(allocator);
    var processed = try client_packets.processProtectedRawPacket(retransmission[0].data, null);
    defer processed.deinit(allocator);
    var reader = std.Io.Reader.fixed(processed.payload);
    const frame = try QuicFrames.Frame.parse(&reader, allocator);
    defer if (frame == .crypto) allocator.free(frame.crypto.data);
    try std.testing.expect(frame == .crypto);
    try std.testing.expectEqual(crypto_offset, frame.crypto.offset);
    try std.testing.expectEqualSlices(u8, crypto_bytes, frame.crypto.data);

    server_conn.clearRetainedCrypto(.initial);
    try std.testing.expectEqual(@as(usize, 0), server_conn.retainedCryptoLen(.initial));
}

test "integration: handshake timeout clears recovery data and enters draining" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer conn.deinit();
    var tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer tls.deinit();
    var packet_crypto = try PacketCrypto.init(allocator, &tls, null);
    defer packet_crypto.deinit();

    const dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_scid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_scid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    try packet_crypto.installRfc9001ServerInitialKeys(&dcid);
    _ = (try conn.scheduleCryptoBytesAsProtectedRawPacket(
        &packet_crypto,
        .initial,
        .initial,
        &client_scid,
        &server_scid,
        0,
        "partial handshake flight awaiting progress",
    )).?;
    try std.testing.expect(conn.recoveryDeadline() != null);
    try std.testing.expect(conn.retainedCryptoLen(.initial) > 0);

    try std.testing.expect(!try conn.pollHandshakeTimeout(1_000, 1_499, 500));
    try std.testing.expect(try conn.pollHandshakeTimeout(1_000, 1_500, 500));
    try std.testing.expectEqual(.draining, conn.state);
    try std.testing.expectEqual(@as(usize, 0), conn.outgoing_raw_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.retainedCryptoLen(.initial));
    try std.testing.expectEqual(@as(?u64, null), conn.recoveryDeadline());
    try std.testing.expectEqual(@as(usize, 1), conn.outgoing_packets.items.len);
    try std.testing.expect(!try conn.pollHandshakeTimeout(1_000, 2_000, 500));

    try std.testing.expect(!try conn.waitForDrain(1));
    try std.testing.expect(conn.isTerminated());
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

test "integration: minimal HTTP/3 control and response cross protected application packets" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    try client_tls.deriveApplicationKeys("minimal HTTP/3 protected application packets");
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try server_tls.deriveApplicationKeys("minimal HTTP/3 protected application packets");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();

    const dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const control_frames = [_]QuicFrames.Frame{
        .{ .handshake_done = QuicFrames.HandshakeDoneFrame.init() },
        .{ .stream_off_len = QuicFrames.StreamFrame.init(3, 0, &MinimalHttp3.server_control_bytes, false, true, true) },
    };
    try server_conn.scheduleFramesAsProtectedRawPacket(
        &server_packets,
        .application,
        .one_rtt,
        &dcid,
        &.{},
        &control_frames,
    );

    const response_frames = [_]QuicFrames.Frame{
        .{ .stream_off_len_fin = QuicFrames.StreamFrame.init(
            0,
            0,
            &MinimalHttp3.get_root_response_bytes,
            true,
            true,
            true,
        ) },
    };
    try server_conn.scheduleFramesAsProtectedRawPacket(
        &server_packets,
        .application,
        .one_rtt,
        &dcid,
        &.{},
        &response_frames,
    );

    const outgoing = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    defer for (outgoing) |*packet| packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), outgoing.len);

    var control_packet = try client_packets.processProtectedRawPacket(outgoing[0].data, null);
    defer control_packet.deinit(allocator);
    try std.testing.expectEqual(.application, control_packet.encryption_level);
    var control_reader = std.Io.Reader.fixed(control_packet.payload);
    const handshake_done = try QuicFrames.Frame.parse(&control_reader, allocator);
    try std.testing.expect(handshake_done == .handshake_done);
    var settings_stream = try QuicFrames.Frame.parse(&control_reader, allocator);
    defer settings_stream.deinit(allocator);
    try std.testing.expect(settings_stream == .stream);
    try std.testing.expectEqual(@as(u64, 3), settings_stream.stream.stream_id);
    try std.testing.expectEqual(@as(u64, 0), settings_stream.stream.offset);
    try std.testing.expect(!settings_stream.stream.fin);
    try std.testing.expectEqualSlices(u8, &MinimalHttp3.server_control_bytes, settings_stream.stream.data);
    try std.testing.expectEqual(control_reader.end, control_reader.seek);

    var response_packet = try client_packets.processProtectedRawPacket(outgoing[1].data, control_packet.packet_number);
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(.application, response_packet.encryption_level);
    var response_reader = std.Io.Reader.fixed(response_packet.payload);
    var response_stream = try QuicFrames.Frame.parse(&response_reader, allocator);
    defer response_stream.deinit(allocator);
    try std.testing.expect(response_stream == .stream);
    try std.testing.expectEqual(@as(u64, 0), response_stream.stream.stream_id);
    try std.testing.expectEqual(@as(u64, 0), response_stream.stream.offset);
    try std.testing.expect(response_stream.stream.fin);
    try std.testing.expectEqualSlices(u8, &MinimalHttp3.get_root_response_bytes, response_stream.stream.data);
    try std.testing.expectEqual(response_reader.end, response_reader.seek);
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

    try client_tls.deriveHandshakeKeys("connection path split server flight");
    try server_tls.deriveHandshakeKeys("connection path split server flight");
    _ = try client_packets.refreshKeysFromTlsContext();
    _ = try server_packets.refreshKeysFromTlsContext();

    const handshake_metadata = (try server_conn.schedulePendingCryptoAsProtectedRawPacketWithMetadata(
        &server_packets,
        &server_hs,
        .handshake,
        .handshake,
        &client_scid,
        &server_scid,
    )).?;
    try std.testing.expectEqual(.handshake, handshake_metadata.encryption_level);
    try std.testing.expectEqual(@as(u64, 0), handshake_metadata.packet_number);
    try std.testing.expect(handshake_metadata.crypto_len > 0);

    var server_handshake_outgoing = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_handshake_outgoing);
    try std.testing.expectEqual(@as(usize, 1), server_handshake_outgoing.len);
    defer server_handshake_outgoing[0].deinit(allocator);

    var processed_handshake = try client_packets.processProtectedRawPacket(server_handshake_outgoing[0].data, null);
    defer processed_handshake.deinit(allocator);
    try std.testing.expectEqual(.handshake, processed_handshake.encryption_level);
    try std.testing.expectEqual(@as(u64, 0), processed_handshake.packet_number);

    var handshake_reader = std.Io.Reader.fixed(processed_handshake.payload);
    const handshake_frame = try QuicFrames.Frame.parse(&handshake_reader, allocator);
    defer switch (handshake_frame) {
        .crypto => |crypto| allocator.free(crypto.data),
        else => {},
    };
    try std.testing.expect(handshake_frame == .crypto);
    try std.testing.expectEqual(handshake_metadata.crypto_len, handshake_frame.crypto.data.len);
}

/// Build a framed (type + u24 length) ClientHello the real parser accepts.
///
/// Every test that needs a well-formed ClientHello goes through here so there is
/// exactly one definition of "acceptable" shared across the suite.
fn buildAcceptableFramedClientHello(out: []u8, opts: Tls13Messages.TestClientHelloOptions) ![]u8 {
    var overridden = opts;
    if (overridden.alpn_protocols == null) overridden.alpn_protocols = &.{"h3"};
    const body = try Tls13Messages.buildTestClientHello(out[4..], overridden);
    out[0] = 1; // ClientHello
    out[1] = 0;
    out[2] = @truncate(body.len >> 8);
    out[3] = @truncate(body.len);
    return out[0 .. 4 + body.len];
}

test "integration: live initial crypto advances comprehensive TLS transcript" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_hs = HandshakeManager.init(allocator, true);
    defer server_hs.deinit();
    var comprehensive_tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer comprehensive_tls.deinit();
    try comprehensive_tls.initServer(&.{});

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

    const original_dcid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };
    const client_scid = [_]u8{ 0xB1, 0xB2, 0xB3, 0xB4 };
    const server_scid = [_]u8{ 0xC1, 0xC2, 0xC3, 0xC4 };
    try server_hs.startHandshake(&original_dcid);
    try client_packets.installRfc9001ClientInitialKeys(&original_dcid);
    try server_packets.installRfc9001ServerInitialKeys(&original_dcid);

    var client_hello_buffer: [512]u8 = undefined;
    const framed_client_hello = try buildAcceptableFramedClientHello(&client_hello_buffer, .{});
    var crypto_payload_buffer: [640]u8 = undefined;
    var crypto_writer = std.Io.Writer.fixed(&crypto_payload_buffer);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, framed_client_hello) }).serialize(&crypto_writer);

    try client_conn.sendProtectedRawPacket(
        &client_packets,
        .initial,
        .initial,
        &original_dcid,
        &client_scid,
        std.Io.Writer.buffered(&crypto_writer),
    );
    var client_outgoing = try client_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(client_outgoing);
    defer client_outgoing[0].deinit(allocator);
    try server_conn.queueIncomingRawPacket(client_outgoing[0].data);

    const result = try server_conn.processNextIncomingInitialCryptoAndScheduleServerFlightWithComprehensiveTls(
        &server_packets,
        &server_hs,
        &comprehensive_tls,
        &client_scid,
        &server_scid,
        null,
    );
    try std.testing.expectEqual(@as(usize, 1), result.scheduled_packets);
    try std.testing.expectEqual(@as(usize, 1), result.tls_messages_processed);
    // The accepted ClientHello now drives a real ServerHello and the Handshake
    // key schedule, so the transcript is CH followed by SH.
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.server_hello_sent, comprehensive_tls.state);
    try std.testing.expectEqualSlices(
        u8,
        framed_client_hello,
        comprehensive_tls.handshake_transcript.items[0..framed_client_hello.len],
    );
    try std.testing.expect(comprehensive_tls.handshake_transcript.items.len > framed_client_hello.len);
    try std.testing.expect(comprehensive_tls.tls13HandshakeKeys() != null);
    // Legacy synthetic handshake keys stay untouched by this boundary.
    try std.testing.expect(comprehensive_tls.handshake_keys == null);
}

test "integration: comprehensive TLS rejects wrong live initial message type" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer conn.deinit();
    var handshake_manager = HandshakeManager.init(allocator, true);
    defer handshake_manager.deinit();
    var comprehensive_tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer comprehensive_tls.deinit();
    try comprehensive_tls.initServer(&.{});
    var enhanced_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer enhanced_tls.deinit();
    var packet_crypto = try PacketCrypto.init(allocator, &enhanced_tls, null);
    defer packet_crypto.deinit();

    const wrong_message = [_]u8{ 2, 0, 0, 1, 0xaa };
    var payload_buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buffer);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, &wrong_message) }).serialize(&writer);

    try std.testing.expectError(
        error.ProtocolViolation,
        conn.processInitialCryptoAndScheduleServerFlightWithComprehensiveTls(
            &packet_crypto,
            &handshake_manager,
            &comprehensive_tls,
            std.Io.Writer.buffered(&writer),
            &.{ 1, 2, 3, 4 },
            &.{ 5, 6, 7, 8 },
        ),
    );
    // A rejected message stays buffered, so the context is failed outright
    // rather than left to re-reject the same bytes on every later datagram.
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.failed, comprehensive_tls.state);
    try std.testing.expectEqual(@as(usize, 0), comprehensive_tls.handshake_transcript.items.len);
    const outgoing = try conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 0), outgoing.len);
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

test "integration: handshake crypto advances comprehensive TLS transcript with installed test keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var client_hs = HandshakeManager.init(allocator, false);
    defer client_hs.deinit();
    var comprehensive_tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, false);
    defer comprehensive_tls.deinit();
    try comprehensive_tls.initClient("localhost");

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    try client_tls.deriveHandshakeKeys("comprehensive handshake routing test keys");
    try server_tls.deriveHandshakeKeys("comprehensive handshake routing test keys");

    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();
    var client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
    defer client_conn.deinit();
    var server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer server_conn.deinit();

    const connection_id = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    try client_hs.startHandshake(&connection_id);
    client_hs.clearSentCryptoData();

    const framed_server_hello = [_]u8{ 2, 0, 0, 2, 0xaa, 0xbb };
    var payload_buffer: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buffer);
    try (QuicFrames.Frame{ .crypto = QuicFrames.CryptoFrame.init(0, &framed_server_hello) }).serialize(&writer);

    try server_conn.sendProtectedRawPacket(
        &server_packets,
        .handshake,
        .handshake,
        &connection_id,
        &.{ 0x81, 0x82, 0x83, 0x84 },
        std.Io.Writer.buffered(&writer),
    );
    var server_outgoing = try server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(server_outgoing);
    defer server_outgoing[0].deinit(allocator);
    try client_conn.queueIncomingRawPacket(server_outgoing[0].data);

    var processed = (try client_conn.processNextIncomingRawCryptoPacketWithComprehensiveTls(
        &client_packets,
        &client_hs,
        &client_tls,
        &comprehensive_tls,
        &connection_id,
        null,
    )).?;
    defer processed.deinit(allocator);

    try std.testing.expectEqual(.handshake, processed.encryption_level);
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.wait_encrypted_extensions, comprehensive_tls.state);
    try std.testing.expectEqualSlices(u8, &framed_server_hello, comprehensive_tls.handshake_transcript.items);
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
    try std.testing.expect(client_hs.getPendingCryptoDataForLevel(.handshake).len > 0);

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
    try std.testing.expectEqual(@as(usize, 0), client_hs.getPendingCryptoDataForLevel(.handshake).len);

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

test "integration: connection close owns payload and uses complete QUIC varints" {
    const allocator = std.testing.allocator;
    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    defer conn.deinit();

    const reason: [80]u8 = @splat('r');
    try conn.initiateShutdown(0x4000, &reason);
    try std.testing.expectEqual(@as(usize, 1), conn.super_connection.outgoing_packets.items.len);

    // Clobber unrelated stack storage before parsing the retained packet. The
    // queued payload must remain connection-owned after initiateShutdown returns.
    var clobber: [256]u8 = @splat(0xa5);
    std.mem.doNotOptimizeAway(&clobber);

    var reader = std.Io.Reader.fixed(conn.super_connection.outgoing_packets.items[0].payload);
    var frame = try QuicFrames.Frame.parse(&reader, allocator);
    defer frame.deinit(allocator);
    switch (frame) {
        .connection_close => |close| {
            try std.testing.expectEqual(@as(u64, 0x4000), close.error_code);
            try std.testing.expectEqualStrings(&reason, close.reason_phrase);
        },
        else => return error.UnexpectedFrame,
    }
}

test "integration: connection close rejects error codes above QUIC varint range" {
    var conn = try zquic.Connection.Connection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(
        error.InvalidArgument,
        conn.initiateShutdown(0x4000_0000_0000_0000, "invalid"),
    );
    try std.testing.expectEqual(zquic.Connection.ConnectionState.initial, conn.getState());
    try std.testing.expectEqual(@as(usize, 0), conn.super_connection.outgoing_packets.items.len);
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
    _ = try recovery.onLossDetectionTimeout(&spaces, 1_000_000);
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

// --- Real TLS 1.3 server boundary -------------------------------------------
//
// `src/crypto/comprehensive_tls.zig` carries inline `test` blocks, but they are
// not registered in `src/root.zig`'s test-collection block and no longer compile
// against the current Zig standard library, so they never run. Tests for the new
// TLS 1.3 boundary therefore live here, where the build actually executes them.

fn serverContextWithAcceptedClientHello(
    allocator: std.mem.Allocator,
    tls: *ComprehensiveTls.ComprehensiveTlsContext,
    hello_buffer: []u8,
    opts: Tls13Messages.TestClientHelloOptions,
) ![]u8 {
    _ = allocator;
    const framed = try buildAcceptableFramedClientHello(hello_buffer, opts);
    try std.testing.expectEqual(@as(usize, 1), try tls.processQuicCryptoData(framed));
    return framed;
}

test "tls13 boundary: accepted ClientHello produces a transcript-bound ServerHello" {
    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{});

    var hello_buffer: [512]u8 = undefined;
    const framed = try serverContextWithAcceptedClientHello(std.testing.allocator, &tls, &hello_buffer, .{});

    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.server_hello_sent, tls.state);
    try std.testing.expectEqualStrings("h3", tls.negotiated_alpn.?);

    // The pending CRYPTO bytes are exactly the ServerHello, and the transcript
    // is ClientHello followed by that same ServerHello.
    const server_hello = tls.pendingHandshakeCrypto();
    try std.testing.expect(server_hello.len > 4);
    try std.testing.expectEqual(@as(u8, 2), server_hello[0]);
    try std.testing.expectEqualSlices(
        u8,
        framed,
        tls.handshake_transcript.items[0..framed.len],
    );
    try std.testing.expectEqualSlices(
        u8,
        server_hello,
        tls.handshake_transcript.items[framed.len..],
    );

    // Handshake secrets exist and the two directions are independent.
    const schedule = tls.tls13HandshakeKeys().?;
    try std.testing.expect(!std.mem.eql(u8, &schedule.client_traffic_secret, &schedule.server_traffic_secret));
    try std.testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.key, &schedule.server_packet_keys.key));
    try std.testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.iv, &schedule.server_packet_keys.iv));
    try std.testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.hp, &schedule.server_packet_keys.hp));

    // Clearing the pending bytes leaves the derived keys in place.
    tls.clearSentHandshakeCrypto();
    try std.testing.expectEqual(@as(usize, 0), tls.pendingHandshakeCrypto().len);
    try std.testing.expect(tls.tls13HandshakeKeys() != null);
}

test "tls13 boundary: produceServerFlight is idempotent after the ServerHello" {
    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{});

    var hello_buffer: [512]u8 = undefined;
    _ = try serverContextWithAcceptedClientHello(std.testing.allocator, &tls, &hello_buffer, .{});

    const transcript_len = tls.handshake_transcript.items.len;
    const pending_len = tls.pendingHandshakeCrypto().len;
    const first_secret = tls.tls13HandshakeKeys().?.server_traffic_secret;

    try tls.produceServerFlight();
    try tls.produceServerFlight();

    try std.testing.expectEqual(transcript_len, tls.handshake_transcript.items.len);
    try std.testing.expectEqual(pending_len, tls.pendingHandshakeCrypto().len);
    try std.testing.expectEqualSlices(u8, &first_secret, &tls.tls13HandshakeKeys().?.server_traffic_secret);
}

test "tls13 boundary: fragmented ClientHello is buffered until complete" {
    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{});

    var hello_buffer: [512]u8 = undefined;
    const framed = try buildAcceptableFramedClientHello(&hello_buffer, .{});

    // Split mid-message: neither half is a complete handshake message.
    const split = framed.len / 2;
    try std.testing.expectEqual(@as(usize, 0), try tls.processQuicCryptoData(framed[0..split]));
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.wait_client_hello, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);
    try std.testing.expect(tls.tls13HandshakeKeys() == null);

    try std.testing.expectEqual(@as(usize, 1), try tls.processQuicCryptoData(framed[split..]));
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.server_hello_sent, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.quic_crypto_buffer.items.len);
    try std.testing.expect(tls.tls13HandshakeKeys() != null);
}

test "tls13 boundary: transcript binding changes the derived handshake secrets" {
    var first_buffer: [512]u8 = undefined;
    var second_buffer: [512]u8 = undefined;

    var first = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer first.deinit();
    try first.initServer(&.{});
    _ = try serverContextWithAcceptedClientHello(std.testing.allocator, &first, &first_buffer, .{});

    var second = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer second.deinit();
    try second.initServer(&.{});
    // Same key material profile, different ClientHello random.
    _ = try serverContextWithAcceptedClientHello(
        std.testing.allocator,
        &second,
        &second_buffer,
        .{ .random = @splat(0xb2) },
    );

    try std.testing.expect(!std.mem.eql(
        u8,
        &first.tls13HandshakeKeys().?.handshake_secret,
        &second.tls13HandshakeKeys().?.handshake_secret,
    ));
}

test "tls13 boundary: rejected ClientHellos install no keys and negotiate nothing" {
    const Case = struct {
        name: []const u8,
        opts: Tls13Messages.TestClientHelloOptions,
    };
    const cases = [_]Case{
        .{ .name = "no supported_versions", .opts = .{ .include_supported_versions = false } },
        .{ .name = "tls 1.2 only", .opts = .{ .supported_versions = &.{0x0303} } },
        .{ .name = "unsupported cipher suite", .opts = .{ .cipher_suites = &.{0x1302} } },
        .{ .name = "no key share", .opts = .{ .include_key_share = false } },
        .{ .name = "p256 key share", .opts = .{ .key_share_group = 0x0017 } },
        .{ .name = "short x25519 share", .opts = .{ .key_share_len = 31 } },
        .{ .name = "duplicate key share", .opts = .{ .duplicate_key_share = true } },
        .{ .name = "no quic transport parameters", .opts = .{ .include_quic_transport_parameters = false } },
        .{ .name = "undecodable transport parameters", .opts = .{ .quic_transport_parameters = &.{ 0x01, 0x00 } } },
        .{ .name = "trailing bytes", .opts = .{ .trailing_bytes = 3 } },
        .{ .name = "unsupported alpn", .opts = .{ .alpn_protocols = &.{"hq-interop"} } },
    };

    for (cases) |case| {
        var tls = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
        defer tls.deinit();
        try tls.initServer(&.{});

        var hello_buffer: [512]u8 = undefined;
        var opts = case.opts;
        if (opts.alpn_protocols == null) opts.alpn_protocols = &.{"h3"};
        var body_buffer: [512]u8 = undefined;
        const body = try Tls13Messages.buildTestClientHello(&body_buffer, opts);
        hello_buffer[0] = 1;
        hello_buffer[1] = 0;
        hello_buffer[2] = @truncate(body.len >> 8);
        hello_buffer[3] = @truncate(body.len);
        @memcpy(hello_buffer[4..][0..body.len], body);
        const framed = hello_buffer[0 .. 4 + body.len];

        // The specific error varies by case (the TLS parser reports
        // ProtocolViolation, the transport-parameter decoder InvalidData), so
        // assert only that the ClientHello was refused.
        if (tls.processQuicCryptoData(framed)) |_| {
            std.debug.print("case '{s}' was accepted but must be rejected\n", .{case.name});
            return error.TestUnexpectedResult;
        } else |_| {}

        try std.testing.expectEqual(ComprehensiveTls.HandshakeState.failed, tls.state);
        try std.testing.expect(tls.tls13HandshakeKeys() == null);
        try std.testing.expect(tls.negotiated_alpn == null);
        try std.testing.expect(tls.peer_quic_transport_params == null);
        try std.testing.expect(tls.peer_x25519_public == null);
        try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);
        try std.testing.expectEqual(@as(usize, 0), tls.pendingHandshakeCrypto().len);
    }
}

test "tls13 boundary: all-zero X25519 share is rejected as non-contributory" {
    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{});

    var hello_buffer: [512]u8 = undefined;
    const framed = try buildAcceptableFramedClientHello(&hello_buffer, .{});

    // The fixture writes a 0x42-filled share; blank it so X25519 sees a
    // low-order point and must refuse the exchange.
    const filled_share: [32]u8 = @splat(0x42);
    const zero_share: [32]u8 = @splat(0);
    const share_index = std.mem.indexOf(u8, framed, &filled_share) orelse unreachable;
    @memcpy(framed[share_index..][0..32], &zero_share);

    try std.testing.expectError(error.CryptoError, tls.processQuicCryptoData(framed));
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.failed, tls.state);
    try std.testing.expect(tls.tls13HandshakeKeys() == null);
}

// ---------------------------------------------------------------------------
// RFC 9001 Handshake packet-protection key install.
//
// These live here rather than inline in `src/core/packet_crypto.zig` because
// that file's inline tests are never collected: only the files listed
// explicitly in the `test { ... }` block of `src/root.zig` are. Registering
// `core/packet_crypto.zig` there transitively pulls in `core/crypto.zig`,
// whose own uncollected tests currently fail for reasons unrelated to this
// phase. See the Claude Review section of tasks/831.md.
// ---------------------------------------------------------------------------

/// Derive a handshake key schedule from fixed inputs so packet tests are
/// deterministic. The inputs are arbitrary test material, not RFC vectors; the
/// key schedule itself is vector-checked in `src/crypto/tls13_key_schedule.zig`.
fn testHandshakeSchedule(seed: u8) !Tls13KeySchedule.HandshakeKeySchedule {
    const shared_secret: [32]u8 = @splat(seed);
    const transcript_hash: [32]u8 = @splat(seed +% 0x40);
    return Tls13KeySchedule.deriveHandshakeKeySchedule(&shared_secret, &transcript_hash);
}

test "rfc9001 handshake keys: installed keys protect both directions" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();

    var server = try PacketCrypto.init(allocator, &server_tls, null);
    defer server.deinit();
    var client = try PacketCrypto.init(allocator, &client_tls, null);
    defer client.deinit();

    var schedule = try testHandshakeSchedule(0x11);
    defer schedule.zeroize();

    // The server writes with the server traffic keys and reads with the
    // client's; the client is the mirror image.
    try server.installRfc9001HandshakeKeys(&schedule.server_packet_keys, &schedule.client_packet_keys);
    try client.installRfc9001HandshakeKeys(&schedule.client_packet_keys, &schedule.server_packet_keys);

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };

    const to_client = try server.encryptPacket(.handshake, 3, &header, "server handshake flight bytes");
    defer allocator.free(to_client);
    const to_client_plain = try client.decryptPacket(.handshake, 3, &header, to_client);
    defer allocator.free(to_client_plain);
    try std.testing.expectEqualStrings("server handshake flight bytes", to_client_plain);

    const to_server = try client.encryptPacket(.handshake, 4, &header, "client handshake flight bytes");
    defer allocator.free(to_server);
    const to_server_plain = try server.decryptPacket(.handshake, 4, &header, to_server);
    defer allocator.free(to_server_plain);
    try std.testing.expectEqualStrings("client handshake flight bytes", to_server_plain);
}

test "rfc9001 handshake keys: reversed direction mapping cannot decrypt" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();

    var server = try PacketCrypto.init(allocator, &server_tls, null);
    defer server.deinit();
    var client = try PacketCrypto.init(allocator, &client_tls, null);
    defer client.deinit();

    var schedule = try testHandshakeSchedule(0x22);
    defer schedule.zeroize();

    try server.installRfc9001HandshakeKeys(&schedule.server_packet_keys, &schedule.client_packet_keys);
    // Deliberately wrong: the client reads with the server's read keys, so it
    // tries to unprotect the server's packets with the client traffic keys.
    try client.installRfc9001HandshakeKeys(&schedule.server_packet_keys, &schedule.client_packet_keys);

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };
    const to_client = try server.encryptPacket(.handshake, 5, &header, "server handshake flight bytes");
    defer allocator.free(to_client);

    try std.testing.expectError(
        error.CryptoError,
        client.decryptPacket(.handshake, 5, &header, to_client),
    );
}

test "rfc9001 handshake keys: wrong packet number or AAD fails authentication" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();

    var server = try PacketCrypto.init(allocator, &server_tls, null);
    defer server.deinit();
    var client = try PacketCrypto.init(allocator, &client_tls, null);
    defer client.deinit();

    var schedule = try testHandshakeSchedule(0x33);
    defer schedule.zeroize();

    try server.installRfc9001HandshakeKeys(&schedule.server_packet_keys, &schedule.client_packet_keys);
    try client.installRfc9001HandshakeKeys(&schedule.client_packet_keys, &schedule.server_packet_keys);

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };
    const packet = try server.encryptPacket(.handshake, 9, &header, "handshake payload under real keys");
    defer allocator.free(packet);

    // The packet number is the AEAD nonce input, so a mismatch must fail.
    try std.testing.expectError(
        error.CryptoError,
        client.decryptPacket(.handshake, 10, &header, packet),
    );

    // The header is the AEAD associated data, so a mismatch must fail too.
    var tampered_header = header;
    tampered_header[5] ^= 0x01;
    try std.testing.expectError(
        error.CryptoError,
        client.decryptPacket(.handshake, 9, &tampered_header, packet),
    );

    // The untampered inputs still authenticate, proving the failures above are
    // caused by the mutations and not by a broken fixture.
    const plain = try client.decryptPacket(.handshake, 9, &header, packet);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("handshake payload under real keys", plain);
}

test "rfc9001 handshake keys: pinned levels survive a helper key refresh" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();

    var server = try PacketCrypto.init(allocator, &server_tls, null);
    defer server.deinit();
    var client = try PacketCrypto.init(allocator, &client_tls, null);
    defer client.deinit();

    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try server.installRfc9001ServerInitialKeys(&dcid);
    try client.installRfc9001ClientInitialKeys(&dcid);

    var schedule = try testHandshakeSchedule(0x44);
    defer schedule.zeroize();
    try server.installRfc9001HandshakeKeys(&schedule.server_packet_keys, &schedule.client_packet_keys);
    try client.installRfc9001HandshakeKeys(&schedule.client_packet_keys, &schedule.server_packet_keys);

    try std.testing.expect(server.isLevelPinned(.initial));
    try std.testing.expect(server.isLevelPinned(.handshake));
    try std.testing.expect(!server.isLevelPinned(.application));

    // Give the helper context material for every level. Only the unpinned
    // application level may be installed, so only it may be counted.
    try server_tls.initializeInitialKeys(&dcid);
    try server_tls.deriveHandshakeKeys("synthetic handshake secret");
    try server_tls.deriveApplicationKeys("synthetic application secret");
    try std.testing.expectEqual(@as(usize, 1), try server.refreshKeysFromTlsContext());

    const initial_header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08 };
    const initial_packet = try server.encryptPacket(.initial, 1, &initial_header, "initial after refresh");
    defer allocator.free(initial_packet);
    const initial_plain = try client.decryptPacket(.initial, 1, &initial_header, initial_packet);
    defer allocator.free(initial_plain);
    try std.testing.expectEqualStrings("initial after refresh", initial_plain);

    const handshake_header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };
    const handshake_packet = try server.encryptPacket(.handshake, 1, &handshake_header, "handshake after refresh");
    defer allocator.free(handshake_packet);
    const handshake_plain = try client.decryptPacket(.handshake, 1, &handshake_header, handshake_packet);
    defer allocator.free(handshake_plain);
    try std.testing.expectEqualStrings("handshake after refresh", handshake_plain);
}

// ---------------------------------------------------------------------------
// End-to-end ClientHello -> ServerHello -> Handshake keys.
//
// The client side of these tests is deliberately built out of `std.crypto` and
// an independent ServerHello reader rather than the server's own helpers, so a
// pass means the two sides agreed on the wire format, the transcript boundary
// and the key schedule -- not that one implementation was replayed against
// itself.
// ---------------------------------------------------------------------------

/// One server stack plus the test client that drives it.
///
/// Heap-allocated because `PacketCrypto` stores a `*EnhancedTlsContext`, so the
/// TLS contexts must not move once the packet layer has been initialised.
const HandshakeFixture = struct {
    allocator: std.mem.Allocator,
    client_tls: EnhancedTlsContext,
    server_tls: EnhancedTlsContext,
    client_packets: PacketCrypto,
    server_packets: PacketCrypto,
    client_conn: zquic.Connection.SuperConnection,
    server_conn: zquic.Connection.SuperConnection,
    server_hs: HandshakeManager,
    comprehensive_tls: ComprehensiveTls.ComprehensiveTlsContext,
    client_keys: std.crypto.dh.X25519.KeyPair,
    client_hello_storage: [512]u8,
    client_hello: []const u8,

    /// `key_seed` picks the client's X25519 private key, so two fixtures built
    /// with different seeds negotiate genuinely different shared secrets.
    fn create(
        allocator: std.mem.Allocator,
        dcid: []const u8,
        key_seed: u8,
        opts: Tls13Messages.TestClientHelloOptions,
    ) !*HandshakeFixture {
        const self = try allocator.create(HandshakeFixture);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
        self.server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
        self.client_packets = try PacketCrypto.init(allocator, &self.client_tls, null);
        self.server_packets = try PacketCrypto.init(allocator, &self.server_tls, null);
        self.client_conn = try zquic.Connection.SuperConnection.init(allocator, .client, .{});
        self.server_conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
        self.server_hs = HandshakeManager.init(allocator, true);
        self.comprehensive_tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
        try self.comprehensive_tls.initServer(&.{});

        try self.server_hs.startHandshake(dcid);
        try self.client_packets.installRfc9001ClientInitialKeys(dcid);
        try self.server_packets.installRfc9001ServerInitialKeys(dcid);

        const private_seed: [32]u8 = @splat(key_seed);
        self.client_keys = try std.crypto.dh.X25519.KeyPair.generateDeterministic(private_seed);

        var client_hello_opts = opts;
        if (client_hello_opts.key_share_bytes == null) {
            client_hello_opts.key_share_bytes = &self.client_keys.public_key;
        }
        self.client_hello = try buildAcceptableFramedClientHello(
            &self.client_hello_storage,
            client_hello_opts,
        );
        return self;
    }

    fn destroy(self: *HandshakeFixture) void {
        self.comprehensive_tls.deinit();
        self.server_hs.deinit();
        self.server_conn.deinit();
        self.client_conn.deinit();
        self.server_packets.deinit();
        self.client_packets.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
        self.allocator.destroy(self);
    }

    /// Send the fixture's ClientHello as an Initial CRYPTO packet and let the
    /// server process it.
    fn sendClientHello(
        self: *HandshakeFixture,
        dcid: []const u8,
        client_scid: []const u8,
        server_scid: []const u8,
    ) !zquic.Connection.InitialCryptoFlightResult {
        var payload_buffer: [640]u8 = undefined;
        var writer = std.Io.Writer.fixed(&payload_buffer);
        try (QuicFrames.Frame{
            .crypto = QuicFrames.CryptoFrame.init(0, self.client_hello),
        }).serialize(&writer);

        try self.client_conn.sendProtectedRawPacket(
            &self.client_packets,
            .initial,
            .initial,
            dcid,
            client_scid,
            std.Io.Writer.buffered(&writer),
        );

        const outgoing = try self.client_conn.drainOutgoingRawPackets(self.allocator);
        defer {
            for (outgoing) |*packet| packet.deinit(self.allocator);
            self.allocator.free(outgoing);
        }
        try std.testing.expectEqual(@as(usize, 1), outgoing.len);
        try self.server_conn.queueIncomingRawPacket(outgoing[0].data);

        return self.server_conn.processNextIncomingInitialCryptoAndScheduleServerFlightWithComprehensiveTls(
            &self.server_packets,
            &self.server_hs,
            &self.comprehensive_tls,
            client_scid,
            server_scid,
            null,
        );
    }

    /// Unprotect the server's Initial packet with the client's own keys and
    /// return the framed ServerHello it carries. Caller owns the bytes.
    fn takeServerHello(self: *HandshakeFixture) ![]const u8 {
        const outgoing = try self.server_conn.drainOutgoingRawPackets(self.allocator);
        defer {
            for (outgoing) |*packet| packet.deinit(self.allocator);
            self.allocator.free(outgoing);
        }
        try std.testing.expectEqual(@as(usize, 1), outgoing.len);

        var processed = try self.client_packets.processProtectedRawPacket(outgoing[0].data, null);
        defer processed.deinit(self.allocator);
        try std.testing.expectEqual(.initial, processed.encryption_level);

        // Read the CRYPTO frame directly: the frame type is the single-byte
        // varint 0x06, so no generic frame free is needed on the error path.
        var reader = std.Io.Reader.fixed(processed.payload);
        try std.testing.expectEqual(@as(u8, 0x06), try reader.takeByte());
        const crypto = try QuicFrames.CryptoFrame.parse(&reader, self.allocator);
        errdefer self.allocator.free(crypto.data);
        try std.testing.expectEqual(@as(u64, 0), crypto.offset);
        return crypto.data;
    }

    /// Reproduce the server's handshake key schedule from the client's side of
    /// the exchange, using only the wire bytes and the client's private key.
    fn deriveClientSchedule(
        self: *HandshakeFixture,
        framed_server_hello: []const u8,
    ) !Tls13KeySchedule.HandshakeKeySchedule {
        try std.testing.expect(framed_server_hello.len > 4);
        try std.testing.expectEqual(@as(u8, 2), framed_server_hello[0]); // ServerHello
        const body_len = (@as(usize, framed_server_hello[1]) << 16) |
            (@as(usize, framed_server_hello[2]) << 8) |
            @as(usize, framed_server_hello[3]);
        try std.testing.expectEqual(framed_server_hello.len - 4, body_len);

        const server_hello = try Tls13Messages.parseServerHelloForTest(framed_server_hello[4..]);
        try std.testing.expectEqual(@as(usize, 32), server_hello.key_share.len);

        var shared_secret = try std.crypto.dh.X25519.scalarmult(
            self.client_keys.secret_key,
            server_hello.key_share[0..32].*,
        );
        defer std.crypto.secureZero(u8, &shared_secret);

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(self.client_hello);
        hasher.update(framed_server_hello);
        var transcript_hash: [32]u8 = undefined;
        hasher.final(&transcript_hash);

        return Tls13KeySchedule.deriveHandshakeKeySchedule(&shared_secret, &transcript_hash);
    }
};

test "integration: real ServerHello completes the X25519 exchange end to end" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const dcid = [_]u8{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };
    const client_scid = [_]u8{ 0xB1, 0xB2, 0xB3, 0xB4 };
    const server_scid = [_]u8{ 0xC1, 0xC2, 0xC3, 0xC4 };

    const fixture = try HandshakeFixture.create(allocator, &dcid, 0x51, .{});
    defer fixture.destroy();

    const result = try fixture.sendClientHello(&dcid, &client_scid, &server_scid);
    try std.testing.expectEqual(@as(usize, 1), result.scheduled_packets);
    try std.testing.expect(result.server_hello_bytes > 0);
    try std.testing.expect(result.handshake_keys_installed);
    try std.testing.expect(fixture.server_packets.isLevelPinned(.handshake));

    const framed_server_hello = try fixture.takeServerHello();
    defer allocator.free(framed_server_hello);
    try std.testing.expectEqual(result.server_hello_bytes, framed_server_hello.len);

    var client_schedule = try fixture.deriveClientSchedule(framed_server_hello);
    defer client_schedule.zeroize();

    // The client writes with the client traffic keys and reads with the
    // server's; the server was given the mirror image by the connection layer.
    try fixture.client_packets.installRfc9001HandshakeKeys(
        &client_schedule.client_packet_keys,
        &client_schedule.server_packet_keys,
    );

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };

    const to_client = try fixture.server_packets.encryptPacket(.handshake, 0, &header, "server handshake flight");
    defer allocator.free(to_client);
    const to_client_plain = try fixture.client_packets.decryptPacket(.handshake, 0, &header, to_client);
    defer allocator.free(to_client_plain);
    try std.testing.expectEqualStrings("server handshake flight", to_client_plain);

    const to_server = try fixture.client_packets.encryptPacket(.handshake, 0, &header, "client handshake flight");
    defer allocator.free(to_server);
    const to_server_plain = try fixture.server_packets.decryptPacket(.handshake, 0, &header, to_server);
    defer allocator.free(to_server_plain);
    try std.testing.expectEqualStrings("client handshake flight", to_server_plain);
}

test "integration: initial and handshake packet number spaces stay independent" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

    const fixture = try HandshakeFixture.create(allocator, &dcid, 0x62, .{});
    defer fixture.destroy();

    const result = try fixture.sendClientHello(&dcid, &client_scid, &server_scid);
    try std.testing.expect(result.handshake_keys_installed);

    // The ServerHello consumed Initial packet number 0, so the Initial space is
    // now at 1 while the untouched Handshake space still starts at 0.
    try std.testing.expectEqual(@as(u64, 1), fixture.server_packets.nextPacketNumberForLevel(.initial));
    try std.testing.expectEqual(@as(u64, 0), fixture.server_packets.nextPacketNumberForLevel(.handshake));

    const framed_server_hello = try fixture.takeServerHello();
    defer allocator.free(framed_server_hello);
    var client_schedule = try fixture.deriveClientSchedule(framed_server_hello);
    defer client_schedule.zeroize();
    try fixture.client_packets.installRfc9001HandshakeKeys(
        &client_schedule.client_packet_keys,
        &client_schedule.server_packet_keys,
    );

    // Handshake packet number 0 is still available even though Initial 0 was
    // already used: reusing it must authenticate, which it only can if the two
    // spaces carry separate nonces under separate keys.
    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };
    const handshake_packet = try fixture.server_packets.encryptPacket(.handshake, 0, &header, "handshake pn zero");
    defer allocator.free(handshake_packet);
    const handshake_plain = try fixture.client_packets.decryptPacket(.handshake, 0, &header, handshake_packet);
    defer allocator.free(handshake_plain);
    try std.testing.expectEqualStrings("handshake pn zero", handshake_plain);

    // The Initial keys are pinned and untouched, so Initial 1 still works.
    const initial_header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08 };
    const initial_packet = try fixture.server_packets.encryptPacket(.initial, 1, &initial_header, "initial pn one");
    defer allocator.free(initial_packet);
    const initial_plain = try fixture.client_packets.decryptPacket(.initial, 1, &initial_header, initial_packet);
    defer allocator.free(initial_plain);
    try std.testing.expectEqualStrings("initial pn one", initial_plain);
}

test "integration: interleaved connection ids keep separate handshake keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const dcid_a = [_]u8{ 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A };
    const dcid_b = [_]u8{ 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B };
    const client_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };

    const a = try HandshakeFixture.create(allocator, &dcid_a, 0x71, .{});
    defer a.destroy();
    const b = try HandshakeFixture.create(allocator, &dcid_b, 0x72, .{});
    defer b.destroy();

    // Interleave the two connections so neither can rely on being the only one
    // in flight.
    const result_a = try a.sendClientHello(&dcid_a, &client_scid, &server_scid);
    const result_b = try b.sendClientHello(&dcid_b, &client_scid, &server_scid);
    try std.testing.expect(result_a.handshake_keys_installed);
    try std.testing.expect(result_b.handshake_keys_installed);

    const hello_a = try a.takeServerHello();
    defer allocator.free(hello_a);
    const hello_b = try b.takeServerHello();
    defer allocator.free(hello_b);

    var schedule_a = try a.deriveClientSchedule(hello_a);
    defer schedule_a.zeroize();
    var schedule_b = try b.deriveClientSchedule(hello_b);
    defer schedule_b.zeroize();

    // Different connection IDs, client key shares and server randoms must yield
    // unrelated handshake secrets.
    try std.testing.expect(!std.mem.eql(u8, &schedule_a.handshake_secret, &schedule_b.handshake_secret));

    try a.client_packets.installRfc9001HandshakeKeys(
        &schedule_a.client_packet_keys,
        &schedule_a.server_packet_keys,
    );
    try b.client_packets.installRfc9001HandshakeKeys(
        &schedule_b.client_packet_keys,
        &schedule_b.server_packet_keys,
    );

    const header = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01, 0x07 };
    const from_a = try a.server_packets.encryptPacket(.handshake, 0, &header, "connection a flight");
    defer allocator.free(from_a);

    const plain_a = try a.client_packets.decryptPacket(.handshake, 0, &header, from_a);
    defer allocator.free(plain_a);
    try std.testing.expectEqualStrings("connection a flight", plain_a);

    // Connection B's keys must not unprotect connection A's packet.
    try std.testing.expectError(
        error.CryptoError,
        b.client_packets.decryptPacket(.handshake, 0, &header, from_a),
    );
}

test "integration: rejected client hello installs no handshake keys" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const dcid = [_]u8{ 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 };
    const client_scid = [_]u8{ 0xE1, 0xE2, 0xE3, 0xE4 };
    const server_scid = [_]u8{ 0xF1, 0xF2, 0xF3, 0xF4 };

    // A ClientHello with no QUIC transport parameters extension is not usable
    // for a QUIC handshake and must be refused outright.
    const fixture = try HandshakeFixture.create(allocator, &dcid, 0x83, .{
        .include_quic_transport_parameters = false,
    });
    defer fixture.destroy();

    try std.testing.expectError(
        error.ProtocolViolation,
        fixture.sendClientHello(&dcid, &client_scid, &server_scid),
    );

    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.failed, fixture.comprehensive_tls.state);
    try std.testing.expect(fixture.comprehensive_tls.tls13HandshakeKeys() == null);
    try std.testing.expect(!fixture.server_packets.isLevelPinned(.handshake));
    try std.testing.expectEqual(@as(usize, 0), fixture.comprehensive_tls.pendingHandshakeCrypto().len);

    // Nothing was written back, so no ServerHello and no compatibility flight
    // escaped on a rejected input.
    const outgoing = try fixture.server_conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    try std.testing.expectEqual(@as(usize, 0), outgoing.len);
}

test "integration: server flight authenticates peer Finished before exposing application keys" {
    const allocator = std.testing.allocator;
    var identity = try Tls13Identity.EphemeralIdentity.generate(allocator);
    defer identity.deinit();

    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{identity.certificate_der});
    try tls.setServerEd25519SigningKey(&identity.secret_key);
    try tls.setServerQuicTransportContext(&.{ 1, 2, 3, 4 }, &.{ 1, 2, 3, 4 });

    const seed: [std.crypto.dh.X25519.seed_length]u8 = @splat(0x44);
    const client_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed);
    var body_buffer: [1024]u8 = undefined;
    const body = try Tls13Messages.buildTestClientHello(&body_buffer, .{
        .key_share_bytes = &client_keypair.public_key,
        .alpn_protocols = &.{"h3"},
    });
    var framed: [4 + 1024]u8 = undefined;
    framed[0] = 1;
    framed[1] = @truncate(body.len >> 16);
    framed[2] = @truncate(body.len >> 8);
    framed[3] = @truncate(body.len);
    @memcpy(framed[4..][0..body.len], body);
    try std.testing.expectEqual(@as(usize, 1), try tls.processQuicCryptoData(framed[0 .. 4 + body.len]));
    tls.clearSentHandshakeCrypto();

    try tls.produceServerHandshakeFlight();
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.wait_finished, tls.state);
    const flight = tls.pendingServerHandshakeCrypto();
    try std.testing.expect(flight.len > identity.certificate_der.len);

    var offset: usize = 0;
    for ([_]u8{ 8, 11, 15, 20 }) |expected_type| {
        try std.testing.expect(offset + 4 <= flight.len);
        try std.testing.expectEqual(expected_type, flight[offset]);
        const message_len = (@as(usize, flight[offset + 1]) << 16) |
            (@as(usize, flight[offset + 2]) << 8) |
            @as(usize, flight[offset + 3]);
        offset += 4 + message_len;
        try std.testing.expect(offset <= flight.len);
    }
    try std.testing.expectEqual(flight.len, offset);
    try std.testing.expect(tls.tls13ApplicationKeys() == null);

    var transcript_hash: [Tls13KeySchedule.hash_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(tls.handshakeTranscript(), &transcript_hash, .{});
    var client_finished = try Tls13KeySchedule.computeFinishedVerifyData(
        &tls.tls13HandshakeKeys().?.client_traffic_secret,
        &transcript_hash,
    );
    defer std.crypto.secureZero(u8, &client_finished);

    var forged = client_finished;
    forged[0] ^= 1;
    const transcript_len = tls.handshakeTranscript().len;
    try std.testing.expectError(error.CryptoError, tls.processHandshakeMessage(20, &forged));
    try std.testing.expectEqual(transcript_len, tls.handshakeTranscript().len);
    try std.testing.expect(tls.tls13ApplicationKeys() == null);

    try tls.processHandshakeMessage(20, &client_finished);
    try std.testing.expectEqual(ComprehensiveTls.HandshakeState.connected, tls.state);
    const application = tls.tls13ApplicationKeys().?;

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();
    var client_packets = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_packets.deinit();
    var server_packets = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_packets.deinit();
    try client_packets.installRfc9001ApplicationKeys(&application.client_packet_keys, &application.server_packet_keys);
    try server_packets.installRfc9001ApplicationKeys(&application.server_packet_keys, &application.client_packet_keys);

    const one_rtt_dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const application_payload = "transcript-bound client application payload";
    const packet = try client_packets.createProtectedRawPacket(.application, .one_rtt, &one_rtt_dcid, &.{}, application_payload);
    defer allocator.free(packet);
    var processed = try server_packets.processProtectedRawPacket(packet, null);
    defer processed.deinit(allocator);
    try std.testing.expectEqual(.application, processed.encryption_level);
    try std.testing.expectEqualStrings(application_payload, processed.payload);
}

test "integration: Ed25519 server identity rejects a mismatched leaf key" {
    const allocator = std.testing.allocator;
    var identity = try Tls13Identity.EphemeralIdentity.generate(allocator);
    defer identity.deinit();
    var other_identity = try Tls13Identity.EphemeralIdentity.generate(allocator);
    defer other_identity.deinit();

    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{identity.certificate_der});
    try std.testing.expectError(
        error.CertificateError,
        tls.setServerEd25519SigningKey(&other_identity.secret_key),
    );
    try tls.setServerEd25519SigningKey(&identity.secret_key);
}

test "integration: P-256-only ClientHello selects a DER CertificateVerify" {
    const allocator = std.testing.allocator;
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var identity = try Tls13Identity.EphemeralP256Identity.generate(allocator);
    defer identity.deinit();

    var other_identity = try Tls13Identity.EphemeralP256Identity.generate(allocator);
    defer other_identity.deinit();
    var mismatch_tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer mismatch_tls.deinit();
    try mismatch_tls.initServer(&.{identity.certificate_der});
    try std.testing.expectError(
        error.CertificateError,
        mismatch_tls.setServerEcdsaP256Identity(identity.certificate_der, &other_identity.secret_key),
    );

    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{identity.certificate_der});
    try tls.setServerEcdsaP256Identity(identity.certificate_der, &identity.secret_key);
    try tls.setServerQuicTransportContext(&.{ 1, 2, 3, 4 }, &.{ 5, 6, 7, 8 });

    const seed: [std.crypto.dh.X25519.seed_length]u8 = @splat(0x51);
    const client_keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(seed);
    var body_buffer: [1024]u8 = undefined;
    const body = try Tls13Messages.buildTestClientHello(&body_buffer, .{
        .key_share_bytes = &client_keypair.public_key,
        .alpn_protocols = &.{"h3"},
        .signature_algorithms = &.{Tls13Messages.signature_scheme_ecdsa_secp256r1_sha256},
    });
    var framed: [4 + 1024]u8 = undefined;
    framed[0] = 1;
    framed[1] = @truncate(body.len >> 16);
    framed[2] = @truncate(body.len >> 8);
    framed[3] = @truncate(body.len);
    @memcpy(framed[4..][0..body.len], body);
    try std.testing.expectEqual(@as(usize, 1), try tls.processQuicCryptoData(framed[0 .. 4 + body.len]));
    tls.clearSentHandshakeCrypto();
    try tls.produceServerHandshakeFlight();

    const flight = tls.pendingServerHandshakeCrypto();
    var offset: usize = 0;
    var certificate_verify_offset: ?usize = null;
    var certificate_verify_body: ?[]const u8 = null;
    while (offset < flight.len) {
        try std.testing.expect(offset + 4 <= flight.len);
        const message_len = (@as(usize, flight[offset + 1]) << 16) |
            (@as(usize, flight[offset + 2]) << 8) |
            @as(usize, flight[offset + 3]);
        try std.testing.expect(offset + 4 + message_len <= flight.len);
        if (flight[offset] == 15) {
            certificate_verify_offset = offset;
            certificate_verify_body = flight[offset + 4 .. offset + 4 + message_len];
            break;
        }
        offset += 4 + message_len;
    }

    const verify_offset = certificate_verify_offset orelse return error.TestUnexpectedResult;
    const verify_body = certificate_verify_body orelse return error.TestUnexpectedResult;
    try std.testing.expect(verify_body.len >= 4);
    try std.testing.expectEqual(
        Tls13Messages.signature_scheme_ecdsa_secp256r1_sha256,
        std.mem.readInt(u16, verify_body[0..2], .big),
    );
    const signature_len = std.mem.readInt(u16, verify_body[2..4], .big);
    try std.testing.expectEqual(@as(usize, 4 + signature_len), verify_body.len);

    const transcript = tls.handshakeTranscript();
    const transcript_before_flight_len = transcript.len - flight.len;
    var transcript_hash: [Tls13KeySchedule.hash_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        transcript[0 .. transcript_before_flight_len + verify_offset],
        &transcript_hash,
        .{},
    );
    const context = "TLS 1.3, server CertificateVerify";
    var signed_content: [64 + context.len + 1 + Tls13KeySchedule.hash_length]u8 = undefined;
    @memset(signed_content[0..64], 0x20);
    @memcpy(signed_content[64 .. 64 + context.len], context);
    signed_content[64 + context.len] = 0;
    @memcpy(signed_content[65 + context.len ..], &transcript_hash);

    const signature = try EcdsaP256.Signature.fromDer(verify_body[4..]);
    const secret_key = try EcdsaP256.SecretKey.fromBytes(identity.secret_key);
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(secret_key);
    try signature.verify(&signed_content, key_pair.public_key);
}

test "integration: configured P-256-only server rejects an Ed25519-only ClientHello" {
    const allocator = std.testing.allocator;
    var identity = try Tls13Identity.EphemeralP256Identity.generate(allocator);
    defer identity.deinit();

    var tls = ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{identity.certificate_der});
    try tls.setServerEcdsaP256Identity(identity.certificate_der, &identity.secret_key);

    var body_buffer: [1024]u8 = undefined;
    const body = try Tls13Messages.buildTestClientHello(&body_buffer, .{ .alpn_protocols = &.{"h3"} });
    var framed: [4 + 1024]u8 = undefined;
    framed[0] = 1;
    framed[1] = @truncate(body.len >> 16);
    framed[2] = @truncate(body.len >> 8);
    framed[3] = @truncate(body.len);
    @memcpy(framed[4..][0..body.len], body);
    try std.testing.expectError(
        error.ProtocolViolation,
        tls.processQuicCryptoData(framed[0 .. 4 + body.len]),
    );
}
