//! Handshake integration tests exercising client/server flows

const std = @import("std");
const zquic = @import("zquic");

const HandshakeManager = zquic.Handshake.HandshakeManager;
const TransportParameters = zquic.core.TransportParameters;
const QuicFrames = zquic.core.QuicFrames;
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
