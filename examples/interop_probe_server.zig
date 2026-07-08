//! Live UDP interop probe for external QUIC client smoke tests.
//!
//! This endpoint is intentionally narrow: it receives UDP datagrams, parses
//! QUIC long/short headers when possible, emits structured trace lines, and
//! sends Version Negotiation for unsupported long-header versions. It is not a
//! full HTTP/3 server.

const std = @import("std");
const zquic = @import("zquic");

const Packet = zquic.Packet;
const PacketCrypto = zquic.PacketCrypto;
const Time = zquic.Time;
const UdpSocket = zquic.UdpSocket;
const NetAddress = zquic.NetAddress;
const QuicFrames = zquic.core.QuicFrames;

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    duration_ms: u64 = 10_000,
    max_packets: usize = 8,
    qlog: bool = false,
};

pub fn main(init: std.process.Init) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const config = try parseArgs(init.minimal.args);
    const address = try NetAddress.resolveIp(config.host, config.port);

    var socket = try UdpSocket.init(address);
    defer socket.deinit();
    try socket.setNonBlocking(true);

    std.debug.print("zquic interop probe listening on {s}:{}\n", .{ config.host, socket.local_address.getPort() });
    std.debug.print("zquic interop probe mode=packet-trace full_handshake=false\n", .{});

    const start = Time.nowMicros();
    var packets_seen: usize = 0;
    var buffer: [65535]u8 = undefined;

    while (packets_seen < config.max_packets) {
        const now = Time.nowMicros();
        if (now - start >= config.duration_ms * std.time.us_per_ms) break;

        const received = try socket.tryReceiveFrom(&buffer);
        if (received) |packet| {
            packets_seen += 1;
            try traceDatagram(allocator, &socket, buffer[0..packet.bytes_received], packet.remote_address, packets_seen, config.qlog);
        } else {
            Time.sleep(10 * std.time.ns_per_ms);
        }
    }

    std.debug.print("zquic interop probe summary packets_seen={}\n", .{packets_seen});
    if (packets_seen == 0) return error.NoPacketsReceived;
}

fn parseArgs(process_args: std.process.Args) !Config {
    var config = Config{};
    var args = process_args.iterate();

    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--host")) {
            config.host = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "--port")) {
            config.port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, arg, "--duration-ms")) {
            config.duration_ms = try std.fmt.parseInt(u64, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, arg, "--max-packets")) {
            config.max_packets = try std.fmt.parseInt(usize, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, arg, "--qlog")) {
            config.qlog = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        } else {
            printUsage();
            return error.UnknownArgument;
        }
    }

    return config;
}

fn printUsage() void {
    std.debug.print(
        \\usage: zquic-interop-probe-server [--host 127.0.0.1] [--port 4433] [--duration-ms 10000] [--max-packets 8] [--qlog]
        \\
    , .{});
}

fn traceDatagram(
    allocator: std.mem.Allocator,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    ordinal: usize,
    qlog: bool,
) !void {
    const first = if (bytes.len > 0) bytes[0] else 0;
    const header_form = (first & 0x80) != 0;

    const parsed = Packet.PacketHeader.parse(bytes, allocator);
    if (parsed) |header| {
        const version = header.version orelse 0;
        tracePacket("packet_rx", ordinal, bytes.len, header.packet_type, version, header.dest_conn_id.len, if (header.src_conn_id) |cid| cid.len else 0, qlog);
        if (header.packet_type == .initial and version == zquic.quic_version) {
            try maybeSendInitialClose(allocator, socket, bytes, remote, header, qlog);
        }
    } else |err| {
        traceParseError(ordinal, bytes.len, header_form, err, qlog);
        if (header_form) {
            try maybeSendVersionNegotiation(socket, bytes, remote);
        }
    }
}

fn maybeSendInitialClose(
    allocator: std.mem.Allocator,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    header: Packet.PacketHeader,
    qlog: bool,
) !void {
    const client_scid = header.src_conn_id orelse return;

    var tls_context = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();
    try packet_crypto.installRfc9001ServerInitialKeys(header.dest_conn_id.bytes());

    var processed = packet_crypto.processProtectedRawPacket(bytes, null) catch |err| {
        traceInitialCrypto("initial_decrypt_failed", bytes.len, err, qlog);
        return;
    };
    defer processed.deinit(allocator);
    traceInitialCrypto("initial_decrypt_ok", processed.payload.len, null, qlog);

    const server_crypto_data = try processInitialFrames(
        allocator,
        processed.payload,
        qlog,
    );
    defer allocator.free(server_crypto_data);

    if (server_crypto_data.len > 0) {
        const scheduled = try sendConnectionPathServerInitialCrypto(
            allocator,
            socket,
            bytes,
            remote,
            &packet_crypto,
            header.dest_conn_id.bytes(),
            client_scid.bytes(),
            server_crypto_data.len,
            qlog,
        );
        if (scheduled == 0) {
            traceConnectionPathFlightSkipped(server_crypto_data.len, qlog);
        }
    }

    const close_payload = try buildConnectionClosePayload(allocator);
    defer allocator.free(close_payload);

    const response = try packet_crypto.createProtectedRawPacket(
        .initial,
        .initial,
        client_scid.bytes(),
        header.dest_conn_id.bytes(),
        close_payload,
    );
    defer allocator.free(response);

    _ = try socket.sendTo(response, remote);
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"initial_connection_close_tx","len":{},"payload_len":{},"full_handshake":false}}
            \\
        , .{ response.len, close_payload.len });
    } else {
        std.debug.print("interop trace event=initial_connection_close_tx len={} payload_len={}\n", .{ response.len, close_payload.len });
    }
}

fn sendConnectionPathServerInitialCrypto(
    allocator: std.mem.Allocator,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    packet_crypto: *PacketCrypto,
    original_dcid: []const u8,
    client_scid: []const u8,
    crypto_len: usize,
    qlog: bool,
) !usize {
    var conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer conn.deinit();

    var handshake_manager = zquic.core.Handshake.HandshakeManager.init(allocator, true);
    defer handshake_manager.deinit();
    try handshake_manager.startHandshake(original_dcid);

    try conn.queueIncomingRawPacket(bytes);
    const scheduled = try conn.processNextIncomingInitialCryptoAndScheduleServerFlight(
        packet_crypto,
        &handshake_manager,
        client_scid,
        original_dcid,
        null,
    );

    const outgoing = try conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(outgoing);
    for (outgoing) |*packet| {
        defer packet.deinit(allocator);
        _ = try socket.sendTo(packet.data, remote);
        traceServerInitialCryptoTx(packet.data.len, crypto_len, qlog);
    }

    return scheduled;
}

fn processInitialFrames(
    allocator: std.mem.Allocator,
    payload: []const u8,
    qlog: bool,
) ![]u8 {
    var handshake_manager = zquic.core.Handshake.HandshakeManager.init(allocator, true);
    defer handshake_manager.deinit();

    var server_crypto: std.ArrayListUnmanaged(u8) = .empty;
    errdefer server_crypto.deinit(allocator);

    var reader = std.Io.Reader.fixed(payload);
    var padding_count: usize = 0;
    while (reader.seek < reader.end) {
        var frame = QuicFrames.Frame.parse(&reader, allocator) catch |err| {
            traceFrameParseError(payload.len, reader.seek, err, qlog);
            return server_crypto.toOwnedSlice(allocator);
        };
        defer freeParsedFrame(allocator, &frame);

        if (frame == .padding) {
            padding_count += 1;
            continue;
        }
        if (padding_count > 0) {
            tracePaddingRun(padding_count, qlog);
            padding_count = 0;
        }

        traceFrameSummary(frame, qlog);
        switch (frame) {
            .crypto => |crypto| {
                traceCryptoFrame(crypto.offset, crypto.data.len, qlog);
                handshake_manager.processCryptoFrame(crypto.data, crypto.offset) catch |err| {
                    traceHandshakeFeed("handshake_crypto_feed_failed", crypto.offset, crypto.data.len, 0, err, qlog);
                    continue;
                };
                traceHandshakeFeed("handshake_crypto_feed_ok", crypto.offset, crypto.data.len, 0, null, qlog);

                const pending = handshake_manager.getPendingCryptoData();
                if (pending.len > 0) {
                    traceHandshakePending(pending.len, qlog);
                    try server_crypto.appendSlice(allocator, pending);
                    handshake_manager.clearSentCryptoData();
                }
            },
            else => {},
        }
    }
    if (padding_count > 0) {
        tracePaddingRun(padding_count, qlog);
    }
    return server_crypto.toOwnedSlice(allocator);
}

fn freeParsedFrame(allocator: std.mem.Allocator, frame: *QuicFrames.Frame) void {
    switch (frame.*) {
        .crypto => |crypto| allocator.free(crypto.data),
        .new_token => |new_token| allocator.free(new_token.token),
        .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| allocator.free(stream.data),
        .connection_close => |close| allocator.free(close.reason_phrase),
        .connection_close_app => |close| allocator.free(close.reason_phrase),
        .datagram, .datagram_len => |datagram| allocator.free(datagram.data),
        else => {},
    }
}

fn buildConnectionClosePayload(allocator: std.mem.Allocator) ![]u8 {
    var payload_buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&payload_buf);
    try (QuicFrames.Frame{
        .connection_close = QuicFrames.ConnectionCloseFrame.init(0, 0, "zquic probe"),
    }).serialize(&writer);
    return try allocator.dupe(u8, std.Io.Writer.buffered(&writer));
}

fn traceFrameSummary(frame: QuicFrames.Frame, qlog: bool) void {
    const frame_type = frame.getType();
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"frame_rx","frame_type":"{s}","ack_eliciting":{},"full_handshake":false}}
            \\
        , .{ frame_type.toString(), frame.isAckEliciting() });
    } else {
        std.debug.print("interop trace event=frame_rx frame_type={s} ack_eliciting={}\n", .{ frame_type.toString(), frame.isAckEliciting() });
    }
}

fn tracePaddingRun(count: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"padding_frames_rx","count":{},"full_handshake":false}}
            \\
        , .{count});
    } else {
        std.debug.print("interop trace event=padding_frames_rx count={}\n", .{count});
    }
}

fn traceCryptoFrame(offset: u64, len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"crypto_frame_rx","offset":{},"len":{},"full_handshake":false}}
            \\
        , .{ offset, len });
    } else {
        std.debug.print("interop trace event=crypto_frame_rx offset={} len={}\n", .{ offset, len });
    }
}

fn traceFrameParseError(payload_len: usize, offset: usize, err: anyerror, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"frame_parse_error","payload_len":{},"offset":{},"error":"{}","full_handshake":false}}
            \\
        , .{ payload_len, offset, err });
    } else {
        std.debug.print("interop trace event=frame_parse_error payload_len={} offset={} error={}\n", .{ payload_len, offset, err });
    }
}

fn traceHandshakeFeed(event: []const u8, offset: u64, len: usize, installed: usize, err: ?anyerror, qlog: bool) void {
    if (qlog) {
        if (err) |e| {
            std.debug.print(
                \\{{"qlog":"zquic","event":"{s}","offset":{},"len":{},"error":"{}","full_handshake":false}}
                \\
            , .{ event, offset, len, e });
        } else {
            std.debug.print(
                \\{{"qlog":"zquic","event":"{s}","offset":{},"len":{},"installed_keys":{},"full_handshake":false}}
                \\
            , .{ event, offset, len, installed });
        }
    } else if (err) |e| {
        std.debug.print("interop trace event={s} offset={} len={} error={}\n", .{ event, offset, len, e });
    } else {
        std.debug.print("interop trace event={s} offset={} len={} installed_keys={}\n", .{ event, offset, len, installed });
    }
}

fn traceHandshakePending(len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"server_initial_crypto_ready","len":{},"full_handshake":false}}
            \\
        , .{len});
    } else {
        std.debug.print("interop trace event=server_initial_crypto_ready len={}\n", .{len});
    }
}

fn traceServerInitialCryptoTx(packet_len: usize, crypto_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"server_initial_crypto_tx","len":{},"crypto_len":{},"source":"connection_path","full_handshake":false}}
            \\
        , .{ packet_len, crypto_len });
    } else {
        std.debug.print("interop trace event=server_initial_crypto_tx len={} crypto_len={} source=connection_path\n", .{ packet_len, crypto_len });
    }
}

fn traceConnectionPathFlightSkipped(crypto_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"server_initial_crypto_tx_skipped","crypto_len":{},"source":"connection_path","full_handshake":false}}
            \\
        , .{crypto_len});
    } else {
        std.debug.print("interop trace event=server_initial_crypto_tx_skipped crypto_len={} source=connection_path\n", .{crypto_len});
    }
}

fn traceInitialCrypto(event: []const u8, len: usize, err: ?anyerror, qlog: bool) void {
    if (qlog) {
        if (err) |e| {
            std.debug.print(
                \\{{"qlog":"zquic","event":"{s}","len":{},"error":"{}","full_handshake":false}}
                \\
            , .{ event, len, e });
        } else {
            std.debug.print(
                \\{{"qlog":"zquic","event":"{s}","len":{},"full_handshake":false}}
                \\
            , .{ event, len });
        }
    } else if (err) |e| {
        std.debug.print("interop trace event={s} len={} error={}\n", .{ event, len, e });
    } else {
        std.debug.print("interop trace event={s} len={}\n", .{ event, len });
    }
}

fn tracePacket(
    event: []const u8,
    ordinal: usize,
    len: usize,
    packet_type: Packet.PacketType,
    version: u32,
    dcid_len: usize,
    scid_len: usize,
    qlog: bool,
) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"{s}","ordinal":{},"len":{},"packet_type":"{}","version":"0x{x:0>8}","dcid_len":{},"scid_len":{},"full_handshake":false}}
            \\
        , .{ event, ordinal, len, packet_type, version, dcid_len, scid_len });
    } else {
        std.debug.print("interop trace event={s} ordinal={} len={} packet_type={} version=0x{x:0>8} dcid_len={} scid_len={}\n", .{
            event,
            ordinal,
            len,
            packet_type,
            version,
            dcid_len,
            scid_len,
        });
    }
}

fn traceParseError(ordinal: usize, len: usize, long_header: bool, err: anyerror, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"packet_parse_error","ordinal":{},"len":{},"long_header":{},"error":"{}","full_handshake":false}}
            \\
        , .{ ordinal, len, long_header, err });
    } else {
        std.debug.print("interop trace event=packet_parse_error ordinal={} len={} long_header={} error={}\n", .{ ordinal, len, long_header, err });
    }
}

fn maybeSendVersionNegotiation(socket: *UdpSocket, bytes: []const u8, remote: NetAddress.Address) !void {
    if (bytes.len < 7) return;
    if ((bytes[0] & 0x80) == 0) return;

    var pos: usize = 5;
    const dcid_len = bytes[pos];
    pos += 1;
    if (pos + dcid_len > bytes.len) return;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;
    if (pos >= bytes.len) return;
    const scid_len = bytes[pos];
    pos += 1;
    if (pos + scid_len > bytes.len) return;
    const scid = bytes[pos .. pos + scid_len];

    var response: [64]u8 = undefined;
    var out: usize = 0;
    response[out] = 0x80;
    out += 1;
    std.mem.writeInt(u32, response[out..][0..4], 0, .big);
    out += 4;
    response[out] = @intCast(scid.len);
    out += 1;
    @memcpy(response[out .. out + scid.len], scid);
    out += scid.len;
    response[out] = @intCast(dcid.len);
    out += 1;
    @memcpy(response[out .. out + dcid.len], dcid);
    out += dcid.len;
    std.mem.writeInt(u32, response[out..][0..4], zquic.quic_version, .big);
    out += 4;

    _ = try socket.sendTo(response[0..out], remote);
    std.debug.print("interop trace event=version_negotiation_tx len={} version=0x{x:0>8}\n", .{ out, zquic.quic_version });
}
