//! Live UDP interop probe for external QUIC client smoke tests.
//!
//! This endpoint is intentionally narrow: it receives UDP datagrams, parses
//! QUIC long/short headers when possible, emits structured trace lines, and
//! sends Version Negotiation for unsupported long-header versions. It keeps
//! per-connection TLS and packet-protection state between datagrams so an
//! accepted ClientHello can be answered with a complete authenticated TLS 1.3
//! server flight. The probe verifies peer Finished before installing RFC 9001
//! application keys. It has a bounded probe-only HTTP/3 success path, but is not
//! a production server or general HTTP/3 implementation.

const std = @import("std");
const zquic = @import("zquic");

const Packet = zquic.Packet;
const PacketCrypto = zquic.PacketCrypto;
const Time = zquic.Time;
const UdpSocket = zquic.UdpSocket;
const NetAddress = zquic.NetAddress;
const QuicFrames = zquic.core.QuicFrames;
const MinimalHttp3 = zquic.Http3.MinimalInterop;

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    duration_ms: u64 = 10_000,
    max_packets: usize = 8,
    qlog: bool = false,
};

/// Upper bound on concurrent probe connections. The probe is a smoke-test
/// endpoint, not a server, so a small fixed cap is enough and keeps a hostile
/// or looping client from growing the table without limit.
const max_connections = 8;
const max_h3_streams = 8;
const max_pending_application_packets = 8;

/// A connection with no traffic for this long is dropped, releasing its keys.
const idle_timeout_us: i64 = 30 * std.time.us_per_s;

/// Bound incomplete handshakes independently of general connection idleness.
const handshake_timeout_us: u64 = 5 * std.time.us_per_s;

const ProbeStream = struct {
    active: bool = false,
    id: u64 = 0,
    reassembly: MinimalHttp3.StreamReassembler = .{},
    processed: bool = false,
};

/// Per-connection state retained between datagrams.
///
/// Heap-allocated and never moved: `PacketCrypto` holds a pointer to the
/// `EnhancedTlsContext` stored in this same struct, so the address has to stay
/// stable for the connection's whole lifetime.
const ProbeConnection = struct {
    allocator: std.mem.Allocator,
    /// Destination connection ID the client used on its Initial packets. The
    /// probe echoes it back as its own source connection ID, so it doubles as
    /// the table key.
    dcid: Packet.ConnectionId,
    server_scid: Packet.ConnectionId,
    client_scid: Packet.ConnectionId,
    remote: NetAddress.Address,
    handshake_started_us: u64,
    last_activity_us: i64,
    datagrams: usize = 0,
    handshake_keys_installed: bool = false,
    handshake_confirmed: bool = false,
    largest_initial_received: ?u64 = null,
    largest_handshake_received: ?u64 = null,
    largest_application_received: ?u64 = null,
    pending_application_packets: [max_pending_application_packets]?[]u8 = @splat(null),
    pending_application_packet_count: usize = 0,
    h3_streams: [max_h3_streams]ProbeStream = @splat(.{}),
    peer_settings_received: bool = false,
    server_settings_sent: bool = false,
    response_sent: bool = false,

    tls_context: zquic.EnhancedCrypto.EnhancedTlsContext,
    packet_crypto: PacketCrypto,
    comprehensive_tls: zquic.ComprehensiveTls.ComprehensiveTlsContext,
    handshake_manager: zquic.core.Handshake.HandshakeManager,
    conn: zquic.Connection.SuperConnection,

    fn create(
        allocator: std.mem.Allocator,
        dcid: Packet.ConnectionId,
        client_scid: Packet.ConnectionId,
        remote: NetAddress.Address,
        now_us: i64,
        identity: *const zquic.Tls13Identity.EphemeralIdentity,
        p256_identity: *const zquic.Tls13Identity.EphemeralP256Identity,
    ) !*ProbeConnection {
        const self = try allocator.create(ProbeConnection);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.dcid = dcid;
        const server_cid_bytes = identity.deriveConnectionId(dcid.bytes(), client_scid.bytes(), now_us);
        self.server_scid = try Packet.ConnectionId.init(&server_cid_bytes);
        self.client_scid = client_scid;
        self.remote = remote;
        self.handshake_started_us = @intCast(@max(now_us, 0));
        self.last_activity_us = now_us;
        self.datagrams = 0;
        self.handshake_keys_installed = false;
        self.handshake_confirmed = false;
        self.largest_initial_received = null;
        self.largest_handshake_received = null;
        self.largest_application_received = null;
        self.pending_application_packets = @splat(null);
        self.pending_application_packet_count = 0;
        self.h3_streams = @splat(.{});
        self.peer_settings_received = false;
        self.server_settings_sent = false;
        self.response_sent = false;

        self.tls_context = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
        errdefer self.tls_context.deinit();
        self.comprehensive_tls = zquic.ComprehensiveTls.ComprehensiveTlsContext.init(allocator, true);
        errdefer self.comprehensive_tls.deinit();
        self.handshake_manager = zquic.core.Handshake.HandshakeManager.init(allocator, true);
        errdefer self.handshake_manager.deinit();
        self.conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
        errdefer self.conn.deinit();

        self.packet_crypto = try PacketCrypto.init(allocator, &self.tls_context, null);
        errdefer self.packet_crypto.deinit();

        try self.comprehensive_tls.initServer(&.{identity.certificate_der});
        try self.comprehensive_tls.setServerEd25519SigningKey(&identity.secret_key);
        try self.comprehensive_tls.setServerEcdsaP256Identity(
            p256_identity.certificate_der,
            &p256_identity.secret_key,
        );
        try self.comprehensive_tls.setServerQuicTransportContext(self.dcid.bytes(), self.server_scid.bytes());
        try self.comprehensive_tls.setPeerNegotiationContext(.{
            .peer_role = .client,
            .initial_source_connection_id = self.client_scid.bytes(),
        });
        try self.handshake_manager.startHandshake(self.dcid.bytes());
        try self.packet_crypto.installRfc9001ServerInitialKeys(self.dcid.bytes());
        return self;
    }

    fn destroy(self: *ProbeConnection) void {
        const allocator = self.allocator;
        for (self.pending_application_packets[0..self.pending_application_packet_count]) |packet| {
            if (packet) |bytes| allocator.free(bytes);
        }
        self.conn.deinit();
        self.handshake_manager.deinit();
        self.comprehensive_tls.deinit();
        self.packet_crypto.deinit();
        self.tls_context.deinit();
        allocator.destroy(self);
    }

    fn matches(self: *const ProbeConnection, dcid: *const Packet.ConnectionId, remote: NetAddress.Address) bool {
        return (self.dcid.eql(dcid) or self.server_scid.eql(dcid)) and self.remote.eql(&remote);
    }
};

/// Small fixed-capacity connection table keyed by (destination connection ID,
/// remote address).
const ConnectionTable = struct {
    allocator: std.mem.Allocator,
    identity: *const zquic.Tls13Identity.EphemeralIdentity,
    p256_identity: *const zquic.Tls13Identity.EphemeralP256Identity,
    entries: std.ArrayListUnmanaged(*ProbeConnection) = .empty,

    fn deinit(self: *ConnectionTable) void {
        for (self.entries.items) |connection| connection.destroy();
        self.entries.deinit(self.allocator);
    }

    fn find(
        self: *ConnectionTable,
        dcid: *const Packet.ConnectionId,
        remote: NetAddress.Address,
    ) ?*ProbeConnection {
        for (self.entries.items) |connection| {
            if (connection.matches(dcid, remote)) return connection;
        }
        return null;
    }

    fn evictIdle(self: *ConnectionTable, now_us: i64, qlog: bool) void {
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const connection = self.entries.items[index];
            if (now_us - connection.last_activity_us >= idle_timeout_us) {
                traceConnectionEvicted(connection.datagrams, qlog);
                connection.destroy();
                _ = self.entries.swapRemove(index);
                continue;
            }
            index += 1;
        }
    }

    fn pollRecovery(self: *ConnectionTable, socket: *UdpSocket, now_us: i64, qlog: bool) !void {
        const now: u64 = @intCast(@max(now_us, 0));
        for (self.entries.items) |connection| {
            if (!connection.handshake_confirmed and try connection.conn.pollHandshakeTimeout(
                connection.handshake_started_us,
                now,
                handshake_timeout_us,
            )) {
                traceHandshakeTimeout(now - connection.handshake_started_us, qlog);
                continue;
            }
            const result = try connection.conn.pollLossRecovery(
                &connection.packet_crypto,
                now,
                connection.client_scid.bytes(),
                connection.server_scid.bytes(),
            );
            if (result.count == 0) continue;

            tracePtoScheduled(result.pto_count, result.count, qlog);
            for (result.slice()) |probe| {
                if (probe.retransmitted_crypto) {
                    traceCryptoRetransmission(probe.encryption_level, probe.packet_number, probe.crypto_len, qlog);
                }
            }
            try flushOutgoingRecovery(connection, socket);
        }
    }

    /// Look the connection up, creating it if the table has room. Returns null
    /// when the table is full, in which case the datagram is only traced.
    fn getOrCreate(
        self: *ConnectionTable,
        dcid: Packet.ConnectionId,
        client_scid: Packet.ConnectionId,
        remote: NetAddress.Address,
        now_us: i64,
        qlog: bool,
    ) !?*ProbeConnection {
        self.evictIdle(now_us, qlog);

        if (self.find(&dcid, remote)) |existing| {
            existing.last_activity_us = now_us;
            existing.datagrams += 1;
            traceConnectionStateReused(existing, qlog);
            return existing;
        }

        if (self.entries.items.len >= max_connections) {
            traceConnectionTableFull(self.entries.items.len, qlog);
            return null;
        }

        const connection = try ProbeConnection.create(
            self.allocator,
            dcid,
            client_scid,
            remote,
            now_us,
            self.identity,
            self.p256_identity,
        );
        errdefer connection.destroy();
        try self.entries.append(self.allocator, connection);
        connection.datagrams += 1;
        return connection;
    }
};

fn flushPendingAcks(connection: *ProbeConnection, socket: *UdpSocket, qlog: bool) !void {
    const scheduled = try connection.conn.schedulePendingAckFramesWithMetadata(
        &connection.packet_crypto,
        connection.client_scid.bytes(),
        connection.server_scid.bytes(),
    );
    if (scheduled.count == 0) return;

    const outgoing = try connection.conn.drainOutgoingRawPackets(connection.allocator);
    defer {
        for (outgoing) |*packet| packet.deinit(connection.allocator);
        connection.allocator.free(outgoing);
    }
    if (outgoing.len != scheduled.count) return error.InvalidState;
    for (outgoing, scheduled.slice()) |packet, metadata| {
        _ = try socket.sendTo(packet.data, connection.remote);
        traceAckSent(metadata, qlog);
    }
}

fn flushOutgoingRecovery(connection: *ProbeConnection, socket: *UdpSocket) !void {
    const outgoing = try connection.conn.drainOutgoingRawPackets(connection.allocator);
    defer {
        for (outgoing) |*packet| packet.deinit(connection.allocator);
        connection.allocator.free(outgoing);
    }
    for (outgoing) |packet| _ = try socket.sendTo(packet.data, connection.remote);
}

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
    std.debug.print("zquic interop probe mode=packet-trace tls=bounded-server http3=minimal\n", .{});

    var identity = try zquic.Tls13Identity.EphemeralIdentity.generate(allocator);
    defer identity.deinit();
    var p256_identity = try zquic.Tls13Identity.EphemeralP256Identity.generate(allocator);
    defer p256_identity.deinit();
    var connections = ConnectionTable{
        .allocator = allocator,
        .identity = &identity,
        .p256_identity = &p256_identity,
    };
    defer connections.deinit();

    const start = Time.nowMicros();
    var packets_seen: usize = 0;
    var buffer: [65535]u8 = undefined;

    while (packets_seen < config.max_packets) {
        const now = Time.nowMicros();
        if (now - start >= config.duration_ms * std.time.us_per_ms) break;

        const received = try socket.tryReceiveFrom(&buffer);
        if (received) |packet| {
            packets_seen += 1;
            try traceDatagram(&connections, &socket, buffer[0..packet.bytes_received], packet.remote_address, packets_seen, now, config.qlog);
        } else {
            connections.evictIdle(now, config.qlog);
            try connections.pollRecovery(&socket, now, config.qlog);
            Time.sleep(10 * std.time.ns_per_ms);
        }
    }

    std.debug.print("zquic interop probe summary packets_seen={} connections={}\n", .{ packets_seen, connections.entries.items.len });
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
    connections: *ConnectionTable,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    ordinal: usize,
    now_us: i64,
    qlog: bool,
) !void {
    const first = if (bytes.len > 0) bytes[0] else 0;
    const header_form = (first & 0x80) != 0;

    const parsed = Packet.PacketHeader.parse(bytes, connections.allocator);
    if (parsed) |header| {
        const version = header.version orelse 0;
        tracePacket("packet_rx", ordinal, bytes.len, header.packet_type, version, header.dest_conn_id.len, if (header.src_conn_id) |cid| cid.len else 0, qlog);
        if (header.version) |wire_version| {
            if (wire_version != zquic.quic_version) return;
        }

        switch (header.packet_type) {
            .initial => try handleInitialPacket(connections, socket, bytes, remote, header, now_us, qlog),
            .handshake => try traceClientHandshakePacket(connections, socket, bytes, remote, header, now_us, qlog),
            .one_rtt => try traceClientApplicationPacket(connections, socket, bytes, remote, header, now_us, qlog),
            else => {},
        }
    } else |err| {
        traceParseError(ordinal, bytes.len, header_form, err, qlog);
        if (err == error.NotSupported) {
            try maybeSendVersionNegotiation(socket, bytes, remote);
        }
    }
}

fn handleInitialPacket(
    connections: *ConnectionTable,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    header: Packet.PacketHeader,
    now_us: i64,
    qlog: bool,
) !void {
    const client_scid = header.src_conn_id orelse return;
    const allocator = connections.allocator;

    const connection = try connections.getOrCreate(
        header.dest_conn_id,
        client_scid,
        remote,
        now_us,
        qlog,
    ) orelse return;

    // Unprotect once purely to trace the frames the client sent. The
    // connection path below unprotects the same datagram again for the
    // handshake itself; receiving does not consume a packet number, so the two
    // passes cannot disagree.
    var processed = connection.packet_crypto.processProtectedRawPacket(bytes, connection.largest_initial_received) catch |err| {
        traceInitialCrypto("initial_decrypt_failed", bytes.len, err, qlog);
        return;
    };
    defer processed.deinit(allocator);
    traceInitialCrypto("initial_decrypt_ok", processed.payload.len, null, qlog);
    traceInitialFrames(allocator, processed.payload, qlog);

    try advanceHandshake(connection, socket, bytes, connection.largest_initial_received, qlog);
    connection.largest_initial_received = if (connection.largest_initial_received) |largest|
        @max(largest, processed.packet_number)
    else
        processed.packet_number;
    try flushPendingAcks(connection, socket, qlog);

    // CONNECTION_CLOSE is the fallback evidence packet for a connection that
    // could not be taken any further. Once real Handshake keys are installed
    // the client is mid-handshake, so closing would destroy the state this
    // phase exists to prove.
    if (connection.handshake_keys_installed) return;
    try sendInitialConnectionClose(connection, socket, qlog);
}

/// Feed one Initial datagram through the connection path and flush whatever it
/// scheduled in reply.
fn advanceHandshake(
    connection: *ProbeConnection,
    socket: *UdpSocket,
    bytes: []const u8,
    largest_processed: ?u64,
    qlog: bool,
) !void {
    const allocator = connection.allocator;

    try connection.conn.queueIncomingRawPacket(bytes);
    const result = connection.conn.processNextIncomingInitialCryptoAndScheduleServerFlightWithComprehensiveTls(
        &connection.packet_crypto,
        &connection.handshake_manager,
        &connection.comprehensive_tls,
        connection.client_scid.bytes(),
        connection.server_scid.bytes(),
        largest_processed,
    ) catch |err| {
        traceClientHelloRejected(
            @tagName(connection.comprehensive_tls.state),
            @tagName(connection.comprehensive_tls.client_hello_stage),
            err,
            qlog,
        );
        return;
    };

    if (result.tls_messages_processed > 0) {
        if (connection.conn.getPeerTransportParameters() == null) {
            try connection.conn.applyPeerTransportParametersFromTls(&connection.comprehensive_tls, .{
                .peer_role = .client,
                .initial_source_connection_id = connection.client_scid.bytes(),
            });
        }
        traceClientHelloAccepted(result.tls_messages_processed, @tagName(connection.comprehensive_tls.state), qlog);
    }
    if (result.handshake_keys_installed) {
        connection.handshake_keys_installed = true;
        traceHandshakeKeysInstalled(result.server_hello_bytes, qlog);
    }

    const outgoing = try connection.conn.drainOutgoingRawPackets(allocator);
    defer {
        for (outgoing) |*packet| packet.deinit(allocator);
        allocator.free(outgoing);
    }
    for (outgoing, 0..) |*packet, index| {
        _ = try socket.sendTo(packet.data, connection.remote);
        if (index == 0 and result.server_hello_bytes > 0) {
            traceServerHelloInitialCryptoTx(packet.data.len, result.server_hello_bytes, qlog);
        } else if (result.server_handshake_bytes > 0) {
            traceServerHandshakeFlightTx(packet.data.len, result.server_handshake_bytes, qlog);
        }
    }
}

fn sendInitialConnectionClose(connection: *ProbeConnection, socket: *UdpSocket, qlog: bool) !void {
    const allocator = connection.allocator;

    const close_payload = try buildConnectionClosePayload(allocator);
    defer allocator.free(close_payload);

    const response = try connection.packet_crypto.createProtectedRawPacket(
        .initial,
        .initial,
        connection.client_scid.bytes(),
        connection.server_scid.bytes(),
        close_payload,
    );
    defer allocator.free(response);

    _ = try socket.sendTo(response, connection.remote);
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"initial_connection_close_tx","len":{},"payload_len":{},"full_handshake":false}}
            \\
        , .{ response.len, close_payload.len });
    } else {
        std.debug.print("interop trace event=initial_connection_close_tx len={} payload_len={}\n", .{ response.len, close_payload.len });
    }
}

/// Process a client Handshake packet under the installed RFC 9001 Handshake
/// keys. A valid Finished advances the strict TLS transcript and installs 1-RTT
/// keys; ACK-only packets remain observational.
fn traceClientHandshakePacket(
    connections: *ConnectionTable,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    header: Packet.PacketHeader,
    now_us: i64,
    qlog: bool,
) !void {
    const connection = connections.find(&header.dest_conn_id, remote) orelse return;
    connection.last_activity_us = now_us;
    connection.datagrams += 1;
    if (!connection.handshake_keys_installed) return;

    connection.conn.queueIncomingRawPacket(bytes) catch |err| {
        traceInitialCrypto("client_handshake_decrypt_failed", bytes.len, err, qlog);
        return;
    };
    var processed = connection.conn.processNextIncomingRawCryptoPacketWithComprehensiveTls(
        &connection.packet_crypto,
        &connection.handshake_manager,
        &connection.tls_context,
        &connection.comprehensive_tls,
        connection.server_scid.bytes(),
        connection.largest_handshake_received,
    ) catch |err| {
        traceInitialCrypto("client_handshake_decrypt_failed", bytes.len, err, qlog);
        return;
    } orelse return;
    defer processed.deinit(connection.allocator);
    connection.largest_handshake_received = if (connection.largest_handshake_received) |largest|
        @max(largest, processed.packet_number)
    else
        processed.packet_number;
    traceInitialCrypto("client_handshake_decrypt_ok", processed.payload.len, null, qlog);
    traceAckFrames(connection.allocator, processed.payload, .handshake, qlog);
    connection.conn.discardPacketNumberSpace(.initial);
    var newly_confirmed = false;
    if (connection.packet_crypto.isLevelPinned(.application) and !connection.handshake_confirmed) {
        connection.handshake_confirmed = true;
        newly_confirmed = true;
        traceHandshakeConfirmed(qlog);
    }
    try flushPendingAcks(connection, socket, qlog);
    if (newly_confirmed) connection.conn.discardPacketNumberSpace(.handshake);
    if (newly_confirmed) try sendServerHttp3Control(connection, socket, qlog);
    if (connection.handshake_confirmed) {
        for (connection.pending_application_packets[0..connection.pending_application_packet_count]) |*slot| {
            const pending = slot.* orelse continue;
            slot.* = null;
            defer connection.allocator.free(pending);
            try processClientApplicationPacket(connection, socket, pending, qlog);
        }
        connection.pending_application_packet_count = 0;
    }
}

fn traceClientApplicationPacket(
    connections: *ConnectionTable,
    socket: *UdpSocket,
    bytes: []const u8,
    remote: NetAddress.Address,
    header: Packet.PacketHeader,
    now_us: i64,
    qlog: bool,
) !void {
    const connection = connections.find(&header.dest_conn_id, remote) orelse {
        var cid_match = false;
        var remote_match = false;
        for (connections.entries.items) |candidate| {
            cid_match = cid_match or candidate.dcid.eql(&header.dest_conn_id) or candidate.server_scid.eql(&header.dest_conn_id);
            remote_match = remote_match or candidate.remote.eql(&remote);
        }
        traceConnectionLookupMiss(cid_match, remote_match, qlog);
        return;
    };
    connection.last_activity_us = now_us;
    connection.datagrams += 1;
    if (!connection.handshake_confirmed) {
        if (connection.pending_application_packet_count < connection.pending_application_packets.len) {
            const index = connection.pending_application_packet_count;
            connection.pending_application_packets[index] = try connection.allocator.dupe(u8, bytes);
            connection.pending_application_packet_count += 1;
            traceApplicationBuffered(bytes.len, connection.pending_application_packet_count, qlog);
        }
        traceInitialCrypto("client_application_before_handshake_confirmed", bytes.len, null, qlog);
        return;
    }

    try processClientApplicationPacket(connection, socket, bytes, qlog);
}

fn processClientApplicationPacket(
    connection: *ProbeConnection,
    socket: *UdpSocket,
    bytes: []const u8,
    qlog: bool,
) !void {
    connection.conn.queueIncomingRawPacket(bytes) catch |err| {
        traceInitialCrypto("client_application_decrypt_failed", bytes.len, err, qlog);
        return;
    };
    var processed = connection.conn.processNextIncomingRawPacket(
        &connection.packet_crypto,
        connection.largest_application_received,
    ) catch |err| {
        traceInitialCrypto("client_application_decrypt_failed", bytes.len, err, qlog);
        return;
    } orelse return;
    defer processed.deinit(connection.allocator);
    connection.largest_application_received = if (connection.largest_application_received) |largest|
        @max(largest, processed.packet_number)
    else
        processed.packet_number;
    traceInitialCrypto("client_application_decrypt_ok", processed.payload.len, null, qlog);
    traceAckFrames(connection.allocator, processed.payload, .application, qlog);
    try recordHttp3StreamFrames(connection, processed.payload, qlog);
    try flushPendingAcks(connection, socket, qlog);
    try processHttp3Streams(connection, socket, qlog);
}

fn recordHttp3StreamFrames(connection: *ProbeConnection, payload: []const u8, qlog: bool) !void {
    var reader = std.Io.Reader.fixed(payload);
    while (reader.seek < reader.end) {
        var frame = QuicFrames.Frame.parse(&reader, connection.allocator) catch return;
        defer frame.deinit(connection.allocator);
        if (frame != .stream) continue;

        const stream = frame.stream;
        if (stream.stream_id & 0x01 != 0) {
            traceHttp3Error(stream.stream_id, "peer_used_server_stream", qlog);
            continue;
        }
        const tracked = streamFor(connection, stream.stream_id) orelse {
            traceHttp3Error(stream.stream_id, "stream_limit", qlog);
            continue;
        };
        tracked.reassembly.insert(stream.offset, stream.data, stream.fin) catch |err| {
            traceHttp3Error(stream.stream_id, @errorName(err), qlog);
            continue;
        };
        traceHttp3StreamData(stream.stream_id, stream.offset, stream.data.len, stream.fin, tracked.reassembly.contiguous_len, qlog);
    }
}

fn streamFor(connection: *ProbeConnection, stream_id: u64) ?*ProbeStream {
    for (&connection.h3_streams) |*stream| {
        if (stream.active and stream.id == stream_id) return stream;
    }
    for (&connection.h3_streams) |*stream| {
        if (!stream.active) {
            stream.* = .{ .active = true, .id = stream_id };
            return stream;
        }
    }
    return null;
}

fn processHttp3Streams(connection: *ProbeConnection, socket: *UdpSocket, qlog: bool) !void {
    // Control streams are processed before requests even when both arrived in
    // the same QUIC packet in the opposite frame order.
    for (&connection.h3_streams) |*stream| {
        if (!stream.active or stream.processed or stream.id & 0x03 != 0x02) continue;
        const bytes = stream.reassembly.contiguous();
        const stream_type = MinimalHttp3.parseStreamType(bytes) catch continue;
        switch (stream_type) {
            0x00 => {
                MinimalHttp3.parseControlSettings(bytes) catch |err| switch (err) {
                    MinimalHttp3.Error.WouldBlock => continue,
                    else => {
                        stream.processed = true;
                        traceHttp3Error(stream.id, @errorName(err), qlog);
                        continue;
                    },
                };
                connection.peer_settings_received = true;
                stream.processed = true;
                tracePeerSettingsReceived(stream.id, qlog);
            },
            0x02, 0x03 => {
                // Dynamic capacity is zero, so no encoder instructions are
                // required for this phase. Recognize each critical stream and
                // retain no instruction bytes.
                stream.processed = true;
                traceQpackStream(stream.id, stream_type, qlog);
            },
            else => stream.processed = true,
        }
    }

    if (!connection.peer_settings_received or connection.response_sent) return;
    for (&connection.h3_streams) |*stream| {
        if (!stream.active or stream.processed or stream.id & 0x03 != 0x00) continue;
        _ = MinimalHttp3.parseGetRootRequest(stream.reassembly.contiguous()) catch |err| switch (err) {
            MinimalHttp3.Error.WouldBlock => continue,
            else => {
                stream.processed = true;
                traceHttp3RequestParseError(stream.id, stream.reassembly.contiguous(), stream.reassembly.complete(), qlog);
                traceHttp3Error(stream.id, @errorName(err), qlog);
                continue;
            },
        };
        stream.processed = true;
        traceHttp3RequestAccepted(stream.id, qlog);
        try sendGetRootResponse(connection, socket, stream.id, qlog);
        return;
    }
}

fn sendServerHttp3Control(connection: *ProbeConnection, socket: *UdpSocket, qlog: bool) !void {
    if (connection.server_settings_sent) return;
    const frames = [_]QuicFrames.Frame{
        .{ .handshake_done = QuicFrames.HandshakeDoneFrame.init() },
        .{ .stream_off_len = QuicFrames.StreamFrame.init(3, 0, &MinimalHttp3.server_control_bytes, false, true, true) },
    };
    try connection.conn.scheduleFramesAsProtectedRawPacket(
        &connection.packet_crypto,
        .application,
        .one_rtt,
        connection.client_scid.bytes(),
        &.{},
        &frames,
    );
    try flushOutgoingRecovery(connection, socket);
    connection.server_settings_sent = true;
    traceServerSettingsSent(3, qlog);
}

fn sendGetRootResponse(connection: *ProbeConnection, socket: *UdpSocket, stream_id: u64, qlog: bool) !void {
    const frames = [_]QuicFrames.Frame{
        .{ .stream_off_len_fin = QuicFrames.StreamFrame.init(
            stream_id,
            0,
            &MinimalHttp3.get_root_response_bytes,
            true,
            true,
            true,
        ) },
    };
    try connection.conn.scheduleFramesAsProtectedRawPacket(
        &connection.packet_crypto,
        .application,
        .one_rtt,
        connection.client_scid.bytes(),
        &.{},
        &frames,
    );
    try flushOutgoingRecovery(connection, socket);
    connection.response_sent = true;
    traceHttp3ResponseSent(stream_id, MinimalHttp3.get_root_response_bytes.len, qlog);
}

fn traceConnectionLookupMiss(cid_match: bool, remote_match: bool, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"connection_lookup_miss","cid_match":{},"remote_match":{},"full_handshake":false}}
            \\
        , .{ cid_match, remote_match });
    } else {
        std.debug.print("interop trace event=connection_lookup_miss cid_match={} remote_match={}\n", .{ cid_match, remote_match });
    }
}

/// Trace the frames in a decrypted Initial payload. Purely observational: the
/// handshake itself is driven by the connection path, not from here.
fn traceInitialFrames(allocator: std.mem.Allocator, payload: []const u8, qlog: bool) void {
    var reader = std.Io.Reader.fixed(payload);
    var padding_count: usize = 0;
    while (reader.seek < reader.end) {
        var frame = QuicFrames.Frame.parse(&reader, allocator) catch |err| {
            traceFrameParseError(payload.len, reader.seek, err, qlog);
            break;
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
        if (frame == .crypto) {
            traceCryptoFrame(frame.crypto.offset, frame.crypto.data.len, qlog);
        }
    }
    if (padding_count > 0) {
        tracePaddingRun(padding_count, qlog);
    }
}

fn traceAckFrames(allocator: std.mem.Allocator, payload: []const u8, level: anytype, qlog: bool) void {
    var reader = std.Io.Reader.fixed(payload);
    while (reader.seek < reader.end) {
        var frame = QuicFrames.Frame.parse(&reader, allocator) catch return;
        defer freeParsedFrame(allocator, &frame);
        switch (frame) {
            .ack => |ack| traceAckReceived(level, ack.largest_acknowledged, ack.ack_range_count + 1, qlog),
            .ack_ecn => |ack| traceAckReceived(level, ack.ack_frame.largest_acknowledged, ack.ack_frame.ack_range_count + 1, qlog),
            else => {},
        }
    }
}

fn freeParsedFrame(allocator: std.mem.Allocator, frame: *QuicFrames.Frame) void {
    frame.deinit(allocator);
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

/// A structurally valid ClientHello was parsed and accepted. `state` is the TLS
/// state name after the message was consumed.
fn traceClientHelloAccepted(messages_processed: usize, state: []const u8, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"client_hello_accepted","messages_processed":{},"state":"{s}","persistent_connection":true,"full_handshake":false}}
            \\
        , .{ messages_processed, state });
    } else {
        std.debug.print(
            "interop trace event=client_hello_accepted messages_processed={} state={s} persistent_connection=true\n",
            .{ messages_processed, state },
        );
    }
}

fn traceClientHelloRejected(state: []const u8, stage: []const u8, err: anyerror, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"client_hello_rejected","state":"{s}","stage":"{s}","error":"{}","persistent_connection":true,"full_handshake":false}}
            \\
        , .{ state, stage, err });
    } else {
        std.debug.print(
            "interop trace event=client_hello_rejected state={s} stage={s} error={} persistent_connection=true\n",
            .{ state, stage, err },
        );
    }
}

/// A real TLS 1.3 ServerHello left as Initial-level CRYPTO. `crypto_len` is the
/// framed ServerHello length; no key or secret material is ever traced.
fn traceServerHelloInitialCryptoTx(packet_len: usize, crypto_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"server_hello_initial_crypto_tx","len":{},"crypto_len":{},"source":"connection_path","full_handshake":false}}
            \\
        , .{ packet_len, crypto_len });
    } else {
        std.debug.print(
            "interop trace event=server_hello_initial_crypto_tx len={} crypto_len={} source=connection_path\n",
            .{ packet_len, crypto_len },
        );
    }
}

fn traceServerHandshakeFlightTx(packet_len: usize, crypto_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"server_handshake_flight_tx","len":{},"crypto_len":{},"messages":4,"full_handshake":false}}
            \\
        , .{ packet_len, crypto_len });
    } else {
        std.debug.print(
            "interop trace event=server_handshake_flight_tx len={} crypto_len={} messages=4\n",
            .{ packet_len, crypto_len },
        );
    }
}

fn traceHandshakeKeysInstalled(server_hello_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"handshake_keys_installed","level":"handshake","cipher_suite":"TLS_AES_128_GCM_SHA256","key_exchange":"x25519","server_hello_len":{},"full_handshake":false}}
            \\
        , .{server_hello_len});
    } else {
        std.debug.print(
            "interop trace event=handshake_keys_installed level=handshake cipher_suite=TLS_AES_128_GCM_SHA256 key_exchange=x25519 server_hello_len={}\n",
            .{server_hello_len},
        );
    }
}

fn traceHandshakeConfirmed(qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"handshake_confirmed","application_keys_installed":true,"full_handshake":true}}
            \\
        , .{});
    } else {
        std.debug.print("interop trace event=handshake_confirmed application_keys_installed=true\n", .{});
    }
}

fn traceAckSent(metadata: zquic.Connection.ScheduledAckPacket, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"ack_sent","level":"{s}","packet_number":{},"largest_acknowledged":{},"range_count":{},"full_handshake":false}}
            \\
        , .{ @tagName(metadata.encryption_level), metadata.packet_number, metadata.largest_acknowledged, metadata.range_count });
    } else {
        std.debug.print("interop trace event=ack_sent level={s} pn={} largest={} ranges={}\n", .{
            @tagName(metadata.encryption_level),
            metadata.packet_number,
            metadata.largest_acknowledged,
            metadata.range_count,
        });
    }
}

fn traceAckReceived(level: anytype, largest: u64, range_count: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"ack_received","level":"{s}","largest_acknowledged":{},"range_count":{},"full_handshake":false}}
            \\
        , .{ @tagName(level), largest, range_count });
    } else {
        std.debug.print("interop trace event=ack_received level={s} largest={} ranges={}\n", .{ @tagName(level), largest, range_count });
    }
}

fn tracePtoScheduled(pto_count: u32, probe_count: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"pto_probe_scheduled","pto_count":{},"probe_count":{},"full_handshake":false}}
            \\
        , .{ pto_count, probe_count });
    } else {
        std.debug.print("interop trace event=pto_probe_scheduled pto_count={} probes={}\n", .{ pto_count, probe_count });
    }
}

fn traceCryptoRetransmission(level: anytype, packet_number: u64, crypto_len: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"crypto_retransmission","level":"{s}","packet_number":{},"crypto_len":{},"full_handshake":false}}
            \\
        , .{ @tagName(level), packet_number, crypto_len });
    } else {
        std.debug.print("interop trace event=crypto_retransmission level={s} pn={} crypto_len={}\n", .{ @tagName(level), packet_number, crypto_len });
    }
}

fn traceHandshakeTimeout(elapsed_us: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"handshake_timeout","elapsed_us":{},"state":"draining","full_handshake":false}}
            \\
        , .{elapsed_us});
    } else {
        std.debug.print("interop trace event=handshake_timeout elapsed_us={} state=draining\n", .{elapsed_us});
    }
}

fn traceApplicationBuffered(packet_len: usize, count: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"client_application_buffered","packet_len":{},"count":{},"limit":{},"full_handshake":false}}
            \\
        , .{ packet_len, count, max_pending_application_packets });
    } else {
        std.debug.print("interop trace event=client_application_buffered packet_len={} count={} limit={}\n", .{ packet_len, count, max_pending_application_packets });
    }
}

fn traceServerSettingsSent(stream_id: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_server_settings_sent","stream_id":{},"dynamic_table_capacity":0,"full_handshake":true}}
            \\
        , .{stream_id});
    } else {
        std.debug.print("interop trace event=h3_server_settings_sent stream_id={} dynamic_table_capacity=0\n", .{stream_id});
    }
}

fn tracePeerSettingsReceived(stream_id: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_peer_settings_received","stream_id":{},"full_handshake":true}}
            \\
        , .{stream_id});
    } else {
        std.debug.print("interop trace event=h3_peer_settings_received stream_id={}\n", .{stream_id});
    }
}

fn traceQpackStream(stream_id: u64, stream_type: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_qpack_stream_seen","stream_id":{},"stream_type":{},"dynamic_table_capacity":0,"full_handshake":true}}
            \\
        , .{ stream_id, stream_type });
    } else {
        std.debug.print("interop trace event=h3_qpack_stream_seen stream_id={} stream_type={}\n", .{ stream_id, stream_type });
    }
}

fn traceHttp3RequestAccepted(stream_id: u64, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_request_accepted","stream_id":{},"method":"GET","path":"/","full_handshake":true}}
            \\
        , .{stream_id});
    } else {
        std.debug.print("interop trace event=h3_request_accepted stream_id={} method=GET path=/\n", .{stream_id});
    }
}

fn traceHttp3ResponseSent(stream_id: u64, response_bytes: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_response_sent","stream_id":{},"status":200,"response_bytes":{},"fin":true,"full_handshake":true}}
            \\
        , .{ stream_id, response_bytes });
    } else {
        std.debug.print("interop trace event=h3_response_sent stream_id={} status=200 response_bytes={} fin=true\n", .{ stream_id, response_bytes });
    }
}

fn traceHttp3Error(stream_id: u64, reason: []const u8, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"h3_stream_rejected","stream_id":{},"reason":"{s}","full_handshake":true}}
            \\
        , .{ stream_id, reason });
    } else {
        std.debug.print("interop trace event=h3_stream_rejected stream_id={} reason={s}\n", .{ stream_id, reason });
    }
}

fn traceHttp3StreamData(stream_id: u64, offset: u64, len: usize, fin: bool, contiguous_len: usize, qlog: bool) void {
    if (!qlog) return;
    std.debug.print(
        \\{{"qlog":"zquic","event":"h3_stream_data","stream_id":{},"offset":{},"len":{},"fin":{},"contiguous_len":{},"full_handshake":true}}
        \\
    , .{ stream_id, offset, len, fin, contiguous_len });
}

fn traceHttp3RequestParseError(stream_id: u64, data: []const u8, complete: bool, qlog: bool) void {
    if (!qlog) return;
    const first = if (data.len > 0) data[0] else 0;
    const second = if (data.len > 1) data[1] else 0;
    std.debug.print(
        \\{{"qlog":"zquic","event":"h3_request_parse_error","stream_id":{},"len":{},"complete":{},"first_byte":{},"second_byte":{},"full_handshake":true}}
        \\
    , .{ stream_id, data.len, complete, first, second });
}

fn traceConnectionStateReused(connection: *const ProbeConnection, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"connection_state_reused","datagrams":{},"state":"{s}","handshake_keys_installed":{},"full_handshake":false}}
            \\
        , .{ connection.datagrams, @tagName(connection.comprehensive_tls.state), connection.handshake_keys_installed });
    } else {
        std.debug.print(
            "interop trace event=connection_state_reused datagrams={} state={s} handshake_keys_installed={}\n",
            .{ connection.datagrams, @tagName(connection.comprehensive_tls.state), connection.handshake_keys_installed },
        );
    }
}

fn traceConnectionEvicted(datagrams: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"connection_evicted","datagrams":{},"reason":"idle","full_handshake":false}}
            \\
        , .{datagrams});
    } else {
        std.debug.print("interop trace event=connection_evicted datagrams={} reason=idle\n", .{datagrams});
    }
}

fn traceConnectionTableFull(active: usize, qlog: bool) void {
    if (qlog) {
        std.debug.print(
            \\{{"qlog":"zquic","event":"connection_table_full","active":{},"limit":{},"full_handshake":false}}
            \\
        , .{ active, max_connections });
    } else {
        std.debug.print("interop trace event=connection_table_full active={} limit={}\n", .{ active, max_connections });
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
