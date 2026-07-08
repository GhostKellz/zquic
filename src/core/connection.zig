//! QUIC Connection with async channel support
//!
//! High-performance connection management without external dependencies

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const Packet = @import("packet.zig");
const QuicFrames = @import("quic_frames.zig");
const PacketSpace = @import("packet_space.zig");
const Stream = @import("stream.zig");
const TransportParameters = @import("transport_parameters.zig");
const PacketCryptoMod = @import("packet_crypto.zig");
const FlowControl = @import("flow_control.zig");
const Recovery = @import("recovery.zig");
const Handshake = @import("../crypto/handshake.zig");
const EnhancedTls = @import("../crypto/enhanced_tls.zig");
const ComprehensiveTls = @import("../crypto/comprehensive_tls.zig");
const SpinMutex = @import("../utils/sync.zig").SpinMutex;

/// Connection states according to RFC 9000
pub const ConnectionState = enum {
    initial,
    handshake,
    established,
    closing,
    draining,
    closed,
};

/// Connection role
pub const Role = enum {
    client,
    server,
};

/// Stream event for async processing
pub const StreamEvent = union(enum) {
    new_stream: struct {
        stream_id: u64,
        stream_type: Stream.StreamType,
    },
    stream_data: struct {
        stream_id: u64,
        data: []const u8,
        fin: bool,
    },
    stream_closed: struct {
        stream_id: u64,
        error_code: u64,
    },
    flow_control_update: struct {
        stream_id: u64,
        max_data: u64,
    },
};

/// Crypto operation for async processing
pub const CryptoOperation = union(enum) {
    pq_encrypt: struct {
        plaintext: []const u8,
        public_key: []const u8,
    },
    pq_decrypt: struct {
        ciphertext: []const u8,
        private_key: []const u8,
    },
    tls_handshake: struct {
        handshake_data: []const u8,
    },
};

/// Connection parameters
pub const ConnectionParams = struct {
    max_idle_timeout: u64 = 30_000, // 30 seconds in milliseconds
    max_udp_payload_size: u64 = 1472, // Safe MTU size
    initial_max_data: u64 = 1048576, // 1MB
    initial_max_stream_data_bidi_local: u64 = 65536, // 64KB
    initial_max_stream_data_bidi_remote: u64 = 65536, // 64KB
    initial_max_stream_data_uni: u64 = 65536, // 64KB
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25, // 25ms
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    accept_early_data: bool = false,
};

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    packets_lost: u64 = 0,
    rtt: u64 = 0, // Round-trip time in microseconds
    rtt_variance: u64 = 0,
    congestion_window: u64 = 14720, // Initial congestion window (10 * MSS)
    bytes_in_flight: u64 = 0,
    ssthresh: u64 = std.math.maxInt(u64),

    // Performance metrics
    async_tasks_spawned: u64 = 0,
    channel_operations: u64 = 0,
    crypto_operations: u64 = 0,
};

/// Owned snapshot of peer transport parameters negotiated during handshake.
///
/// The decoder returns slices into the encoded TLS extension; connection state
/// keeps fixed-size copies so negotiation results remain valid after TLS parser
/// buffers are released.
pub const NegotiatedPeerTransportParameters = struct {
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u8,
    max_ack_delay: u64,
    disable_active_migration: bool,
    active_connection_id_limit: u64,
    original_destination_connection_id: [20]u8 = undefined,
    original_destination_connection_id_len: u8 = 0,
    initial_source_connection_id: [20]u8 = undefined,
    initial_source_connection_id_len: u8 = 0,
    retry_source_connection_id: [20]u8 = undefined,
    retry_source_connection_id_len: u8 = 0,

    pub fn fromDecoded(params: TransportParameters.TransportParameters) Error.ZquicError!NegotiatedPeerTransportParameters {
        var result = NegotiatedPeerTransportParameters{
            .max_idle_timeout = params.max_idle_timeout,
            .max_udp_payload_size = params.max_udp_payload_size,
            .initial_max_data = params.initial_max_data,
            .initial_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = params.initial_max_stream_data_uni,
            .initial_max_streams_bidi = params.initial_max_streams_bidi,
            .initial_max_streams_uni = params.initial_max_streams_uni,
            .ack_delay_exponent = params.ack_delay_exponent,
            .max_ack_delay = params.max_ack_delay,
            .disable_active_migration = params.disable_active_migration,
            .active_connection_id_limit = params.active_connection_id_limit,
        };

        try copyConnectionId(&result.original_destination_connection_id, &result.original_destination_connection_id_len, params.original_destination_connection_id);
        try copyConnectionId(&result.initial_source_connection_id, &result.initial_source_connection_id_len, params.initial_source_connection_id);
        try copyConnectionId(&result.retry_source_connection_id, &result.retry_source_connection_id_len, params.retry_source_connection_id);
        return result;
    }

    pub fn originalDestinationConnectionId(self: *const NegotiatedPeerTransportParameters) []const u8 {
        return self.original_destination_connection_id[0..self.original_destination_connection_id_len];
    }

    pub fn initialSourceConnectionId(self: *const NegotiatedPeerTransportParameters) []const u8 {
        return self.initial_source_connection_id[0..self.initial_source_connection_id_len];
    }

    pub fn retrySourceConnectionId(self: *const NegotiatedPeerTransportParameters) []const u8 {
        return self.retry_source_connection_id[0..self.retry_source_connection_id_len];
    }

    fn copyConnectionId(dest: *[20]u8, dest_len: *u8, source: []const u8) Error.ZquicError!void {
        if (source.len > dest.len) return Error.ZquicError.InvalidConnectionId;
        @memset(dest, 0);
        @memcpy(dest[0..source.len], source);
        dest_len.* = @intCast(source.len);
    }
};

pub const OwnedRawPacket = struct {
    data: []u8,

    pub fn init(allocator: std.mem.Allocator, bytes: []const u8) Error.ZquicError!OwnedRawPacket {
        return .{ .data = allocator.dupe(u8, bytes) catch return Error.ZquicError.OutOfMemory };
    }

    pub fn deinit(self: *OwnedRawPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.data = &.{};
    }
};

const CryptoReassemblyLevel = enum(usize) {
    initial = 0,
    handshake = 1,
    application = 2,
};

const AckTracker = struct {
    smallest: u64 = 0,
    largest: u64 = 0,
    has_packets: bool = false,
    ack_required: bool = false,

    fn record(self: *AckTracker, packet_number: u64, ack_eliciting: bool) void {
        if (!self.has_packets) {
            self.smallest = packet_number;
            self.largest = packet_number;
            self.has_packets = true;
        } else {
            self.smallest = @min(self.smallest, packet_number);
            self.largest = @max(self.largest, packet_number);
        }
        self.ack_required = self.ack_required or ack_eliciting;
    }

    fn clear(self: *AckTracker) void {
        self.ack_required = false;
    }
};

const AckTrackerLevel = enum(usize) {
    initial = 0,
    handshake = 1,
    application = 2,
};

fn ackLevelForLevel(level: PacketCryptoMod.EncryptionLevel) AckTrackerLevel {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .early_data, .application => .application,
    };
}

fn packetSpaceTypeForLevel(level: PacketCryptoMod.EncryptionLevel) PacketSpace.PacketSpaceType {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .early_data, .application => .application,
    };
}

fn nowMicrosU64() u64 {
    return @intCast(@max(Time.nowMicros(), 0));
}

const CryptoReassemblyBuffer = struct {
    data: std.ArrayListUnmanaged(u8) = .empty,
    consumed: usize = 0,

    pub fn deinit(self: *CryptoReassemblyBuffer, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.consumed = 0;
    }

    pub fn clear(self: *CryptoReassemblyBuffer) void {
        self.data.clearRetainingCapacity();
        self.consumed = 0;
    }

    pub fn append(self: *CryptoReassemblyBuffer, allocator: std.mem.Allocator, offset: u64, bytes: []const u8) Error.ZquicError![]const u8 {
        const start: usize = std.math.cast(usize, offset) orelse return Error.ZquicError.InvalidFrame;
        const end = start + bytes.len;
        if (end < start) return Error.ZquicError.InvalidFrame;

        if (start > self.data.items.len) return Error.ZquicError.InvalidFrame;
        if (end > self.data.items.len) {
            self.data.resize(allocator, end) catch return Error.ZquicError.OutOfMemory;
        }
        @memcpy(self.data.items[start..end], bytes);

        if (self.consumed >= self.data.items.len) return &.{};
        const ready = self.data.items[self.consumed..];
        self.consumed = self.data.items.len;
        return ready;
    }
};

/// High-performance QUIC connection
pub const SuperConnection = struct {
    // Core connection data
    role: Role,
    state: ConnectionState,
    local_conn_id: Packet.ConnectionId,
    remote_conn_id: ?Packet.ConnectionId,
    params: ConnectionParams,
    peer_transport_params: ?NegotiatedPeerTransportParameters,
    stats: ConnectionStats,
    next_stream_id: u64,

    // Internal packet queues
    incoming_packets: std.ArrayListUnmanaged(Packet.Packet),
    outgoing_packets: std.ArrayListUnmanaged(Packet.Packet),
    incoming_raw_packets: std.ArrayListUnmanaged(OwnedRawPacket),
    outgoing_raw_packets: std.ArrayListUnmanaged(OwnedRawPacket),
    stream_events: std.ArrayListUnmanaged(StreamEvent),
    crypto_reassembly: [3]CryptoReassemblyBuffer,
    packet_spaces: PacketSpace.PacketSpaceManager,
    ack_trackers: [3]AckTracker,

    // Stream management
    streams: std.AutoHashMapUnmanaged(u64, *Stream.SuperStream),
    allocator: std.mem.Allocator,
    is_running: bool = false,

    // Stream ID counters per RFC 9000:
    // - Client bidi: 0, 4, 8, ... (0x0)
    // - Server bidi: 1, 5, 9, ... (0x1)
    // - Client uni:  2, 6, 10, ... (0x2)
    // - Server uni:  3, 7, 11, ... (0x3)
    next_bidi_stream_id: u64,
    next_uni_stream_id: u64,

    const Self = @This();

    /// Generate a cryptographically random connection ID
    fn generateConnectionId() !Packet.ConnectionId {
        var random_bytes: [8]u8 = undefined;
        zcrypto.rand.fill(&random_bytes);
        return Packet.ConnectionId.init(&random_bytes);
    }

    pub fn init(allocator: std.mem.Allocator, role: Role, params: ConnectionParams) !Self {
        // Generate cryptographically random connection ID
        const local_conn_id = try generateConnectionId();

        // Initialize stream ID counters per RFC 9000 Section 2.1:
        // - Bits 0-1 encode stream type: 0x0 = client bidi, 0x1 = server bidi,
        //                                 0x2 = client uni, 0x3 = server uni
        const initial_bidi_id: u64 = switch (role) {
            .client => 0, // Client-initiated bidirectional: 0, 4, 8, ...
            .server => 1, // Server-initiated bidirectional: 1, 5, 9, ...
        };
        const initial_uni_id: u64 = switch (role) {
            .client => 2, // Client-initiated unidirectional: 2, 6, 10, ...
            .server => 3, // Server-initiated unidirectional: 3, 7, 11, ...
        };

        return Self{
            .role = role,
            .state = .initial,
            .local_conn_id = local_conn_id,
            .remote_conn_id = null,
            .params = params,
            .peer_transport_params = null,
            .stats = ConnectionStats{},
            .next_stream_id = initial_bidi_id, // Legacy field for backward compat
            .next_bidi_stream_id = initial_bidi_id,
            .next_uni_stream_id = initial_uni_id,
            .incoming_packets = .empty,
            .outgoing_packets = .empty,
            .incoming_raw_packets = .empty,
            .outgoing_raw_packets = .empty,
            .stream_events = .empty,
            .crypto_reassembly = .{ .{}, .{}, .{} },
            .packet_spaces = try PacketSpace.PacketSpaceManager.init(allocator),
            .ack_trackers = .{ .{}, .{}, .{} },
            .streams = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.is_running = false;

        // Clean up streams
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit(self.allocator);

        // Clean up queues
        self.incoming_packets.deinit(self.allocator);
        self.outgoing_packets.deinit(self.allocator);
        self.clearOwnedRawPackets();
        self.incoming_raw_packets.deinit(self.allocator);
        self.outgoing_raw_packets.deinit(self.allocator);
        self.stream_events.deinit(self.allocator);
        for (&self.crypto_reassembly) |*buffer| {
            buffer.deinit(self.allocator);
        }
        self.packet_spaces.deinit();
    }

    /// Run connection event loop
    pub fn runConnectionLoop(self: *Self) !void {
        self.is_running = true;

        // Main connection event loop
        while (self.is_running and self.state != .closed) {
            try self.processPendingStreamEvents();

            // Process packets - O(n) batch processing instead of O(n²) orderedRemove
            for (self.incoming_packets.items) |packet| {
                try self.processPacket(packet);
                self.stats.packets_received += 1;
            }
            self.incoming_packets.clearRetainingCapacity();

            // Small sleep to prevent busy loop
            Time.sleep(std.time.ns_per_ms);
        }
    }

    /// Queue a stream event for the core connection event loop.
    pub fn queueStreamEvent(self: *Self, event: StreamEvent) !void {
        try self.stream_events.append(self.allocator, event);
    }

    /// Process queued stream events once without entering the long-running loop.
    /// Protocol integrations use this to stay tied to the real stream table while
    /// retaining control of their own server event loops.
    pub fn processPendingStreamEvents(self: *Self) !void {
        for (self.stream_events.items) |event| {
            try self.handleStreamEvent(event);
            self.stats.channel_operations += 1;
        }
        self.stream_events.clearRetainingCapacity();
    }

    /// Handle stream events
    fn handleStreamEvent(self: *Self, event: StreamEvent) !void {
        switch (event) {
            .new_stream => |new| {
                try self.createStreamAsync(new.stream_id, new.stream_type);
            },
            .stream_data => |data| {
                try self.handleStreamData(data.stream_id, data.data, data.fin);
            },
            .stream_closed => |closed| {
                try self.closeStream(closed.stream_id, closed.error_code);
            },
            .flow_control_update => |update| {
                try self.updateStreamFlowControl(update.stream_id, update.max_data);
            },
        }
    }

    /// Create stream asynchronously
    fn createStreamAsync(self: *Self, stream_id: u64, stream_type: Stream.StreamType) !void {
        const stream = try self.allocator.create(Stream.SuperStream);
        errdefer self.allocator.destroy(stream);

        stream.* = try Stream.SuperStream.init(self.allocator, stream_id, stream_type);
        errdefer stream.deinit();

        try self.streams.put(self.allocator, stream_id, stream);
    }

    /// Handle incoming stream data - routes to receive buffer, not send buffer
    fn handleStreamData(self: *Self, stream_id: u64, data: []const u8, fin: bool) !void {
        if (self.streams.get(stream_id)) |stream| {
            // Write incoming data to the stream's read buffer (not write buffer)
            try stream.handleIncomingDataWithFin(data, fin);
            self.stats.bytes_received += data.len;
        } else {
            // Stream doesn't exist - per RFC 9000, this could be a new stream
            // initiated by the peer. Log for debugging.
            std.log.debug("Received data for unknown stream {}", .{stream_id});
        }
    }

    /// Close stream
    fn closeStream(self: *Self, stream_id: u64, error_code: u64) !void {
        if (self.streams.fetchRemove(stream_id)) |kv| {
            _ = error_code;
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        }
    }

    /// Update stream flow control
    fn updateStreamFlowControl(self: *Self, stream_id: u64, max_data: u64) !void {
        if (self.streams.get(stream_id)) |stream| {
            try stream.updateFlowControl(max_data);
        }
    }

    /// Process packet
    fn processPacket(self: *Self, packet: Packet.Packet) !void {
        try self.processPlaintextPayload(packet.payload);
    }

    /// Encrypt an outgoing packet payload using the live packet crypto facade.
    ///
    /// The returned ciphertext is owned by the caller. The existing packet
    /// queue stores borrowed payload slices, so this API keeps ownership
    /// explicit until the queue grows owned-buffer semantics.
    pub fn protectPacketPayloadForSend(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        level: PacketCryptoMod.EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        plaintext_payload: []const u8,
    ) Error.ZquicError![]u8 {
        const ciphertext = packet_crypto.encryptPacket(level, packet_number, header, plaintext_payload) catch return Error.ZquicError.CryptoError;
        self.stats.bytes_sent += plaintext_payload.len;
        self.stats.packets_sent += 1;
        self.stats.crypto_operations += 1;
        return ciphertext;
    }

    /// Decrypt and process a protected packet payload through the connection's
    /// regular frame dispatch path.
    pub fn processProtectedPacketPayload(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        level: PacketCryptoMod.EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        ciphertext_payload: []const u8,
    ) Error.ZquicError!void {
        const plaintext = packet_crypto.decryptPacket(level, packet_number, header, ciphertext_payload) catch return Error.ZquicError.CryptoError;
        defer self.allocator.free(plaintext);

        try self.processPlaintextPayload(plaintext);
        self.stats.bytes_received += plaintext.len;
        self.stats.packets_received += 1;
        self.stats.crypto_operations += 1;
    }

    /// Decrypt a protected packet payload, route CRYPTO frames into the
    /// handshake manager, and refresh packet protection keys after progress.
    pub fn processProtectedCryptoPacketPayload(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        handshake_manager: *Handshake.HandshakeManager,
        enhanced_tls_context: *EnhancedTls.EnhancedTlsContext,
        connection_id: []const u8,
        level: PacketCryptoMod.EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        ciphertext_payload: []const u8,
    ) Error.ZquicError!usize {
        const plaintext = packet_crypto.decryptPacket(level, packet_number, header, ciphertext_payload) catch return Error.ZquicError.CryptoError;
        defer self.allocator.free(plaintext);

        const installed = try self.processCryptoPayload(
            handshake_manager,
            enhanced_tls_context,
            packet_crypto,
            connection_id,
            level,
            plaintext,
        );
        self.stats.bytes_received += plaintext.len;
        self.stats.packets_received += 1;
        self.stats.crypto_operations += 1;
        return installed;
    }

    pub fn processPlaintextPayload(self: *Self, payload: []const u8) Error.ZquicError!void {
        return self.processPlaintextPayloadAtLevel(.application, payload);
    }

    pub fn processPlaintextPayloadAtLevel(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        payload: []const u8,
    ) Error.ZquicError!void {
        var reader = std.Io.Reader.fixed(payload);
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch |err| return mapFrameError(err);
            defer freeParsedFrame(self.allocator, &frame);
            try self.handleParsedFrameAtLevel(level, frame);
        }
    }

    pub fn processCryptoPayload(
        self: *Self,
        handshake_manager: *Handshake.HandshakeManager,
        enhanced_tls_context: *EnhancedTls.EnhancedTlsContext,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        connection_id: []const u8,
        level: PacketCryptoMod.EncryptionLevel,
        payload: []const u8,
    ) Error.ZquicError!usize {
        var reader = std.Io.Reader.fixed(payload);
        var installed: usize = 0;
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch |err| return mapFrameError(err);
            defer freeParsedFrame(self.allocator, &frame);

            switch (frame) {
                .crypto => |crypto| {
                    const ready = try self.appendCryptoFrame(level, crypto.offset, crypto.data);
                    if (ready.len > 0) {
                        try handshake_manager.processCryptoFrame(ready, crypto.offset);
                        installed = try handshake_manager.syncPacketCrypto(enhanced_tls_context, packet_crypto, connection_id);
                    }
                    self.state = switch (handshake_manager.getCurrentEncryptionLevel()) {
                        .initial => .initial,
                        .handshake => .handshake,
                        .application => .established,
                    };
                },
                else => try self.handleParsedFrameAtLevel(level, frame),
            }
        }
        return installed;
    }

    pub fn processInitialCryptoAndScheduleServerFlight(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        handshake_manager: *Handshake.HandshakeManager,
        payload: []const u8,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
    ) Error.ZquicError!usize {
        if (self.role != .server) return Error.ZquicError.ProtocolViolation;

        var reader = std.Io.Reader.fixed(payload);
        var scheduled: usize = 0;
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch |err| return mapFrameError(err);
            defer freeParsedFrame(self.allocator, &frame);

            switch (frame) {
                .crypto => |crypto| {
                    const ready = try self.appendCryptoFrame(.initial, crypto.offset, crypto.data);
                    if (ready.len > 0) {
                        try handshake_manager.processCryptoFrame(ready, crypto.offset);
                    }

                    const pending = handshake_manager.getPendingCryptoData();
                    if (pending.len > 0) {
                        _ = try self.schedulePendingCryptoAsProtectedRawPacket(
                            packet_crypto,
                            handshake_manager,
                            .initial,
                            .initial,
                            dest_conn_id,
                            src_conn_id,
                        );
                        scheduled += 1;
                    }

                    self.state = switch (handshake_manager.getCurrentEncryptionLevel()) {
                        .initial => .initial,
                        .handshake => .handshake,
                        .application => .established,
                    };
                },
                else => try self.handleParsedFrameAtLevel(.initial, frame),
            }
        }
        return scheduled;
    }

    fn appendCryptoFrame(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        offset: u64,
        data: []const u8,
    ) Error.ZquicError![]const u8 {
        const reassembly_level: CryptoReassemblyLevel = switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .early_data, .application => .application,
        };
        return self.crypto_reassembly[@intFromEnum(reassembly_level)].append(self.allocator, offset, data);
    }

    fn handleParsedFrame(self: *Self, frame: QuicFrames.Frame) Error.ZquicError!void {
        return self.handleParsedFrameAtLevel(.application, frame);
    }

    fn handleParsedFrameAtLevel(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        frame: QuicFrames.Frame,
    ) Error.ZquicError!void {
        if (level == .early_data and !self.params.accept_early_data) {
            switch (frame) {
                .padding, .ping, .ack, .ack_ecn, .crypto => {},
                else => return Error.ZquicError.ProtocolViolation,
            }
        }

        switch (frame) {
            .padding, .ping => {},
            .ack => |ack| try self.processAckFrame(level, ack),
            .ack_ecn => |ack_ecn| try self.processAckFrame(level, ack_ecn.ack_frame),
            .crypto => return Error.ZquicError.ProtocolViolation,
            .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream_frame| {
                try self.handleStreamData(stream_frame.stream_id, stream_frame.data, stream_frame.fin);
            },
            .max_data => |max_data| self.params.initial_max_data = max_data.maximum_data,
            .max_stream_data => |max_stream_data| try self.updateStreamFlowControl(max_stream_data.stream_id, max_stream_data.maximum_stream_data),
            .max_streams_bidi => |max_streams| self.params.initial_max_streams_bidi = max_streams.maximum_streams,
            .max_streams_uni => |max_streams| self.params.initial_max_streams_uni = max_streams.maximum_streams,
            .connection_close, .connection_close_app => {
                self.state = .draining;
                self.is_running = false;
            },
            .handshake_done => {
                if (self.role == .client) self.state = .established;
            },
            .reset_stream => |reset_frame| try self.closeStream(reset_frame.stream_id, reset_frame.application_error_code),
            .stop_sending,
            .new_token,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            .new_connection_id,
            .retire_connection_id,
            .path_challenge,
            .path_response,
            .datagram,
            .datagram_len,
            => {},
        }
    }

    fn processAckFrame(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        ack: QuicFrames.AckFrame,
    ) Error.ZquicError!void {
        if (ack.largest_acknowledged < ack.first_ack_range) return Error.ZquicError.ProtocolViolation;

        var ranges: std.ArrayListUnmanaged(PacketSpace.AckRange) = .empty;
        defer ranges.deinit(self.allocator);

        try ranges.append(self.allocator, .{
            .start = @intCast(ack.largest_acknowledged - ack.first_ack_range),
            .end = @intCast(ack.largest_acknowledged),
        });

        var next_largest = ack.largest_acknowledged - ack.first_ack_range;
        for (ack.ack_ranges) |wire_range| {
            if (next_largest < wire_range.gap + 2) return Error.ZquicError.ProtocolViolation;
            const range_end = next_largest - wire_range.gap - 2;
            if (range_end < wire_range.ack_range_length) return Error.ZquicError.ProtocolViolation;
            const range_start = range_end - wire_range.ack_range_length;
            try ranges.append(self.allocator, .{
                .start = @intCast(range_start),
                .end = @intCast(range_end),
            });
            next_largest = range_start;
        }

        _ = try self.packetSpaceForLevel(level).processAck(ranges.items, ack.ack_delay, nowMicrosU64());
    }

    /// Send packet
    pub fn sendPacketAsync(self: *Self, packet: Packet.Packet) !void {
        try self.outgoing_packets.append(self.allocator, packet);
        self.stats.packets_sent += 1;
    }

    /// Receive packet
    pub fn receivePacketAsync(self: *Self, packet: Packet.Packet) !void {
        try self.incoming_packets.append(self.allocator, packet);
    }

    pub fn queueIncomingRawPacket(self: *Self, bytes: []const u8) Error.ZquicError!void {
        const packet = try OwnedRawPacket.init(self.allocator, bytes);
        errdefer {
            var owned = packet;
            owned.deinit(self.allocator);
        }
        self.incoming_raw_packets.append(self.allocator, packet) catch return Error.ZquicError.OutOfMemory;
    }

    pub fn queueOutgoingRawPacket(self: *Self, bytes: []const u8) Error.ZquicError!void {
        const packet = try OwnedRawPacket.init(self.allocator, bytes);
        errdefer {
            var owned = packet;
            owned.deinit(self.allocator);
        }
        self.outgoing_raw_packets.append(self.allocator, packet) catch return Error.ZquicError.OutOfMemory;
    }

    pub fn drainOutgoingRawPackets(self: *Self, allocator: std.mem.Allocator) Error.ZquicError![]OwnedRawPacket {
        const result = allocator.alloc(OwnedRawPacket, self.outgoing_raw_packets.items.len) catch return Error.ZquicError.OutOfMemory;
        errdefer allocator.free(result);
        @memcpy(result, self.outgoing_raw_packets.items);
        self.outgoing_raw_packets.clearRetainingCapacity();
        return result;
    }

    pub fn sendProtectedRawPacket(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        level: PacketCryptoMod.EncryptionLevel,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
        plaintext_payload: []const u8,
    ) Error.ZquicError!void {
        const packet_number = packet_crypto.packet_number_state.next_packet_number;
        const ack_eliciting = try self.payloadIsAckEliciting(plaintext_payload);
        const raw = packet_crypto.createProtectedRawPacket(level, packet_type, dest_conn_id, src_conn_id, plaintext_payload) catch return Error.ZquicError.CryptoError;
        defer self.allocator.free(raw);
        try self.queueOutgoingRawPacket(raw);
        try self.recordRawPacketSent(level, packet_number, plaintext_payload.len, ack_eliciting);
        self.stats.bytes_sent += plaintext_payload.len;
        self.stats.packets_sent += 1;
        self.stats.crypto_operations += 1;
    }

    pub fn scheduleFramesAsProtectedRawPacket(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        level: PacketCryptoMod.EncryptionLevel,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
        frames: []const QuicFrames.Frame,
    ) Error.ZquicError!void {
        const payload = try self.serializeFrames(frames);
        defer self.allocator.free(payload);
        try self.sendProtectedRawPacket(packet_crypto, level, packet_type, dest_conn_id, src_conn_id, payload);
    }

    pub fn schedulePendingCryptoAsProtectedRawPacket(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        handshake_manager: *Handshake.HandshakeManager,
        level: PacketCryptoMod.EncryptionLevel,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
    ) Error.ZquicError!bool {
        const pending = handshake_manager.getPendingCryptoData();
        if (pending.len == 0) return false;

        const frame = [_]QuicFrames.Frame{
            .{ .crypto = QuicFrames.CryptoFrame.init(0, pending) },
        };
        try self.scheduleFramesAsProtectedRawPacket(packet_crypto, level, packet_type, dest_conn_id, src_conn_id, &frame);
        handshake_manager.clearSentCryptoData();
        return true;
    }

    pub fn scheduleFlowControlFrames(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        flow_controller: *FlowControl.FlowController,
        dest_conn_id: []const u8,
    ) Error.ZquicError!usize {
        const pending = flow_controller.drainPendingFrames(self.allocator) catch return Error.ZquicError.OutOfMemory;
        defer self.allocator.free(pending);
        if (pending.len == 0) return 0;

        const frames = self.allocator.alloc(QuicFrames.Frame, pending.len) catch return Error.ZquicError.OutOfMemory;
        defer self.allocator.free(frames);
        for (pending, 0..) |pending_frame, i| {
            frames[i] = pending_frame.toFrame();
        }

        try self.scheduleFramesAsProtectedRawPacket(packet_crypto, .application, .one_rtt, dest_conn_id, &.{}, frames);
        return pending.len;
    }

    pub fn schedulePendingAckFrames(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
    ) Error.ZquicError!usize {
        var scheduled: usize = 0;
        if (try self.scheduleAckForLevel(packet_crypto, .initial, .initial, dest_conn_id, src_conn_id)) scheduled += 1;
        if (try self.scheduleAckForLevel(packet_crypto, .handshake, .handshake, dest_conn_id, src_conn_id)) scheduled += 1;
        if (try self.scheduleAckForLevel(packet_crypto, .application, .one_rtt, dest_conn_id, &.{})) scheduled += 1;
        return scheduled;
    }

    pub fn scheduleStreamDataFrames(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        dest_conn_id: []const u8,
        max_payload_bytes: usize,
    ) Error.ZquicError!usize {
        if (max_payload_bytes == 0) return Error.ZquicError.PacketTooLarge;

        var scheduled: usize = 0;
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            const stream = entry.value_ptr.*;
            const pending = stream.pendingWriteData();
            if (pending.len == 0) continue;

            const take = @min(pending.len, max_payload_bytes);
            const frame = [_]QuicFrames.Frame{.{ .stream_len = QuicFrames.StreamFrame.init(stream.id, stream.bytesFlushed(), pending[0..take], false, true, true) }};
            try self.scheduleFramesAsProtectedRawPacket(packet_crypto, .application, .one_rtt, dest_conn_id, &.{}, &frame);
            stream.markWriteDataFlushed(take);
            scheduled += 1;
        }

        return scheduled;
    }

    pub fn schedulePtoProbePackets(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        plan: Recovery.PtoProbePlan,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
    ) Error.ZquicError!usize {
        var scheduled: usize = 0;
        const probe = [_]QuicFrames.Frame{
            .{ .ping = QuicFrames.PingFrame.init() },
            .{ .padding = QuicFrames.PaddingFrame.init(3) },
        };

        if (plan.initial) {
            try self.scheduleFramesAsProtectedRawPacket(packet_crypto, .initial, .initial, dest_conn_id, src_conn_id, &probe);
            scheduled += 1;
        }
        if (plan.handshake) {
            try self.scheduleFramesAsProtectedRawPacket(packet_crypto, .handshake, .handshake, dest_conn_id, src_conn_id, &probe);
            scheduled += 1;
        }
        if (plan.application) {
            try self.scheduleFramesAsProtectedRawPacket(packet_crypto, .application, .one_rtt, dest_conn_id, &.{}, &probe);
            scheduled += 1;
        }

        return scheduled;
    }

    fn serializeFrames(self: *Self, frames: []const QuicFrames.Frame) Error.ZquicError![]u8 {
        if (frames.len == 0) return Error.ZquicError.InvalidFrame;

        const max_payload = std.math.cast(usize, self.params.max_udp_payload_size) orelse return Error.ZquicError.PacketTooLarge;
        if (max_payload == 0) return Error.ZquicError.PacketTooLarge;

        const payload = self.allocator.alloc(u8, max_payload) catch return Error.ZquicError.OutOfMemory;
        errdefer self.allocator.free(payload);

        var writer = std.Io.Writer.fixed(payload);
        for (frames) |frame| {
            frame.serialize(&writer) catch return Error.ZquicError.PacketTooLarge;
        }

        return self.allocator.realloc(payload, std.Io.Writer.buffered(&writer).len) catch return Error.ZquicError.OutOfMemory;
    }

    fn scheduleAckForLevel(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        level: PacketCryptoMod.EncryptionLevel,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
    ) Error.ZquicError!bool {
        const tracker = self.ackTrackerForLevel(level);
        if (!tracker.ack_required or !tracker.has_packets) return false;

        var ack = QuicFrames.AckFrame.init(self.allocator, tracker.largest, 0, tracker.largest - tracker.smallest) catch return Error.ZquicError.OutOfMemory;
        defer ack.deinit(self.allocator);

        const frame = [_]QuicFrames.Frame{.{ .ack = ack }};
        try self.scheduleFramesAsProtectedRawPacket(packet_crypto, level, packet_type, dest_conn_id, src_conn_id, &frame);
        tracker.clear();
        return true;
    }

    fn recordRawPacketSent(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        packet_number: u64,
        sent_bytes: usize,
        ack_eliciting: bool,
    ) Error.ZquicError!void {
        if (packet_number > PacketSpace.MAX_PACKET_NUMBER) return Error.ZquicError.InvalidPacket;
        self.packetSpaceForLevel(level).onPacketSent(
            @intCast(packet_number),
            nowMicrosU64(),
            ack_eliciting,
            ack_eliciting,
            sent_bytes,
        ) catch return Error.ZquicError.OutOfMemory;
    }

    fn recordRawPacketReceived(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
        packet_number: u64,
        ack_eliciting: bool,
    ) void {
        self.ackTrackerForLevel(level).record(packet_number, ack_eliciting);
    }

    fn payloadIsAckEliciting(self: *Self, payload: []const u8) Error.ZquicError!bool {
        var reader = std.Io.Reader.fixed(payload);
        var ack_eliciting = false;
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch |err| return mapFrameError(err);
            defer freeParsedFrame(self.allocator, &frame);
            ack_eliciting = ack_eliciting or frame.isAckEliciting();
        }
        return ack_eliciting;
    }

    fn packetSpaceForLevel(self: *Self, level: PacketCryptoMod.EncryptionLevel) *PacketSpace.PacketSpace {
        return self.packet_spaces.getSpace(packetSpaceTypeForLevel(level));
    }

    fn ackTrackerForLevel(self: *Self, level: PacketCryptoMod.EncryptionLevel) *AckTracker {
        return &self.ack_trackers[@intFromEnum(ackLevelForLevel(level))];
    }

    pub fn processNextIncomingRawPacket(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        largest_processed: ?u64,
    ) Error.ZquicError!?PacketCryptoMod.ProcessedPacket {
        if (self.incoming_raw_packets.items.len == 0) return null;
        var owned = self.incoming_raw_packets.orderedRemove(0);
        defer owned.deinit(self.allocator);

        var processed = packet_crypto.processProtectedRawPacket(owned.data, largest_processed) catch return Error.ZquicError.CryptoError;
        errdefer processed.deinit(self.allocator);
        const ack_eliciting = try self.payloadIsAckEliciting(processed.payload);
        self.recordRawPacketReceived(processed.encryption_level, processed.packet_number, ack_eliciting);
        try self.processPlaintextPayloadAtLevel(processed.encryption_level, processed.payload);
        self.stats.bytes_received += processed.payload.len;
        self.stats.packets_received += 1;
        self.stats.crypto_operations += 1;
        return processed;
    }

    pub fn processNextIncomingRawCryptoPacket(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        handshake_manager: *Handshake.HandshakeManager,
        enhanced_tls_context: *EnhancedTls.EnhancedTlsContext,
        connection_id: []const u8,
        largest_processed: ?u64,
    ) Error.ZquicError!?PacketCryptoMod.ProcessedPacket {
        if (self.incoming_raw_packets.items.len == 0) return null;
        var owned = self.incoming_raw_packets.orderedRemove(0);
        defer owned.deinit(self.allocator);

        var processed = packet_crypto.processProtectedRawPacket(owned.data, largest_processed) catch return Error.ZquicError.CryptoError;
        errdefer processed.deinit(self.allocator);
        const ack_eliciting = try self.payloadIsAckEliciting(processed.payload);
        self.recordRawPacketReceived(processed.encryption_level, processed.packet_number, ack_eliciting);
        _ = try self.processCryptoPayload(handshake_manager, enhanced_tls_context, packet_crypto, connection_id, processed.encryption_level, processed.payload);
        self.stats.bytes_received += processed.payload.len;
        self.stats.packets_received += 1;
        self.stats.crypto_operations += 1;
        return processed;
    }

    pub fn processNextIncomingInitialCryptoAndScheduleServerFlight(
        self: *Self,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        handshake_manager: *Handshake.HandshakeManager,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
        largest_processed: ?u64,
    ) Error.ZquicError!usize {
        if (self.incoming_raw_packets.items.len == 0) return 0;
        var owned = self.incoming_raw_packets.orderedRemove(0);
        defer owned.deinit(self.allocator);

        var processed = packet_crypto.processProtectedRawPacket(owned.data, largest_processed) catch return Error.ZquicError.CryptoError;
        defer processed.deinit(self.allocator);
        if (processed.encryption_level != .initial) return Error.ZquicError.ProtocolViolation;

        const ack_eliciting = try self.payloadIsAckEliciting(processed.payload);
        self.recordRawPacketReceived(processed.encryption_level, processed.packet_number, ack_eliciting);
        const scheduled = try self.processInitialCryptoAndScheduleServerFlight(
            packet_crypto,
            handshake_manager,
            processed.payload,
            dest_conn_id,
            src_conn_id,
        );
        self.stats.bytes_received += processed.payload.len;
        self.stats.packets_received += 1;
        self.stats.crypto_operations += 1;
        return scheduled;
    }

    fn clearOwnedRawPackets(self: *Self) void {
        for (self.incoming_raw_packets.items) |*packet| {
            packet.deinit(self.allocator);
        }
        self.incoming_raw_packets.clearRetainingCapacity();

        for (self.outgoing_raw_packets.items) |*packet| {
            packet.deinit(self.allocator);
        }
        self.outgoing_raw_packets.clearRetainingCapacity();
    }

    pub fn collectOpenStreams(self: *Self, allocator: std.mem.Allocator) ![]*Stream.Stream {
        var streams = try allocator.alloc(*Stream.Stream, self.streams.count());
        errdefer allocator.free(streams);

        var count: usize = 0;
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            const stream = entry.value_ptr.*;
            const state = stream.state.load(.acquire);
            if (state != .closed) {
                streams[count] = stream;
                count += 1;
            }
        }

        return allocator.realloc(streams, count);
    }

    /// Get connection statistics
    pub fn getStats(self: *const Self) ConnectionStats {
        return self.stats;
    }

    /// Validate decoded peer transport parameters against the handshake context
    /// and retain an owned snapshot for connection-level policy.
    pub fn applyPeerTransportParameters(
        self: *Self,
        params: TransportParameters.TransportParameters,
        context: TransportParameters.NegotiationContext,
    ) Error.ZquicError!void {
        try TransportParameters.validateForHandshake(params, context);
        self.peer_transport_params = try NegotiatedPeerTransportParameters.fromDecoded(params);
    }

    pub fn applyPeerTransportParametersFromTls(
        self: *Self,
        tls_context: *const ComprehensiveTls.ComprehensiveTlsContext,
        context: TransportParameters.NegotiationContext,
    ) Error.ZquicError!void {
        const params = try tls_context.validatePeerQuicTransportParameters(context);
        try self.applyPeerTransportParameters(params, context);
    }

    pub fn getPeerTransportParameters(self: *const Self) ?NegotiatedPeerTransportParameters {
        return self.peer_transport_params;
    }

    // =========================================================================
    // Graceful Shutdown and Connection Draining (RFC 9000 Section 10.2)
    // =========================================================================

    /// Initiate graceful shutdown of the connection.
    ///
    /// This begins the connection close process:
    /// 1. Stops accepting new streams
    /// 2. Allows existing streams to complete
    /// 3. Sends CONNECTION_CLOSE frame
    /// 4. Enters draining state
    ///
    /// ## Parameters
    /// - `error_code`: Application error code (0 for normal closure)
    /// - `reason`: Optional human-readable reason phrase
    ///
    /// ## Example
    /// ```zig
    /// // Normal graceful shutdown
    /// try conn.initiateShutdown(0, "Server shutting down");
    ///
    /// // Wait for draining to complete
    /// try conn.waitForDrain(30_000); // 30 second timeout
    /// ```
    pub fn initiateShutdown(self: *Self, error_code: u64, reason: ?[]const u8) !void {
        if (self.state == .closed or self.state == .draining) {
            return; // Already shutting down
        }

        std.log.info("Connection {x}: Initiating graceful shutdown (code={}, reason={s})", .{
            self.local_conn_id.bytes()[0],
            error_code,
            reason orelse "none",
        });

        // Transition to closing state
        self.state = .closing;

        // Close all streams gracefully
        var stream_iter = self.streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.close() catch |err| {
                std.log.debug("Connection: Failed to close stream {}: {}", .{ entry.key_ptr.*, err });
            };
        }

        // Queue CONNECTION_CLOSE frame
        try self.queueConnectionClose(error_code, reason);

        // Transition to draining state
        self.state = .draining;
    }

    /// Queue a CONNECTION_CLOSE frame for transmission.
    /// Per RFC 9000 Section 19.19, CONNECTION_CLOSE frame format:
    /// - Error Code (variable-length integer)
    /// - Frame Type (variable-length integer, 0 for transport errors)
    /// - Reason Phrase Length (variable-length integer)
    /// - Reason Phrase (bytes)
    fn queueConnectionClose(self: *Self, error_code: u64, reason: ?[]const u8) !void {
        // Build CONNECTION_CLOSE frame payload
        // Frame type 0x1c = CONNECTION_CLOSE (application)
        // Frame type 0x1d = CONNECTION_CLOSE (transport)
        var frame_buf: [256]u8 = undefined;
        var frame_len: usize = 0;

        // Frame type (0x1c for application-level close)
        frame_buf[frame_len] = 0x1c;
        frame_len += 1;

        // Error code as varint (simplified: 1-byte for small codes, 2-byte otherwise)
        if (error_code < 64) {
            frame_buf[frame_len] = @intCast(error_code);
            frame_len += 1;
        } else if (error_code < 16384) {
            frame_buf[frame_len] = @intCast(0x40 | (error_code >> 8));
            frame_buf[frame_len + 1] = @intCast(error_code & 0xFF);
            frame_len += 2;
        } else {
            // 4-byte varint for larger codes
            frame_buf[frame_len] = @intCast(0x80 | (error_code >> 24));
            frame_buf[frame_len + 1] = @intCast((error_code >> 16) & 0xFF);
            frame_buf[frame_len + 2] = @intCast((error_code >> 8) & 0xFF);
            frame_buf[frame_len + 3] = @intCast(error_code & 0xFF);
            frame_len += 4;
        }

        // Frame type that triggered close (0 for application close)
        frame_buf[frame_len] = 0x00;
        frame_len += 1;

        // Reason phrase length and content
        const reason_bytes = reason orelse "";
        const reason_len = @min(reason_bytes.len, 200); // Cap reason length
        frame_buf[frame_len] = @intCast(reason_len);
        frame_len += 1;
        if (reason_len > 0) {
            @memcpy(frame_buf[frame_len..][0..reason_len], reason_bytes[0..reason_len]);
            frame_len += reason_len;
        }

        // Build packet header - use 1-RTT (short header) if established, else handshake
        const packet_type: Packet.PacketType = if (self.state == .established)
            .one_rtt
        else
            .handshake;

        const header = Packet.PacketHeader{
            .packet_type = packet_type,
            .version = if (packet_type == .one_rtt) null else 1,
            .dest_conn_id = self.remote_conn_id orelse self.local_conn_id,
            .src_conn_id = if (packet_type == .one_rtt) null else self.local_conn_id,
            .packet_number = self.stats.packets_sent,
            .packet_number_len = 2,
            .token = null,
            .header_length = 0, // Not used for outgoing packets
        };

        const close_packet = Packet.Packet.init(header, frame_buf[0..frame_len]);
        try self.outgoing_packets.append(self.allocator, close_packet);
        self.stats.packets_sent += 1;
    }

    /// Wait for connection draining to complete.
    ///
    /// During draining (RFC 9000 Section 10.2.2):
    /// - No new packets are sent except for CONNECTION_CLOSE retransmissions
    /// - Incoming packets are discarded
    /// - Connection resources are held for 3 * PTO to handle delayed packets
    ///
    /// ## Parameters
    /// - `timeout_ms`: Maximum time to wait for draining (0 = use default 3*PTO)
    ///
    /// ## Returns
    /// - `true` if draining completed normally
    /// - `false` if timeout occurred
    pub fn waitForDrain(self: *Self, timeout_ms: u64) !bool {
        if (self.state != .draining) {
            return true; // Not draining, nothing to wait for
        }

        const drain_timeout = if (timeout_ms == 0)
            self.calculateDrainTimeout()
        else
            timeout_ms;

        const start_time = Time.nowSeconds();
        const deadline = start_time + @as(i64, @intCast(drain_timeout / 1000));

        std.log.debug("Connection {x}: Entering drain period ({}ms)", .{
            self.local_conn_id.bytes()[0],
            drain_timeout,
        });

        while (self.state == .draining) {
            const now = Time.nowSeconds();
            if (now >= deadline) {
                std.log.debug("Connection {x}: Drain timeout reached", .{self.local_conn_id.bytes()[0]});
                self.state = .closed;
                return false;
            }

            // Process any remaining packets during drain
            self.incoming_packets.clearRetainingCapacity();

            // Sleep briefly to avoid busy loop
            Time.sleep(10 * std.time.ns_per_ms);
        }

        return true;
    }

    /// Calculate drain timeout based on RTT (3 * PTO per RFC 9000).
    fn calculateDrainTimeout(self: *const Self) u64 {
        // PTO = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay
        // Drain time = 3 * PTO
        const base_rtt = if (self.stats.rtt > 0) self.stats.rtt else 100_000; // Default 100ms in microseconds
        const rtt_var = if (self.stats.rtt_variance > 0) self.stats.rtt_variance else 25_000;
        const pto = base_rtt + @max(4 * rtt_var, 1000) + (self.params.max_ack_delay * 1000);
        return 3 * pto / 1000; // Convert to milliseconds
    }

    /// Perform immediate (non-graceful) connection termination.
    ///
    /// Use this for error conditions where graceful shutdown isn't possible.
    /// Sends a single CONNECTION_CLOSE and immediately releases resources.
    ///
    /// ## Parameters
    /// - `error_code`: Transport or application error code
    /// - `reason`: Optional reason phrase
    pub fn terminateImmediate(self: *Self, error_code: u64, reason: ?[]const u8) void {
        std.log.warn("Connection {x}: Immediate termination (code={}, reason={s})", .{
            self.local_conn_id.bytes()[0],
            error_code,
            reason orelse "none",
        });

        // Best-effort send of CONNECTION_CLOSE
        self.queueConnectionClose(error_code, reason) catch {};

        // Force close all streams
        var stream_iter = self.streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.state.store(.closed, .release);
        }

        self.state = .closed;
        self.is_running = false;
    }

    /// Check if the connection is in a terminal state.
    pub fn isTerminated(self: *const Self) bool {
        return self.state == .closed;
    }

    /// Check if the connection is shutting down (closing or draining).
    pub fn isShuttingDown(self: *const Self) bool {
        return self.state == .closing or self.state == .draining;
    }

    /// Reset connection state for pool reuse.
    /// Clears all streams, queues, stats, and regenerates connection ID.
    pub fn reset(self: *Self) !void {
        // Close and clean up all streams
        var stream_iter = self.streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.clearRetainingCapacity();

        // Clear packet queues
        self.incoming_packets.clearRetainingCapacity();
        self.outgoing_packets.clearRetainingCapacity();
        self.clearOwnedRawPackets();
        for (&self.crypto_reassembly) |*buffer| {
            buffer.clear();
        }
        self.packet_spaces.deinit();
        self.packet_spaces = try PacketSpace.PacketSpaceManager.init(self.allocator);
        self.ack_trackers = .{ .{}, .{}, .{} };
        self.stream_events.clearRetainingCapacity();

        // Reset statistics
        self.stats = ConnectionStats{};
        self.peer_transport_params = null;

        // Generate new connection ID for privacy/security
        self.local_conn_id = try generateConnectionId();
        self.remote_conn_id = null;

        // Reset stream ID counters based on role
        self.next_bidi_stream_id = switch (self.role) {
            .client => 0,
            .server => 1,
        };
        self.next_uni_stream_id = switch (self.role) {
            .client => 2,
            .server => 3,
        };
        self.next_stream_id = self.next_bidi_stream_id;

        // Reset connection state
        self.state = .initial;
        self.is_running = false;
    }
};

/// Legacy connection wrapper for backward compatibility
pub const Connection = struct {
    super_connection: SuperConnection,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, role: Role, params: ConnectionParams) !Self {
        return Self{
            .super_connection = try SuperConnection.init(allocator, role, params),
        };
    }

    pub fn deinit(self: *Self) void {
        self.super_connection.deinit();
    }

    /// Create a new stream with proper RFC 9000 stream ID allocation
    pub fn createStream(self: *Self, stream_type: Stream.StreamType) !*Stream.Stream {
        // Allocate stream ID based on type (RFC 9000 Section 2.1):
        // - Bidirectional streams: increment by 4 from role-specific base
        // - Unidirectional streams: increment by 4 from role-specific base
        const stream_id = switch (stream_type) {
            .client_bidirectional, .server_bidirectional => blk: {
                const id = self.super_connection.next_bidi_stream_id;
                self.super_connection.next_bidi_stream_id += 4;
                self.super_connection.next_stream_id = id; // Keep legacy field updated
                break :blk id;
            },
            .client_unidirectional, .server_unidirectional => blk: {
                const id = self.super_connection.next_uni_stream_id;
                self.super_connection.next_uni_stream_id += 4;
                break :blk id;
            },
        };

        self.super_connection.createStreamAsync(stream_id, stream_type) catch return error.InternalError;

        if (self.super_connection.streams.get(stream_id)) |stream| {
            return stream;
        }
        return error.InternalError;
    }

    /// Get an existing stream by ID
    pub fn getStream(self: *Self, stream_id: u64) ?*Stream.Stream {
        return self.super_connection.streams.get(stream_id);
    }

    /// Collect currently open streams for protocol integrations such as HTTP/3.
    /// Caller owns the returned slice; streams remain owned by the connection.
    pub fn collectOpenStreams(self: *Self, allocator: std.mem.Allocator) ![]*Stream.Stream {
        return self.super_connection.collectOpenStreams(allocator);
    }

    /// Queue a stream event for the underlying core connection event loop.
    pub fn queueStreamEvent(self: *Self, event: StreamEvent) !void {
        return self.super_connection.queueStreamEvent(event);
    }

    /// Process queued stream events once.
    pub fn processPendingStreamEvents(self: *Self) !void {
        return self.super_connection.processPendingStreamEvents();
    }

    /// Get connection state
    pub fn getState(self: *const Self) ConnectionState {
        return self.super_connection.state;
    }

    /// Get connection statistics
    pub fn getStats(self: *const Self) ConnectionStats {
        return self.super_connection.getStats();
    }

    /// Apply validated peer transport parameters to the underlying connection.
    pub fn applyPeerTransportParameters(
        self: *Self,
        params: TransportParameters.TransportParameters,
        context: TransportParameters.NegotiationContext,
    ) Error.ZquicError!void {
        return self.super_connection.applyPeerTransportParameters(params, context);
    }

    /// Return the owned negotiated peer transport-parameter snapshot, if any.
    pub fn getPeerTransportParameters(self: *const Self) ?NegotiatedPeerTransportParameters {
        return self.super_connection.getPeerTransportParameters();
    }

    /// Check if connection is established
    pub fn isEstablished(self: *const Self) bool {
        return self.super_connection.state == .established;
    }

    /// Initiate graceful shutdown (see SuperConnection.initiateShutdown).
    pub fn initiateShutdown(self: *Self, error_code: u64, reason: ?[]const u8) !void {
        return self.super_connection.initiateShutdown(error_code, reason);
    }

    /// Wait for connection draining (see SuperConnection.waitForDrain).
    pub fn waitForDrain(self: *Self, timeout_ms: u64) !bool {
        return self.super_connection.waitForDrain(timeout_ms);
    }

    /// Immediate termination (see SuperConnection.terminateImmediate).
    pub fn terminateImmediate(self: *Self, error_code: u64, reason: ?[]const u8) void {
        self.super_connection.terminateImmediate(error_code, reason);
    }

    /// Check if connection is terminated.
    pub fn isTerminated(self: *const Self) bool {
        return self.super_connection.isTerminated();
    }

    /// Check if connection is shutting down.
    pub fn isShuttingDown(self: *const Self) bool {
        return self.super_connection.isShuttingDown();
    }
};

/// Connection pool for managing multiple connections
pub const SuperConnectionPool = struct {
    available: std.ArrayListUnmanaged(*SuperConnection),
    active: std.ArrayListUnmanaged(*SuperConnection),
    allocator: std.mem.Allocator,
    stats: PoolStats,
    mutex: SpinMutex,

    pub const PoolStats = struct {
        connections_created: u64 = 0,
        connections_active: u64 = 0,
        connections_pooled: u64 = 0,
        peak_active: u64 = 0,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .available = .empty,
            .active = .empty,
            .allocator = allocator,
            .stats = PoolStats{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Clean up all connections
        for (self.available.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.available.deinit(self.allocator);

        for (self.active.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.active.deinit(self.allocator);
    }

    /// Acquire connection from pool
    pub fn acquire(self: *Self, role: Role, params: ConnectionParams) !*SuperConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to get from available pool first
        if (self.available.items.len > 0) {
            const conn = self.available.orderedRemove(self.available.items.len - 1);
            try self.active.append(self.allocator, conn);
            self.stats.connections_active += 1;
            return conn;
        }

        // Create new connection
        const conn = try self.allocator.create(SuperConnection);
        conn.* = try SuperConnection.init(self.allocator, role, params);

        try self.active.append(self.allocator, conn);
        self.stats.connections_created += 1;
        self.stats.connections_active += 1;
        self.stats.peak_active = @max(self.stats.peak_active, self.stats.connections_active);

        return conn;
    }

    /// Release connection back to pool
    pub fn release(self: *Self, conn: *SuperConnection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Fully reset connection state for reuse
        // This clears streams, queues, stats, and regenerates connection ID
        try conn.reset();

        // Remove from active
        for (self.active.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.active.swapRemove(i);
                break;
            }
        }

        // Return to available pool
        try self.available.append(self.allocator, conn);
        self.stats.connections_active -= 1;
        self.stats.connections_pooled += 1;
    }

    /// Get pool statistics
    pub fn getStats(self: *const Self) PoolStats {
        return self.stats;
    }
};

fn mapFrameError(err: anyerror) Error.ZquicError {
    return switch (err) {
        error.OutOfMemory => Error.ZquicError.OutOfMemory,
        error.EndOfStream => Error.ZquicError.InvalidFrame,
        else => Error.ZquicError.InvalidFrame,
    };
}

fn freeParsedFrame(allocator: std.mem.Allocator, frame: *QuicFrames.Frame) void {
    switch (frame.*) {
        .crypto => |crypto| allocator.free(crypto.data),
        .new_token => |new_token| allocator.free(new_token.token),
        .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| allocator.free(stream.data),
        .new_connection_id => |new_connection_id| allocator.free(new_connection_id.connection_id),
        .connection_close => |connection_close| allocator.free(connection_close.reason_phrase),
        .connection_close_app => |connection_close| allocator.free(connection_close.reason_phrase),
        .datagram, .datagram_len => |datagram| allocator.free(datagram.data),
        else => {},
    }
}

test "connection creation" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const params = ConnectionParams{};
    var conn = try SuperConnection.init(allocator, .client, params);
    defer conn.deinit();

    try std.testing.expect(conn.state == .initial);
    try std.testing.expect(conn.role == .client);
}

test "connection pool operations" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var pool = SuperConnectionPool.init(allocator);
    defer pool.deinit();

    const params = ConnectionParams{};
    const conn = try pool.acquire(.client, params);

    try pool.release(conn);

    const stats = pool.getStats();
    try std.testing.expect(stats.connections_created == 1);
}
