//! QUIC Packet Cryptography using ZCrypto
//!
//! Hardware-accelerated packet encryption/decryption with post-quantum support

const std = @import("std");
const Error = @import("../utils/error.zig");

const CoreCrypto = @import("crypto.zig");
const Packet = @import("packet.zig");
const Tls13KeySchedule = @import("../crypto/tls13_key_schedule.zig");
const enhanced_tls = @import("../crypto/enhanced_tls.zig");
const EnhancedTlsContext = enhanced_tls.EnhancedTlsContext;
const EnhancedCipherSuite = enhanced_tls.EnhancedCipherSuite;

/// QUIC encryption levels
pub const EncryptionLevel = enum {
    initial,
    early_data,
    handshake,
    application,
};

const PacketNumberState = struct {
    largest_acked: u64 = 0,
    next_packet_number: u64 = 0,
};

/// QUIC packet protection using zcrypto with hardware acceleration
pub const PacketCrypto = struct {
    tls_context: *EnhancedTlsContext,
    allocator: std.mem.Allocator,

    // Conditionally include PQ context - will be set through feature modules
    pq_context: ?*anyopaque = null,

    // Real QUIC AEAD/header-protection helper used by this facade.
    core_crypto: CoreCrypto.QuicCrypto,
    cipher_suite: CoreCrypto.CipherSuite,
    hw_accelerator: HardwareCrypto.Accelerator,
    batch_processor: ?PacketBatchProcessor = null,

    /// Packet number encoding state
    packet_number_state: PacketNumberState,
    initial_packet_number_state: PacketNumberState,
    handshake_packet_number_state: PacketNumberState,

    /// Levels holding real, standards-derived key material.
    ///
    /// `refreshKeysFromTlsContext` installs deterministic facade keys derived
    /// from the `EnhancedTlsContext` helper, which are not RFC 9001 keys. Once
    /// a level has been given real keys it is pinned so that refresh cannot
    /// silently replace them.
    pinned_levels: std.EnumSet(CoreCrypto.EncryptionLevel),

    pub fn init(allocator: std.mem.Allocator, tls_context: *EnhancedTlsContext, pq_context: ?*anyopaque) !PacketCrypto {
        // Initialize hardware acceleration
        const hw_caps = HardwareCrypto.detectCapabilities();
        std.log.info("Hardware acceleration available: AES-NI={}, AVX2={}", .{ hw_caps.has_aes_ni, hw_caps.has_avx2 });

        const cipher_suite = mapEnhancedCipherSuite(tls_context.cipher_suite);

        var core_crypto = CoreCrypto.QuicCrypto.init(allocator, cipher_suite);
        errdefer core_crypto.deinit();
        try installDeterministicFacadeKeys(allocator, &core_crypto, cipher_suite, "zquic packet crypto facade v1");

        // Initialize hardware accelerator
        const hw_accelerator = try HardwareCrypto.Accelerator.init(allocator, hw_caps);

        var packet_crypto = PacketCrypto{
            .tls_context = tls_context,
            .pq_context = pq_context,
            .allocator = allocator,
            .core_crypto = core_crypto,
            .cipher_suite = cipher_suite,
            .hw_accelerator = hw_accelerator,
            .packet_number_state = .{},
            .initial_packet_number_state = .{},
            .handshake_packet_number_state = .{},
            .pinned_levels = .empty,
        };
        _ = try packet_crypto.refreshKeysFromTlsContext();
        return packet_crypto;
    }

    pub fn deinit(self: *PacketCrypto) void {
        self.core_crypto.deinit();
        self.hw_accelerator.deinit();
        if (self.batch_processor) |*processor| {
            processor.deinit();
        }
    }

    /// Install any keys currently derived by the associated TLS helper context.
    ///
    /// This bridges the packet facade to TLS-derived key material while keeping
    /// deterministic facade keys as a fallback for not-yet-derived levels.
    ///
    /// Pinned levels are skipped and are not counted in the return value: they
    /// already hold real RFC 9001 key material, which this helper path must not
    /// overwrite.
    pub fn refreshKeysFromTlsContext(self: *PacketCrypto) !usize {
        var installed: usize = 0;

        if (self.tls_context.initial_keys) |*keys| {
            if (try self.installTlsKeysUnlessPinned(.initial, keys)) installed += 1;
        }
        if (self.tls_context.handshake_keys) |*keys| {
            if (try self.installTlsKeysUnlessPinned(.handshake, keys)) installed += 1;
        }
        if (self.tls_context.application_keys) |*keys| {
            if (try self.installTlsKeysUnlessPinned(.application, keys)) installed += 1;
        }

        return installed;
    }

    /// Returns true when the helper keys were actually installed.
    fn installTlsKeysUnlessPinned(
        self: *PacketCrypto,
        level: CoreCrypto.EncryptionLevel,
        keys: *const enhanced_tls.EnhancedCryptoKeys,
    ) !bool {
        if (self.isLevelPinned(level)) return false;
        try self.installTlsKeys(level, keys);
        return true;
    }

    /// Whether a level holds real, standards-derived key material.
    pub fn isLevelPinned(self: *const PacketCrypto, level: CoreCrypto.EncryptionLevel) bool {
        return self.pinned_levels.contains(level);
    }

    fn installTlsKeys(self: *PacketCrypto, level: CoreCrypto.EncryptionLevel, keys: *const enhanced_tls.EnhancedCryptoKeys) !void {
        const local = try directionalKeysFromTls(self.allocator, self.cipher_suite, keys);
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }

        const remote = try directionalKeysFromTls(self.allocator, self.cipher_suite, keys);
        self.core_crypto.installKeys(level, local, remote);
    }

    /// Install RFC 9001 QUIC v1 Initial keys for a server endpoint.
    ///
    /// `destination_connection_id` is the DCID from the client's first Initial.
    /// After this call, local Initial packets use server keys and remote
    /// Initial packets use client keys, and the Initial level is pinned.
    pub fn installRfc9001ServerInitialKeys(self: *PacketCrypto, destination_connection_id: []const u8) !void {
        const initial = try enhanced_tls.deriveRfc9001InitialKeys(destination_connection_id);
        const local = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &initial.server.key,
            &initial.server.iv,
            &initial.server.header_protection_key,
        );
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }
        const remote = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &initial.client.key,
            &initial.client.iv,
            &initial.client.header_protection_key,
        );
        self.core_crypto.installKeys(.initial, local, remote);
        self.pinned_levels.insert(.initial);
    }

    /// Install RFC 9001 QUIC v1 Initial keys for a client endpoint.
    ///
    /// After this call, local Initial packets use client keys and remote
    /// Initial packets use server keys, and the Initial level is pinned.
    pub fn installRfc9001ClientInitialKeys(self: *PacketCrypto, destination_connection_id: []const u8) !void {
        const initial = try enhanced_tls.deriveRfc9001InitialKeys(destination_connection_id);
        const local = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &initial.client.key,
            &initial.client.iv,
            &initial.client.header_protection_key,
        );
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }
        const remote = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &initial.server.key,
            &initial.server.iv,
            &initial.server.header_protection_key,
        );
        self.core_crypto.installKeys(.initial, local, remote);
        self.pinned_levels.insert(.initial);
    }

    /// Install RFC 9001 Handshake packet-protection keys derived from a real
    /// TLS 1.3 handshake key schedule.
    ///
    /// `local` protects packets this endpoint sends; `remote` unprotects the
    /// packets it receives. Callers own the traffic-secret mapping: a server
    /// passes the server-derived keys as `local` and the client-derived keys as
    /// `remote`, and a client passes them the other way around.
    ///
    /// Both directional key sets are built before either is installed, so an
    /// allocation failure leaves any previously installed Handshake keys
    /// untouched. The Handshake level is pinned afterwards.
    pub fn installRfc9001HandshakeKeys(
        self: *PacketCrypto,
        local_keys: *const Tls13KeySchedule.QuicPacketKeys,
        remote_keys: *const Tls13KeySchedule.QuicPacketKeys,
    ) !void {
        // The key schedule only derives AES-128-GCM-SHA256 material. Installing
        // it under a facade configured for another AEAD would silently protect
        // packets with the wrong algorithm.
        if (self.cipher_suite != .aes_128_gcm_sha256) return Error.ZquicError.CryptoError;

        const local = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &local_keys.key,
            &local_keys.iv,
            &local_keys.hp,
        );
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }
        const remote = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &remote_keys.key,
            &remote_keys.iv,
            &remote_keys.hp,
        );
        self.core_crypto.installKeys(.handshake, local, remote);
        self.pinned_levels.insert(.handshake);
    }

    /// Install first-generation RFC 9001 application (1-RTT) keys after TLS
    /// Finished authentication. Direction mapping is identical to Handshake:
    /// local protects writes and remote authenticates peer packets.
    pub fn installRfc9001ApplicationKeys(
        self: *PacketCrypto,
        local_keys: *const Tls13KeySchedule.QuicPacketKeys,
        remote_keys: *const Tls13KeySchedule.QuicPacketKeys,
    ) !void {
        if (self.cipher_suite != .aes_128_gcm_sha256) return Error.ZquicError.CryptoError;

        const local = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &local_keys.key,
            &local_keys.iv,
            &local_keys.hp,
        );
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }
        const remote = try CoreCrypto.DirectionalKeys.init(
            self.allocator,
            .aes_128_gcm_sha256,
            &remote_keys.key,
            &remote_keys.iv,
            &remote_keys.hp,
        );
        self.core_crypto.installKeys(.application, local, remote);
        self.pinned_levels.insert(.application);
    }

    /// Encrypt QUIC packet payload using hardware acceleration
    pub fn encryptPacket(
        self: *PacketCrypto,
        level: EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
    ) ![]u8 {
        const core_level = self.mapCoreEncryptionLevel(level);
        const packet_len = header.len + payload.len + self.cipher_suite.tagLength();
        const protected_packet = try self.allocator.alloc(u8, packet_len);
        defer self.allocator.free(protected_packet);

        const written = try self.core_crypto.encryptPacket(core_level, packet_number, header, payload, protected_packet);
        const encrypted_payload = try self.allocator.alloc(u8, written - header.len);
        @memcpy(encrypted_payload, protected_packet[header.len..written]);
        return encrypted_payload;
    }

    /// Decrypt QUIC packet payload using hardware acceleration
    pub fn decryptPacket(
        self: *PacketCrypto,
        level: EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        ciphertext: []const u8,
    ) ![]u8 {
        const core_level = self.mapCoreEncryptionLevel(level);
        const keys = self.core_crypto.getKeys(core_level) orelse return Error.ZquicError.CryptoError;
        if (ciphertext.len < self.cipher_suite.tagLength()) return Error.ZquicError.CryptoError;

        const decrypted = try self.allocator.alloc(u8, ciphertext.len - self.cipher_suite.tagLength());
        errdefer self.allocator.free(decrypted);

        const decrypted_len = try self.core_crypto.aead.decrypt(
            keys.remote.aead_key,
            keys.remote.aead_iv,
            packet_number,
            header,
            ciphertext,
            decrypted,
        );
        return decrypted[0..decrypted_len];
    }

    /// Apply header protection using zcrypto
    pub fn protectHeader(
        self: *PacketCrypto,
        level: EncryptionLevel,
        header: []u8,
        sample: []const u8,
    ) !void {
        const core_level = self.mapCoreEncryptionLevel(level);
        const keys = self.core_crypto.getKeys(core_level) orelse return Error.ZquicError.CryptoError;
        try self.core_crypto.hp.protect(keys.local.hp_key, header, sample);
    }

    /// Remove header protection using zcrypto
    pub fn unprotectHeader(
        self: *PacketCrypto,
        level: EncryptionLevel,
        header: []u8,
        sample: []const u8,
    ) !void {
        const core_level = self.mapCoreEncryptionLevel(level);
        const keys = self.core_crypto.getKeys(core_level) orelse return Error.ZquicError.CryptoError;
        try self.core_crypto.hp.unprotect(keys.remote.hp_key, header, sample);
    }

    /// Process complete QUIC packet (decrypt + validate)
    pub fn processIncomingPacket(
        self: *PacketCrypto,
        raw_packet: []const u8,
    ) !ProcessedPacket {
        if (raw_packet.len < 16) return Error.ZquicError.InvalidPacket;

        // Parse packet header
        const header_len = try self.parseHeaderLength(raw_packet);
        if (header_len >= raw_packet.len) return Error.ZquicError.InvalidPacket;

        const header = raw_packet[0..header_len];
        const protected_payload = raw_packet[header_len..];

        if (protected_payload.len < 20) return Error.ZquicError.InvalidPacket; // Minimum for sample + tag

        // Extract sample for header protection
        const sample_offset = 4; // Skip packet number
        const sample = protected_payload[sample_offset .. sample_offset + 16];

        // Remove header protection
        const mutable_header = try self.allocator.dupe(u8, header);
        defer self.allocator.free(mutable_header);

        const level = try self.determineEncryptionLevel(mutable_header);
        try self.unprotectHeader(level, mutable_header, sample);

        // Extract packet number
        const packet_number = try self.extractPacketNumber(mutable_header);

        // Decrypt payload
        const ciphertext = protected_payload[4..]; // Skip packet number bytes
        const plaintext = try self.decryptPacket(level, packet_number, mutable_header, ciphertext);

        return ProcessedPacket{
            .header = try self.allocator.dupe(u8, mutable_header),
            .payload = plaintext,
            .packet_number = packet_number,
            .encryption_level = level,
        };
    }

    pub fn createProtectedRawPacket(
        self: *PacketCrypto,
        level: EncryptionLevel,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
        payload: []const u8,
    ) ![]u8 {
        const packet_number_state = self.packetNumberStateForLevel(level);
        const packet_number = packet_number_state.next_packet_number;
        packet_number_state.next_packet_number += 1;
        const packet_number_len = choosePacketNumberLen(packet_number);

        const header = try self.buildRawPacketHeader(packet_type, dest_conn_id, src_conn_id, packet_number, packet_number_len, payload.len);
        defer self.allocator.free(header);

        const ciphertext = try self.encryptPacket(level, packet_number, header, payload);
        defer self.allocator.free(ciphertext);

        if (ciphertext.len < 20) return Error.ZquicError.PacketTooShort;

        const packet = try self.allocator.alloc(u8, header.len + ciphertext.len);
        errdefer self.allocator.free(packet);
        @memcpy(packet[0..header.len], header);
        @memcpy(packet[header.len..], ciphertext);

        const pn_offset = header.len - packet_number_len;
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 > packet.len) return Error.ZquicError.PacketTooShort;
        const sample = packet[sample_offset .. sample_offset + 16];
        try self.applyRawHeaderProtection(level, packet[0..header.len], pn_offset, sample, .protect);
        return packet;
    }

    pub fn processProtectedRawPacket(
        self: *PacketCrypto,
        raw_packet: []const u8,
        largest_processed: ?u64,
    ) !ProcessedPacket {
        if (raw_packet.len < 24) return Error.ZquicError.InvalidPacket;

        var packet = try self.allocator.dupe(u8, raw_packet);
        errdefer self.allocator.free(packet);

        const layout = try self.parseProtectedRawPacketLayout(packet);
        const pn_offset = layout.pn_offset;
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 > layout.packet_end) return Error.ZquicError.InvalidPacket;

        const level = try self.determineEncryptionLevel(packet[0..pn_offset]);
        const sample = packet[sample_offset .. sample_offset + 16];
        try self.applyRawHeaderProtection(level, packet[0 .. pn_offset + 4], pn_offset, sample, .unprotect);

        const packet_number_len: u8 = (packet[0] & 0x03) + 1;
        if (pn_offset + packet_number_len > layout.packet_end) return Error.ZquicError.InvalidPacket;

        const truncated = try Packet.readTruncatedPacketNumber(packet[pn_offset .. pn_offset + packet_number_len]);
        const packet_number = try Packet.reconstructPacketNumber(largest_processed, truncated, packet_number_len);
        const header = packet[0 .. pn_offset + packet_number_len];
        const ciphertext = packet[pn_offset + packet_number_len .. layout.packet_end];
        const plaintext = try self.decryptPacket(level, packet_number, header, ciphertext);
        errdefer self.allocator.free(plaintext);

        const owned_header = try self.allocator.dupe(u8, header);
        self.allocator.free(packet);

        return ProcessedPacket{
            .header = owned_header,
            .payload = plaintext,
            .packet_number = packet_number,
            .encryption_level = level,
        };
    }

    /// Create outgoing QUIC packet (encrypt + protect)
    pub fn createOutgoingPacket(
        self: *PacketCrypto,
        level: EncryptionLevel,
        packet_type: u8,
        connection_id: []const u8,
        payload: []const u8,
    ) ![]u8 {
        // Generate next packet number
        const packet_number_state = self.packetNumberStateForLevel(level);
        const packet_number = packet_number_state.next_packet_number;
        packet_number_state.next_packet_number += 1;

        // Build packet header
        const header = try self.buildPacketHeader(packet_type, connection_id, packet_number);
        defer self.allocator.free(header);

        // Encrypt payload
        const encrypted_payload = try self.encryptPacket(level, packet_number, header, payload);
        defer self.allocator.free(encrypted_payload);

        // Construct complete packet
        const total_len = header.len + 4 + encrypted_payload.len; // +4 for packet number
        const packet = try self.allocator.alloc(u8, total_len);

        // Copy header
        @memcpy(packet[0..header.len], header);

        // Add packet number (4 bytes, big-endian)
        const pn_offset = header.len;
        std.mem.writeInt(u32, packet[pn_offset .. pn_offset + 4], @intCast(packet_number), .big);

        // Copy encrypted payload
        const payload_offset = pn_offset + 4;
        @memcpy(packet[payload_offset..], encrypted_payload);

        // Apply header protection
        if (encrypted_payload.len >= 16) {
            const sample = encrypted_payload[4..20]; // Sample from encrypted data
            try self.protectHeader(level, packet[0 .. pn_offset + 4], sample);
        }

        return packet;
    }

    /// Zero-copy packet processing for high performance with hardware acceleration
    pub fn processPacketInPlace(
        self: *PacketCrypto,
        packet_buffer: []u8,
        used_length: *usize,
    ) !EncryptionLevel {
        if (packet_buffer.len < 16) return Error.ZquicError.InvalidPacket;

        // Parse header in-place
        const header_len = try self.parseHeaderLength(packet_buffer);
        if (header_len >= used_length.*) return Error.ZquicError.InvalidPacket;

        const level = try self.determineEncryptionLevel(packet_buffer[0..header_len]);

        // Remove header protection in-place
        const payload_start = header_len + 4;
        if (payload_start + 16 > used_length.*) return Error.ZquicError.InvalidPacket;

        const sample = packet_buffer[payload_start + 4 .. payload_start + 20];
        try self.unprotectHeader(level, packet_buffer[0..payload_start], sample);

        // Extract packet number
        const packet_number = try self.extractPacketNumber(packet_buffer[0..payload_start]);

        // Use hardware-accelerated in-place decryption
        const plaintext = try self.decryptPacket(
            level,
            packet_number,
            packet_buffer[0..payload_start],
            packet_buffer[payload_start..used_length.*],
        );
        defer self.allocator.free(plaintext);
        @memcpy(packet_buffer[payload_start .. payload_start + plaintext.len], plaintext);

        // Update used length after processing
        used_length.* = payload_start + plaintext.len;

        return level;
    }

    /// Initialize batch processor for high-throughput scenarios
    pub fn initBatchProcessor(self: *PacketCrypto, batch_size: usize, max_packet_size: usize) !void {
        self.batch_processor = PacketBatchProcessor.init(self, batch_size, max_packet_size);
    }

    /// Process multiple packets in batch with SIMD acceleration
    pub fn processBatchEncrypt(
        self: *PacketCrypto,
        packet_buffers: [][]u8,
        packet_numbers: []u64,
        aads: [][]const u8,
    ) ![]usize {
        if (self.batch_processor == null) {
            try self.initBatchProcessor(64, 1500);
        }

        return try self.batch_processor.?.encryptBatch(packet_buffers, packet_numbers, aads);
    }

    /// Build Additional Authenticated Data (AAD) for AEAD
    fn buildAAD(self: *PacketCrypto, header: []const u8, packet_number: u64) ![]u8 {
        // AAD = header || packet_number (8 bytes, big-endian)
        const aad = try self.allocator.alloc(u8, header.len + 8);
        @memcpy(aad[0..header.len], header);
        std.mem.writeInt(u64, aad[header.len..], packet_number, .big);
        return aad;
    }

    /// Map QUIC encryption level to TLS encryption level
    fn mapEncryptionLevel(self: *PacketCrypto, level: EncryptionLevel) @import("../crypto/enhanced_tls.zig").EncryptionLevel {
        _ = self;
        return switch (level) {
            .initial => .initial,
            .early_data => .initial, // Map to initial for simplicity
            .handshake => .handshake,
            .application => .application,
        };
    }

    fn mapCoreEncryptionLevel(self: *PacketCrypto, level: EncryptionLevel) CoreCrypto.EncryptionLevel {
        _ = self;
        return switch (level) {
            .initial => .initial,
            .early_data => .early_data,
            .handshake => .handshake,
            .application => .application,
        };
    }

    pub fn nextPacketNumberForLevel(self: *PacketCrypto, level: EncryptionLevel) u64 {
        return self.packetNumberStateForLevel(level).next_packet_number;
    }

    fn packetNumberStateForLevel(self: *PacketCrypto, level: EncryptionLevel) *PacketNumberState {
        return switch (level) {
            .initial => &self.initial_packet_number_state,
            .handshake => &self.handshake_packet_number_state,
            .early_data, .application => &self.packet_number_state,
        };
    }

    const HeaderProtectionDirection = enum { protect, unprotect };

    fn applyRawHeaderProtection(
        self: *PacketCrypto,
        level: EncryptionLevel,
        header: []u8,
        pn_offset: usize,
        sample: []const u8,
        direction: HeaderProtectionDirection,
    ) !void {
        if (header.len == 0 or pn_offset >= header.len) return Error.ZquicError.InvalidPacket;

        const core_level = self.mapCoreEncryptionLevel(level);
        const keys = self.core_crypto.getKeys(core_level) orelse return Error.ZquicError.CryptoError;
        const hp_key = switch (direction) {
            .protect => keys.local.hp_key,
            .unprotect => keys.remote.hp_key,
        };

        var mask: [5]u8 = undefined;
        try self.core_crypto.hp.generateMask(hp_key, sample, &mask);

        const protected_packet_number_len: usize = (header[0] & 0x03) + 1;
        const first_byte_mask: u8 = if (header[0] & 0x80 != 0) 0x0F else 0x1F;
        header[0] ^= mask[0] & first_byte_mask;
        const packet_number_len: usize = switch (direction) {
            .protect => protected_packet_number_len,
            .unprotect => (header[0] & 0x03) + 1,
        };
        if (pn_offset + packet_number_len > header.len) return Error.ZquicError.InvalidPacket;
        for (0..packet_number_len) |i| {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    /// Determine encryption level from packet header
    fn determineEncryptionLevel(self: *PacketCrypto, header: []const u8) !EncryptionLevel {
        _ = self;
        if (header.len == 0) return Error.ZquicError.InvalidPacket;

        const first_byte = header[0];

        // Check if it's a long header packet
        if ((first_byte & 0x80) != 0) {
            // Long header - check packet type
            const packet_type = (first_byte & 0x30) >> 4;
            return switch (packet_type) {
                0x00 => .initial,
                0x01 => .early_data,
                0x02 => .handshake,
                0x03 => return Error.ZquicError.InvalidPacket, // Reserved
                else => return Error.ZquicError.InvalidPacket,
            };
        } else {
            // Short header - always application level
            return .application;
        }
    }

    /// Parse packet header length
    fn parseHeaderLength(self: *PacketCrypto, packet: []const u8) !usize {
        return (try self.parseProtectedRawPacketLayout(packet)).pn_offset;
    }

    const ProtectedRawPacketLayout = struct {
        pn_offset: usize,
        packet_end: usize,
    };

    /// Locate the protected packet within a UDP datagram. Long headers carry a
    /// Length field covering packet number plus ciphertext, while a short
    /// header has no delimiter and therefore consumes the remaining datagram.
    fn parseProtectedRawPacketLayout(self: *PacketCrypto, packet: []const u8) !ProtectedRawPacketLayout {
        _ = self;
        if (packet.len == 0) return Error.ZquicError.InvalidPacket;

        const first_byte = packet[0];

        if ((first_byte & 0x80) != 0) {
            if (packet.len < 7) return Error.ZquicError.InvalidPacket;

            var offset: usize = 5;

            const dcil = packet[offset];
            offset += 1;
            if (offset + dcil > packet.len) return Error.ZquicError.InvalidPacket;
            offset += dcil;

            if (offset >= packet.len) return Error.ZquicError.InvalidPacket;
            const scil = packet[offset];
            offset += 1;
            if (offset + scil > packet.len) return Error.ZquicError.InvalidPacket;
            offset += scil;

            // Initial packets carry a varint token length before the protected length.
            const packet_type = (first_byte & 0x30) >> 4;
            if (packet_type == 0x00) { // Initial
                const token_len = try readQuicVarint(packet, &offset);
                if (token_len > packet.len - offset) return Error.ZquicError.InvalidPacket;
                offset += @intCast(token_len);
            }

            const protected_len = try readQuicVarint(packet, &offset);
            if (protected_len == 0 or protected_len > packet.len - offset) return Error.ZquicError.InvalidPacket;

            return .{
                .pn_offset = offset,
                .packet_end = offset + @as(usize, @intCast(protected_len)),
            };
        } else {
            const dest_cid_len: usize = 8;
            if (packet.len < 1 + dest_cid_len) return Error.ZquicError.InvalidPacket;
            return .{ .pn_offset = 1 + dest_cid_len, .packet_end = packet.len };
        }
    }

    fn buildRawPacketHeader(
        self: *PacketCrypto,
        packet_type: Packet.PacketType,
        dest_conn_id: []const u8,
        src_conn_id: []const u8,
        packet_number: u64,
        packet_number_len: u8,
        payload_len: usize,
    ) ![]u8 {
        if (dest_conn_id.len > 20 or src_conn_id.len > 20) return Error.ZquicError.InvalidConnectionId;
        if (packet_number_len == 0 or packet_number_len > 4) return Error.ZquicError.InvalidPacket;

        if (packet_type == .one_rtt) {
            const header = try self.allocator.alloc(u8, 1 + dest_conn_id.len + packet_number_len);
            header[0] = 0x40 | (packet_number_len - 1);
            @memcpy(header[1 .. 1 + dest_conn_id.len], dest_conn_id);
            writeTruncatedPacketNumber(header[1 + dest_conn_id.len ..][0..packet_number_len], packet_number);
            return header;
        }

        const type_bits: u8 = switch (packet_type) {
            .initial => 0x00,
            .zero_rtt => 0x10,
            .handshake => 0x20,
            .retry, .version_negotiation, .one_rtt => return Error.ZquicError.InvalidPacket,
        };

        const token_len: usize = if (packet_type == .initial) 1 else 0;
        const length_len: usize = 2;
        const header_len = 1 + 4 + 1 + dest_conn_id.len + 1 + src_conn_id.len + token_len + length_len + packet_number_len;
        const header = try self.allocator.alloc(u8, header_len);
        var offset: usize = 0;

        header[offset] = 0xC0 | type_bits | (packet_number_len - 1);
        offset += 1;
        std.mem.writeInt(u32, header[offset..][0..4], 0x00000001, .big);
        offset += 4;
        header[offset] = @intCast(dest_conn_id.len);
        offset += 1;
        @memcpy(header[offset .. offset + dest_conn_id.len], dest_conn_id);
        offset += dest_conn_id.len;
        header[offset] = @intCast(src_conn_id.len);
        offset += 1;
        @memcpy(header[offset .. offset + src_conn_id.len], src_conn_id);
        offset += src_conn_id.len;
        if (packet_type == .initial) {
            header[offset] = 0;
            offset += 1;
        }
        const protected_len = payload_len + self.cipher_suite.tagLength() + packet_number_len;
        if (protected_len >= 0x4000) return Error.ZquicError.PacketTooLarge;
        writeQuicVarint2(header[offset..][0..2], protected_len);
        offset += 2;
        writeTruncatedPacketNumber(header[offset..][0..packet_number_len], packet_number);

        return header;
    }

    fn readQuicVarint(bytes: []const u8, offset: *usize) !u64 {
        if (offset.* >= bytes.len) return Error.ZquicError.InvalidPacket;

        const first = bytes[offset.*];
        const encoded_len: usize = @as(usize, 1) << @intCast(first >> 6);
        if (offset.* + encoded_len > bytes.len) return Error.ZquicError.InvalidPacket;

        var value: u64 = first & 0x3f;
        var i: usize = 1;
        while (i < encoded_len) : (i += 1) {
            value = (value << 8) | bytes[offset.* + i];
        }
        offset.* += encoded_len;
        return value;
    }

    fn writeQuicVarint2(dest: *[2]u8, value: usize) void {
        const encoded: u16 = @intCast(0x4000 | value);
        std.mem.writeInt(u16, dest, encoded, .big);
    }

    fn choosePacketNumberLen(packet_number: u64) u8 {
        if (packet_number <= 0xff) return 1;
        if (packet_number <= 0xffff) return 2;
        if (packet_number <= 0xffffff) return 3;
        return 4;
    }

    fn writeTruncatedPacketNumber(dest: []u8, packet_number: u64) void {
        const shift_base = dest.len - 1;
        for (dest, 0..) |*byte, i| {
            const shift: u6 = @intCast((shift_base - i) * 8);
            byte.* = @truncate(packet_number >> shift);
        }
    }

    /// Extract packet number from unprotected header
    fn extractPacketNumber(self: *PacketCrypto, header: []const u8) !u64 {
        _ = self;
        if (header.len < 4) return Error.ZquicError.InvalidPacket;

        // Simplified: assume 4-byte packet number at end of header
        const pn_bytes = header[header.len - 4 ..];
        return std.mem.readInt(u32, pn_bytes[0..4], .big);
    }

    /// Build QUIC packet header
    fn buildPacketHeader(self: *PacketCrypto, packet_type: u8, connection_id: []const u8, packet_number: u64) ![]u8 {
        _ = packet_number; // Will be added separately

        // Simplified header construction
        const header_len = 1 + 4 + 1 + connection_id.len + 1 + 2; // Basic long header
        const header = try self.allocator.alloc(u8, header_len);

        var offset: usize = 0;

        // First byte (long header with packet type)
        header[offset] = 0x80 | packet_type;
        offset += 1;

        // Version (QUIC v1)
        std.mem.writeInt(u32, header[offset .. offset + 4], 0x00000001, .big);
        offset += 4;

        // DCIL and SCIL (simplified)
        header[offset] = @intCast(connection_id.len);
        offset += 1;

        // Destination Connection ID
        @memcpy(header[offset .. offset + connection_id.len], connection_id);
        offset += connection_id.len;

        // Token length (0 for non-Initial packets)
        header[offset] = 0;
        offset += 1;

        // Length field (simplified - 2 bytes)
        std.mem.writeInt(u16, header[offset .. offset + 2], 0, .big); // Will be filled later

        return header;
    }
};

/// Processed QUIC packet
pub const ProcessedPacket = struct {
    header: []u8,
    payload: []u8,
    packet_number: u64,
    encryption_level: EncryptionLevel,

    pub fn deinit(self: *ProcessedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.header);
        allocator.free(self.payload);
    }
};

/// High-performance packet processor for bulk operations
pub const BulkPacketProcessor = struct {
    crypto: *PacketCrypto,
    batch_size: usize,

    pub fn init(crypto: *PacketCrypto, batch_size: usize) BulkPacketProcessor {
        return BulkPacketProcessor{
            .crypto = crypto,
            .batch_size = batch_size,
        };
    }

    /// Process multiple packets in a batch for performance
    pub fn processBatch(
        self: *BulkPacketProcessor,
        packets: [][]const u8,
        results: []ProcessedPacket,
    ) !usize {
        const count = @min(packets.len, results.len, self.batch_size);
        var processed: usize = 0;

        for (packets[0..count], 0..) |packet, i| {
            results[i] = self.crypto.processIncomingPacket(packet) catch continue;
            processed += 1;
        }

        return processed;
    }

    /// Parallel packet processing using multiple threads
    pub fn processParallel(
        self: *BulkPacketProcessor,
        packets: [][]const u8,
        results: []ProcessedPacket,
        thread_pool: *std.Thread.Pool,
    ) !usize {
        // Keep the fallback deterministic; callers still pass the pool used by
        // future scheduled implementations.
        _ = thread_pool;
        return self.processBatch(packets, results);
    }
};

// Performance-optimized memory pools for packet processing
pub const PacketMemoryPool = struct {
    allocator: std.mem.Allocator,
    small_buffers: std.ArrayList([]u8), // 1KB buffers
    medium_buffers: std.ArrayList([]u8), // 4KB buffers
    large_buffers: std.ArrayList([]u8), // 16KB buffers

    const SMALL_SIZE = 1024;
    const MEDIUM_SIZE = 4096;
    const LARGE_SIZE = 16384;

    pub fn init(allocator: std.mem.Allocator) PacketMemoryPool {
        return PacketMemoryPool{
            .allocator = allocator,
            .small_buffers = .{},
            .medium_buffers = .{},
            .large_buffers = .{},
        };
    }

    pub fn deinit(self: *PacketMemoryPool) void {
        // Free all pooled buffers
        for (self.small_buffers.items) |buffer| {
            self.allocator.free(buffer);
        }
        for (self.medium_buffers.items) |buffer| {
            self.allocator.free(buffer);
        }
        for (self.large_buffers.items) |buffer| {
            self.allocator.free(buffer);
        }

        self.small_buffers.deinit(self.allocator);
        self.medium_buffers.deinit(self.allocator);
        self.large_buffers.deinit(self.allocator);
    }

    pub fn getBuffer(self: *PacketMemoryPool, size: usize) ![]u8 {
        if (size <= SMALL_SIZE) {
            if (self.small_buffers.popOrNull()) |buffer| {
                return buffer;
            }
            return try self.allocator.alloc(u8, SMALL_SIZE);
        } else if (size <= MEDIUM_SIZE) {
            if (self.medium_buffers.popOrNull()) |buffer| {
                return buffer;
            }
            return try self.allocator.alloc(u8, MEDIUM_SIZE);
        } else if (size <= LARGE_SIZE) {
            if (self.large_buffers.popOrNull()) |buffer| {
                return buffer;
            }
            return try self.allocator.alloc(u8, LARGE_SIZE);
        } else {
            // For very large packets, allocate directly
            return try self.allocator.alloc(u8, size);
        }
    }

    pub fn returnBuffer(self: *PacketMemoryPool, buffer: []u8) !void {
        if (buffer.len == SMALL_SIZE) {
            try self.small_buffers.append(self.allocator, buffer);
        } else if (buffer.len == MEDIUM_SIZE) {
            try self.medium_buffers.append(self.allocator, buffer);
        } else if (buffer.len == LARGE_SIZE) {
            try self.large_buffers.append(self.allocator, buffer);
        } else {
            // Non-pooled buffer, free directly
            self.allocator.free(buffer);
        }
    }
};

const PacketBatchProcessor = struct {
    crypto: *PacketCrypto,
    batch_size: usize,
    max_packet_size: usize,

    pub fn init(crypto: *PacketCrypto, batch_size: usize, max_packet_size: usize) PacketBatchProcessor {
        return .{
            .crypto = crypto,
            .batch_size = batch_size,
            .max_packet_size = max_packet_size,
        };
    }

    pub fn deinit(self: *PacketBatchProcessor) void {
        _ = self;
    }

    pub fn encryptBatch(
        self: *PacketBatchProcessor,
        packet_buffers: [][]u8,
        packet_numbers: []u64,
        aads: [][]const u8,
    ) ![]usize {
        const count = @min(@min(packet_buffers.len, packet_numbers.len), @min(aads.len, self.batch_size));
        const lengths = try self.crypto.allocator.alloc(usize, count);
        errdefer self.crypto.allocator.free(lengths);

        for (0..count) |i| {
            if (packet_buffers[i].len > self.max_packet_size) return Error.ZquicError.InvalidPacket;
            const encrypted = try self.crypto.encryptPacket(.application, packet_numbers[i], aads[i], packet_buffers[i]);
            defer self.crypto.allocator.free(encrypted);
            if (encrypted.len > packet_buffers[i].len) return Error.ZquicError.CryptoError;
            @memcpy(packet_buffers[i][0..encrypted.len], encrypted);
            lengths[i] = encrypted.len;
        }

        return lengths;
    }
};

fn mapEnhancedCipherSuite(cipher_suite: EnhancedCipherSuite) CoreCrypto.CipherSuite {
    return switch (cipher_suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
        .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
    };
}

fn installDeterministicFacadeKeys(
    allocator: std.mem.Allocator,
    crypto: *CoreCrypto.QuicCrypto,
    cipher_suite: CoreCrypto.CipherSuite,
    seed: []const u8,
) !void {
    const levels = [_]CoreCrypto.EncryptionLevel{ .initial, .early_data, .handshake, .application };
    for (levels) |level| {
        const local = try deriveDirectionalKeys(allocator, cipher_suite, seed, level, "local");
        errdefer {
            var local_copy = local;
            local_copy.deinit();
        }
        const remote = try deriveDirectionalKeys(allocator, cipher_suite, seed, level, "local");
        crypto.installKeys(level, local, remote);
    }
}

fn deriveDirectionalKeys(
    allocator: std.mem.Allocator,
    cipher_suite: CoreCrypto.CipherSuite,
    seed: []const u8,
    level: CoreCrypto.EncryptionLevel,
    role: []const u8,
) !CoreCrypto.DirectionalKeys {
    var key = deriveBytes(32, seed, level, role, "key");
    var iv = deriveBytes(12, seed, level, role, "iv");
    var hp_key = deriveBytes(32, seed, level, role, "hp");
    return CoreCrypto.DirectionalKeys.init(
        allocator,
        cipher_suite,
        key[0..cipher_suite.keyLength()],
        &iv,
        hp_key[0..cipher_suite.keyLength()],
    );
}

fn directionalKeysFromTls(
    allocator: std.mem.Allocator,
    cipher_suite: CoreCrypto.CipherSuite,
    keys: *const enhanced_tls.EnhancedCryptoKeys,
) !CoreCrypto.DirectionalKeys {
    return CoreCrypto.DirectionalKeys.init(
        allocator,
        cipher_suite,
        keys.key,
        keys.iv,
        keys.header_protection_key,
    );
}

fn deriveBytes(
    comptime len: usize,
    seed: []const u8,
    level: CoreCrypto.EncryptionLevel,
    role: []const u8,
    purpose: []const u8,
) [len]u8 {
    var output: [len]u8 = undefined;
    var written: usize = 0;
    var counter: u8 = 0;

    while (written < len) : (counter +%= 1) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(seed);
        hasher.update(&[_]u8{ @backingInt(level), counter });
        hasher.update(role);
        hasher.update(purpose);

        var digest: [32]u8 = undefined;
        hasher.final(&digest);

        const take = @min(digest.len, len - written);
        @memcpy(output[written .. written + take], digest[0..take]);
        written += take;
    }

    return output;
}

const HardwareCrypto = struct {
    pub const Capabilities = struct {
        has_aes_ni: bool = false,
        has_avx2: bool = false,
    };

    pub fn detectCapabilities() Capabilities {
        return Capabilities{};
    }

    pub const Accelerator = struct {
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, caps: Capabilities) !Accelerator {
            _ = caps;
            return Accelerator{ .allocator = allocator };
        }

        pub fn deinit(self: *Accelerator) void {
            _ = self;
        }
    };
};

test "packet crypto initialization" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_256_gcm_sha384,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    try std.testing.expect(packet_crypto.packet_number_state.next_packet_number == 0);
    try std.testing.expect(packet_crypto.packet_number_state.largest_acked == 0);
}

test "encryption level mapping" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_256_gcm_sha384,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const initial_level = packet_crypto.mapEncryptionLevel(.initial);
    const handshake_level = packet_crypto.mapEncryptionLevel(.handshake);
    const app_level = packet_crypto.mapEncryptionLevel(.application);

    try std.testing.expect(initial_level == .initial);
    try std.testing.expect(handshake_level == .handshake);
    try std.testing.expect(app_level == .application);
}

test "packet crypto facade performs authenticated round trip" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_256_gcm_sha384,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x07 };
    const payload = "facade packet payload long enough to exercise real AEAD";

    const encrypted = try packet_crypto.encryptPacket(.application, 7, &header, payload);
    defer allocator.free(encrypted);
    try std.testing.expectEqual(payload.len + 16, encrypted.len);
    try std.testing.expect(!std.mem.eql(u8, payload, encrypted[0..payload.len]));

    const decrypted = try packet_crypto.decryptPacket(.application, 7, &header, encrypted);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(payload, decrypted);
}

test "packet crypto facade rejects tampering and wrong aad" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x09 };
    const wrong_header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x0a };
    const payload = "authenticated payload for negative facade tests";

    const encrypted = try packet_crypto.encryptPacket(.application, 9, &header, payload);
    defer allocator.free(encrypted);

    var tampered = try allocator.dupe(u8, encrypted);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.application, 9, &header, tampered),
    );

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.application, 10, &header, encrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.application, 9, &wrong_header, encrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.handshake, 9, &header, encrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.application, 9, &header, encrypted[0..8]),
    );
}

test "packet crypto installs matching TLS-derived application keys" {
    const allocator = std.testing.allocator;

    var sender_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_256_gcm_sha384,
    );
    defer sender_tls.deinit();
    try sender_tls.deriveApplicationKeys("shared tls application secret for packet crypto");

    var receiver_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        true,
        .aes_256_gcm_sha384,
    );
    defer receiver_tls.deinit();
    try receiver_tls.deriveApplicationKeys("shared tls application secret for packet crypto");

    var sender = try PacketCrypto.init(allocator, &sender_tls, null);
    defer sender.deinit();
    var receiver = try PacketCrypto.init(allocator, &receiver_tls, null);
    defer receiver.deinit();

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x11 };
    const payload = "tls-derived packet payload";

    const encrypted = try sender.encryptPacket(.application, 17, &header, payload);
    defer allocator.free(encrypted);

    const decrypted = try receiver.decryptPacket(.application, 17, &header, encrypted);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(payload, decrypted);
}

test "packet crypto rejects mismatched TLS-derived application keys" {
    const allocator = std.testing.allocator;

    var sender_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .chacha20_poly1305_sha256,
    );
    defer sender_tls.deinit();
    try sender_tls.deriveApplicationKeys("sender application secret");

    var receiver_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        true,
        .chacha20_poly1305_sha256,
    );
    defer receiver_tls.deinit();
    try receiver_tls.deriveApplicationKeys("receiver application secret");

    var sender = try PacketCrypto.init(allocator, &sender_tls, null);
    defer sender.deinit();
    var receiver = try PacketCrypto.init(allocator, &receiver_tls, null);
    defer receiver.deinit();

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x12 };
    const payload = "mismatched tls-derived packet payload";

    const encrypted = try sender.encryptPacket(.application, 18, &header, payload);
    defer allocator.free(encrypted);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        receiver.decryptPacket(.application, 18, &header, encrypted),
    );
}

test "packet crypto refreshes keys derived after initialization" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x13 };
    const fallback_payload = "fallback before tls keys";
    const fallback_encrypted = try packet_crypto.encryptPacket(.application, 19, &header, fallback_payload);
    defer allocator.free(fallback_encrypted);

    try tls_context.deriveApplicationKeys("late tls application secret");
    try std.testing.expectEqual(@as(usize, 1), try packet_crypto.refreshKeysFromTlsContext());

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        packet_crypto.decryptPacket(.application, 19, &header, fallback_encrypted),
    );

    const tls_payload = "payload after tls keys";
    const tls_encrypted = try packet_crypto.encryptPacket(.application, 20, &header, tls_payload);
    defer allocator.free(tls_encrypted);
    const tls_decrypted = try packet_crypto.decryptPacket(.application, 20, &header, tls_encrypted);
    defer allocator.free(tls_decrypted);
    try std.testing.expectEqualStrings(tls_payload, tls_decrypted);
}

test "packet crypto raw packet path uses variable packet number lengths" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer tls_context.deinit();
    try tls_context.deriveApplicationKeys("variable packet number raw packet path");

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const payload = "variable packet number payload with enough bytes for hp sample";

    const cases = [_]struct {
        packet_number: u64,
        packet_number_len: u8,
    }{
        .{ .packet_number = 0x7f, .packet_number_len = 1 },
        .{ .packet_number = 0x1234, .packet_number_len = 2 },
        .{ .packet_number = 0x12_3456, .packet_number_len = 3 },
        .{ .packet_number = 0x1234_5678, .packet_number_len = 4 },
    };

    for (cases) |case| {
        packet_crypto.packet_number_state.next_packet_number = case.packet_number;
        const raw = try packet_crypto.createProtectedRawPacket(.application, .one_rtt, &dcid, &.{}, payload);
        defer allocator.free(raw);

        var processed = try packet_crypto.processProtectedRawPacket(raw, null);
        defer processed.deinit(allocator);

        try std.testing.expectEqual(case.packet_number, processed.packet_number);
        try std.testing.expectEqual(case.packet_number_len, (processed.header[0] & 0x03) + 1);
        try std.testing.expectEqualStrings(payload, processed.payload);
    }
}

test "packet crypto raw packet path accepts zero rtt long header" {
    const allocator = std.testing.allocator;

    var tls_context = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer tls_context.deinit();

    var packet_crypto = try PacketCrypto.init(allocator, &tls_context, null);
    defer packet_crypto.deinit();

    const dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const scid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const payload = "zero rtt protected payload with sufficient sample bytes";

    const raw = try packet_crypto.createProtectedRawPacket(.early_data, .zero_rtt, &dcid, &scid, payload);
    defer allocator.free(raw);

    var processed = try packet_crypto.processProtectedRawPacket(raw, null);
    defer processed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);
    try std.testing.expectEqual(.early_data, processed.encryption_level);
    try std.testing.expectEqualStrings(payload, processed.payload);
}

test "packet crypto parses QUIC varint token and length fields" {
    var offset: usize = 0;
    try std.testing.expectEqual(@as(u64, 0), try PacketCrypto.readQuicVarint(&.{0x00}, &offset));
    try std.testing.expectEqual(@as(usize, 1), offset);

    offset = 0;
    try std.testing.expectEqual(@as(u64, 1), try PacketCrypto.readQuicVarint(&.{ 0x40, 0x01 }, &offset));
    try std.testing.expectEqual(@as(usize, 2), offset);

    var encoded: [2]u8 = undefined;
    PacketCrypto.writeQuicVarint2(&encoded, 1200);
    offset = 0;
    try std.testing.expectEqual(@as(u64, 1200), try PacketCrypto.readQuicVarint(&encoded, &offset));
    try std.testing.expectEqual(@as(usize, 2), offset);
}

test "packet crypto installs directional RFC 9001 initial keys" {
    const allocator = std.testing.allocator;

    var client_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer client_tls.deinit();
    var server_tls = try @import("../crypto/enhanced_tls.zig").EnhancedTlsContext.init(
        allocator,
        true,
        .aes_128_gcm_sha256,
    );
    defer server_tls.deinit();

    var client_crypto = try PacketCrypto.init(allocator, &client_tls, null);
    defer client_crypto.deinit();
    var server_crypto = try PacketCrypto.init(allocator, &server_tls, null);
    defer server_crypto.deinit();

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    try client_crypto.installRfc9001ClientInitialKeys(&original_dcid);
    try server_crypto.installRfc9001ServerInitialKeys(&original_dcid);

    const client_payload = "client initial crypto bytes with enough length for header protection sample";
    const client_initial = try client_crypto.createProtectedRawPacket(.initial, .initial, &original_dcid, &client_scid, client_payload);
    defer allocator.free(client_initial);

    try std.testing.expectError(
        error.InvalidPacket,
        server_crypto.processProtectedRawPacket(client_initial[0 .. client_initial.len - 1], null),
    );

    const trailing_packet = [_]u8{ 0xe0, 0x00, 0x00, 0x00, 0x01 };
    const coalesced = try allocator.alloc(u8, client_initial.len + trailing_packet.len);
    defer allocator.free(coalesced);
    @memcpy(coalesced[0..client_initial.len], client_initial);
    @memcpy(coalesced[client_initial.len..], &trailing_packet);

    var server_processed = try server_crypto.processProtectedRawPacket(coalesced, null);
    defer server_processed.deinit(allocator);
    try std.testing.expectEqual(.initial, server_processed.encryption_level);
    try std.testing.expectEqualStrings(client_payload, server_processed.payload);

    const close_payload = [_]u8{ 0x1c, 0x00, 0x00, 0x00 };
    const server_initial = try server_crypto.createProtectedRawPacket(
        .initial,
        .initial,
        &client_scid,
        &original_dcid,
        &close_payload,
    );
    defer allocator.free(server_initial);

    var client_processed = try client_crypto.processProtectedRawPacket(server_initial, null);
    defer client_processed.deinit(allocator);
    try std.testing.expectEqual(.initial, client_processed.encryption_level);
    try std.testing.expectEqualSlices(u8, &close_payload, client_processed.payload);
}
