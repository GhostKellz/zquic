//! TLS 1.3 integration for QUIC
//!
//! Provides TLS 1.3 handshake and key derivation for QUIC

const std = @import("std");
const Error = @import("../utils/error.zig");

/// TLS 1.3 cipher suites supported by QUIC
pub const CipherSuite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,
};

/// TLS handshake state
pub const HandshakeState = enum {
    initial,
    wait_client_hello,
    wait_server_hello,
    wait_finished,
    completed,
    failed,
};

/// QUIC Transport Parameters
pub const TransportParameters = struct {
    max_idle_timeout: u64 = 30_000,
    max_udp_payload_size: u64 = 1472,
    initial_max_data: u64 = 1048576,
    initial_max_stream_data_bidi_local: u64 = 65536,
    initial_max_stream_data_bidi_remote: u64 = 65536,
    initial_max_stream_data_uni: u64 = 65536,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 100,
    ack_delay_exponent: u8 = 3,
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
};

/// Cryptographic keys for a single encryption level
pub const CryptoKeys = struct {
    secret: [32]u8,
    key: [32]u8,
    iv: [12]u8,
    header_protection_key: [32]u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .secret = std.mem.zeroes([32]u8),
            .key = std.mem.zeroes([32]u8),
            .iv = std.mem.zeroes([12]u8),
            .header_protection_key = std.mem.zeroes([32]u8),
        };
    }

    pub fn zeroize(self: *Self) void {
        std.crypto.secureZero(u8, &self.secret);
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, &self.header_protection_key);
    }

    /// Derive keys from a secret (simplified implementation)
    pub fn deriveFromSecret(secret: []const u8) Error.ZquicError!Self {
        if (secret.len == 0) {
            return Error.ZquicError.CryptoError;
        }

        var keys = Self.init();

        // Expand short secrets via SHA-256 so we always have 32 bytes to work with
        var seed: [32]u8 = undefined;
        if (secret.len < seed.len) {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(secret);
            hasher.final(&seed);
        } else {
            @memcpy(seed[0..seed.len], secret[0..seed.len]);
        }
        @memcpy(&keys.secret, &seed);

        // Derive other keys using a simple hash (not cryptographically secure)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&keys.secret);
        hasher.update("key");
        hasher.final(&keys.key);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&keys.secret);
        hasher.update("iv");
        var iv_hash: [32]u8 = undefined;
        hasher.final(&iv_hash);
        @memcpy(&keys.iv, iv_hash[0..12]);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&keys.secret);
        hasher.update("hp");
        hasher.final(&keys.header_protection_key);

        return keys;
    }
};

/// TLS context for QUIC
pub const TlsContext = struct {
    state: HandshakeState,
    cipher_suite: CipherSuite,
    transport_params: TransportParameters,
    is_server: bool,

    // Encryption keys for different packet types
    initial_keys: ?CryptoKeys,
    handshake_keys: ?CryptoKeys,
    application_keys: ?CryptoKeys,

    // Handshake data buffers
    client_hello: ?[]const u8,
    server_hello: ?[]const u8,
    certificate: ?[]const u8,
    finished: ?[]const u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .state = .initial,
            .cipher_suite = .aes_128_gcm_sha256,
            .transport_params = TransportParameters{},
            .is_server = is_server,
            .initial_keys = null,
            .handshake_keys = null,
            .application_keys = null,
            .client_hello = null,
            .server_hello = null,
            .certificate = null,
            .finished = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.initial_keys) |*keys| keys.zeroize();
        if (self.handshake_keys) |*keys| keys.zeroize();
        if (self.application_keys) |*keys| keys.zeroize();
        if (self.client_hello) |data| self.allocator.free(data);
        if (self.server_hello) |data| self.allocator.free(data);
        if (self.certificate) |data| self.allocator.free(data);
        if (self.finished) |data| self.allocator.free(data);
    }

    /// Initialize keys for the Initial packet encryption level
    pub fn initializeInitialKeys(self: *Self, connection_id: []const u8) Error.ZquicError!void {
        // QUIC uses a well-known initial secret
        const initial_secret = "initial_secret_for_quic_v1"; // Simplified

        // In real implementation, would derive from connection ID using HKDF
        _ = connection_id;

        self.initial_keys = try CryptoKeys.deriveFromSecret(initial_secret);
    }

    /// Process incoming CRYPTO frame data
    pub fn processCryptoData(self: *Self, data: []const u8, offset: u64) Error.ZquicError!void {
        _ = offset; // Would handle fragmented CRYPTO frames in real implementation

        switch (self.state) {
            .initial => {
                if (self.is_server) {
                    // Expect ClientHello
                    self.client_hello = try self.allocator.dupe(u8, data);
                    self.state = .wait_server_hello;
                } else {
                    return Error.ZquicError.ProtocolViolation;
                }
            },
            .wait_server_hello => {
                if (!self.is_server) {
                    // Expect ServerHello, Certificate, etc.
                    self.server_hello = try self.allocator.dupe(u8, data);
                    self.state = .wait_finished;
                } else {
                    return Error.ZquicError.ProtocolViolation;
                }
            },
            .wait_finished => {
                // Process Finished message
                self.finished = try self.allocator.dupe(u8, data);
                self.state = .completed;

                // Derive application keys
                try self.deriveApplicationKeys();
            },
            else => {
                return Error.ZquicError.ProtocolViolation;
            },
        }
    }

    /// Generate CRYPTO frame data for handshake
    pub fn generateCryptoData(self: *Self, allocator: std.mem.Allocator) Error.ZquicError![]u8 {
        switch (self.state) {
            .initial => {
                if (!self.is_server) {
                    // Generate ClientHello
                    const client_hello = "ClientHello with QUIC transport parameters";
                    if (self.client_hello) |data| self.allocator.free(data);
                    self.client_hello = try self.allocator.dupe(u8, client_hello);
                    self.state = .wait_server_hello;
                    return try allocator.dupe(u8, client_hello);
                } else {
                    return Error.ZquicError.ProtocolViolation;
                }
            },
            .wait_server_hello => {
                if (self.is_server) {
                    // Generate ServerHello, Certificate, CertificateVerify, Finished
                    const server_hello = "ServerHello with QUIC transport parameters and Certificate";
                    if (self.server_hello) |data| self.allocator.free(data);
                    self.server_hello = try self.allocator.dupe(u8, server_hello);
                    self.state = .wait_finished;
                    return try allocator.dupe(u8, server_hello);
                } else {
                    return Error.ZquicError.ProtocolViolation;
                }
            },
            .wait_finished => {
                if (!self.is_server) {
                    // Generate Finished
                    const finished = "Finished message";
                    if (self.finished) |data| self.allocator.free(data);
                    self.finished = try self.allocator.dupe(u8, finished);
                    self.state = .completed;
                    try self.deriveApplicationKeys();
                    return try allocator.dupe(u8, finished);
                } else {
                    return Error.ZquicError.ProtocolViolation;
                }
            },
            else => {
                return Error.ZquicError.ProtocolViolation;
            },
        }
    }

    /// Check if handshake is completed
    pub fn isHandshakeComplete(self: *const Self) bool {
        return self.state == .completed;
    }

    /// Get keys for the specified encryption level
    pub fn getKeys(self: *const Self, level: EncryptionLevel) ?*const CryptoKeys {
        return switch (level) {
            .initial => if (self.initial_keys) |*keys| keys else null,
            .handshake => if (self.handshake_keys) |*keys| keys else null,
            .application => if (self.application_keys) |*keys| keys else null,
        };
    }

    /// Derive handshake keys (called after processing handshake messages)
    pub fn deriveHandshakeKeys(self: *Self) Error.ZquicError!void {
        const handshake_secret = "handshake_secret_derived_from_messages";
        self.handshake_keys = try CryptoKeys.deriveFromSecret(handshake_secret);
    }

    /// Derive application keys (called after handshake completion)
    fn deriveApplicationKeys(self: *Self) Error.ZquicError!void {
        const application_secret = "application_secret_derived_from_master_secret";
        self.application_keys = try CryptoKeys.deriveFromSecret(application_secret);
    }

    /// Encrypt data using ChaCha20-Poly1305 AEAD
    pub fn encrypt(self: *const Self, level: EncryptionLevel, plaintext: []const u8, packet_number: u64, allocator: std.mem.Allocator) Error.ZquicError![]u8 {
        const keys = self.getKeys(level) orelse return Error.ZquicError.CryptoError;

        // Construct nonce from IV XOR packet number (QUIC nonce construction)
        var nonce: [12]u8 = keys.iv;
        const pn_bytes = std.mem.toBytes(packet_number);
        for (nonce[4..12], pn_bytes[0..8]) |*n, p| {
            n.* ^= p;
        }

        // Allocate output: ciphertext + 16-byte auth tag
        var ciphertext = try allocator.alloc(u8, plaintext.len + 16);
        errdefer allocator.free(ciphertext);

        // Use empty AAD (QUIC would use packet header as AAD)
        const aad: []const u8 = &[_]u8{};

        // Perform ChaCha20-Poly1305 AEAD encryption
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0..plaintext.len],
            ciphertext[plaintext.len..][0..16],
            plaintext,
            aad,
            nonce,
            keys.key,
        );

        return ciphertext;
    }

    /// Decrypt data using ChaCha20-Poly1305 AEAD
    pub fn decrypt(self: *const Self, level: EncryptionLevel, ciphertext: []const u8, packet_number: u64, allocator: std.mem.Allocator) Error.ZquicError![]u8 {
        const keys = self.getKeys(level) orelse return Error.ZquicError.CryptoError;

        // Must have at least 16-byte auth tag
        if (ciphertext.len < 16) {
            return Error.ZquicError.CryptoError;
        }

        const plaintext_len = ciphertext.len - 16;

        // Construct nonce from IV XOR packet number (QUIC nonce construction)
        var nonce: [12]u8 = keys.iv;
        const pn_bytes = std.mem.toBytes(packet_number);
        for (nonce[4..12], pn_bytes[0..8]) |*n, p| {
            n.* ^= p;
        }

        // Allocate output buffer for plaintext
        const plaintext = try allocator.alloc(u8, plaintext_len);
        errdefer allocator.free(plaintext);

        // Use empty AAD
        const aad: []const u8 = &[_]u8{};

        // Perform ChaCha20-Poly1305 AEAD decryption with authentication
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext[0..plaintext_len],
            ciphertext[plaintext_len..][0..16].*,
            aad,
            nonce,
            keys.key,
        ) catch {
            allocator.free(plaintext);
            return Error.ZquicError.CryptoError;
        };

        return plaintext;
    }
};

/// QUIC encryption levels
pub const EncryptionLevel = enum {
    initial,
    handshake,
    application,
};

test "TLS context initialization" {
    var tls = TlsContext.init(std.testing.allocator, false);
    defer tls.deinit();

    try std.testing.expect(tls.state == .initial);
    try std.testing.expect(!tls.is_server);
    try std.testing.expect(!tls.isHandshakeComplete());
}

test "crypto keys derivation" {
    const secret = "test_secret_that_is_long_enough_for_derivation";
    const keys = try CryptoKeys.deriveFromSecret(secret);

    // Keys should be different from each other
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &keys.iv));
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &keys.header_protection_key));
}

test "handshake flow" {
    var client_tls = TlsContext.init(std.testing.allocator, false);
    defer client_tls.deinit();

    var server_tls = TlsContext.init(std.testing.allocator, true);
    defer server_tls.deinit();

    // Client generates ClientHello
    const client_hello = try client_tls.generateCryptoData(std.testing.allocator);
    defer std.testing.allocator.free(client_hello);

    // Server processes ClientHello
    try server_tls.processCryptoData(client_hello, 0);
    try std.testing.expect(server_tls.state == .wait_server_hello);

    // Server generates ServerHello
    const server_hello = try server_tls.generateCryptoData(std.testing.allocator);
    defer std.testing.allocator.free(server_hello);

    // Client processes ServerHello
    try client_tls.processCryptoData(server_hello, 0);
    try std.testing.expect(client_tls.state == .wait_finished);
}
