//! Experimental TLS 1.3 scaffold for QUIC with ZCrypto integration
//!
//! This module is intentionally not exported as a production TLS stack. It
//! contains useful bounded pieces: traffic-key derivation, key update helpers,
//! session-ticket helpers, and caller-supplied raw public-key certificate
//! verification. DER/X.509 parsing, chain building, trust stores, hostname
//! validation, and full TLS transcript interop remain unsupported.

const std = @import("std");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");
const CoreTransportParameters = @import("../core/transport_parameters.zig");
const zcrypto = @import("zcrypto");

/// Security configuration for legacy scaffold paths.
/// This must remain false; simplified verification paths fail closed.
pub const allow_simplified_verification = false;

pub const maturity_status = "experimental-scaffold";
pub const supports_production_tls = false;
pub const supports_x509_certificate_validation = false;
pub const supports_delegated_x509_validation = true;
pub const supports_raw_public_key_verification = true;
pub const default_quic_alpn = "h3";

pub const TlsCiphertextRecord = zcrypto.tls.record.TlsCiphertext;

pub const CertificateValidationMode = enum {
    production_x509,
    raw_public_key,
    test_insecure,
};

pub const CertificateValidationPolicy = struct {
    mode: CertificateValidationMode = .production_x509,
    hostname: ?[]const u8 = null,
    validation_time: ?i64 = null,

    pub fn production(hostname: []const u8) CertificateValidationPolicy {
        return .{ .mode = .production_x509, .hostname = hostname };
    }

    pub fn rawPublicKey(validation_time: i64) CertificateValidationPolicy {
        return .{ .mode = .raw_public_key, .validation_time = validation_time };
    }

    pub fn rawPublicKeyForHost(hostname: []const u8, validation_time: i64) CertificateValidationPolicy {
        return .{ .mode = .raw_public_key, .hostname = hostname, .validation_time = validation_time };
    }

    pub fn testInsecure() CertificateValidationPolicy {
        return .{ .mode = .test_insecure };
    }
};

pub fn parseTlsCiphertextRecord(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error.ZquicError!TlsCiphertextRecord {
    return zcrypto.tls.record.TlsCiphertext.fromBytes(allocator, bytes) catch Error.ZquicError.CryptoError;
}

pub const DeprotectedTlsRecord = struct {
    record_type: zcrypto.tls.record.RecordType,
    plaintext: []u8,

    pub fn deinit(self: *DeprotectedTlsRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.plaintext);
    }
};

pub fn verifyX509CertificateWithRoots(
    allocator: std.mem.Allocator,
    cert_der: []const u8,
    hostname: ?[]const u8,
    root_ca_der: []const []const u8,
) Error.ZquicError!bool {
    if (root_ca_der.len == 0) return Error.ZquicError.CertificateError;

    var roots = allocator.alloc(zcrypto.tls.config.Certificate, root_ca_der.len) catch return Error.ZquicError.OutOfMemory;
    defer allocator.free(roots);

    var initialized: usize = 0;

    for (root_ca_der, 0..) |der, i| {
        roots[i] = zcrypto.tls.config.Certificate.fromDer(allocator, der) catch {
            for (roots[0..initialized]) |root| {
                root.deinit(allocator);
            }
            return Error.ZquicError.CertificateError;
        };
        initialized += 1;
    }
    defer {
        for (roots[0..initialized]) |root| {
            root.deinit(allocator);
        }
    }

    const config = zcrypto.tls.config.TlsConfig.init(allocator).withRootCAs(roots);
    return config.verifyCertificate(cert_der, hostname) catch Error.ZquicError.CertificateError;
}

/// TLS 1.3 version constant
pub const TLS_VERSION_1_3: u16 = 0x0304;

/// TLS 1.3 cipher-suite identifiers used by the experimental scaffold.
pub const CipherSuite = enum(u16) {
    // Standard TLS 1.3 cipher suites
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_aes_128_ccm_sha256 = 0x1304,
    tls_aes_128_ccm_8_sha256 = 0x1305,

    // Post-quantum hybrid cipher suites
    tls_ml_kem_768_aes_128_gcm_sha256 = 0xFE00,
    tls_ml_kem_1024_aes_256_gcm_sha384 = 0xFE01,
    tls_ml_kem_768_chacha20_poly1305_sha256 = 0xFE02,

    pub fn getHashAlgorithm(self: CipherSuite) HashAlgorithm {
        return switch (self) {
            .tls_aes_128_gcm_sha256, .tls_aes_128_ccm_sha256, .tls_aes_128_ccm_8_sha256, .tls_ml_kem_768_aes_128_gcm_sha256 => .sha256,
            .tls_aes_256_gcm_sha384, .tls_ml_kem_1024_aes_256_gcm_sha384 => .sha384,
            .tls_chacha20_poly1305_sha256, .tls_ml_kem_768_chacha20_poly1305_sha256 => .sha256,
        };
    }

    pub fn getKeyLength(self: CipherSuite) u32 {
        return switch (self) {
            .tls_aes_128_gcm_sha256, .tls_aes_128_ccm_sha256, .tls_aes_128_ccm_8_sha256, .tls_ml_kem_768_aes_128_gcm_sha256 => 16,
            .tls_aes_256_gcm_sha384, .tls_ml_kem_1024_aes_256_gcm_sha384 => 32,
            .tls_chacha20_poly1305_sha256, .tls_ml_kem_768_chacha20_poly1305_sha256 => 32,
        };
    }

    pub fn isPostQuantum(self: CipherSuite) bool {
        return switch (self) {
            .tls_ml_kem_768_aes_128_gcm_sha256, .tls_ml_kem_1024_aes_256_gcm_sha384, .tls_ml_kem_768_chacha20_poly1305_sha256 => true,
            else => false,
        };
    }

    pub fn isQuicTls13(self: CipherSuite) bool {
        return switch (self) {
            .tls_aes_128_gcm_sha256,
            .tls_aes_256_gcm_sha384,
            .tls_chacha20_poly1305_sha256,
            => true,
            else => false,
        };
    }
};

pub fn validateQuicCipherSuite(cipher_suite: CipherSuite) Error.ZquicError!void {
    if (!cipher_suite.isQuicTls13()) return Error.ZquicError.UnsupportedAlgorithm;
}

pub fn validateQuicAlpn(expected: []const u8, offered: []const u8) Error.ZquicError!void {
    if (expected.len == 0 or offered.len == 0) return Error.ZquicError.ProtocolViolation;
    if (!std.mem.eql(u8, expected, offered)) return Error.ZquicError.ProtocolViolation;
}

/// Hash algorithms supported by TLS 1.3
pub const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,
    blake3,

    pub fn getHashSize(self: HashAlgorithm) u32 {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
            .blake3 => 32,
        };
    }
};

/// Signature algorithms with ZCrypto support
pub const SignatureAlgorithm = enum(u16) {
    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSA algorithms
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA algorithms
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // Post-quantum signature algorithms
    dilithium3 = 0xFE10,
    falcon512 = 0xFE11,
    sphincs_sha256_128s = 0xFE12,

    pub fn isPostQuantum(self: SignatureAlgorithm) bool {
        return switch (self) {
            .dilithium3, .falcon512, .sphincs_sha256_128s => true,
            else => false,
        };
    }
};

pub const CertificateEncoding = enum {
    der_unparsed,
    raw_public_key,
};

/// Key exchange algorithms
pub const KeyExchangeAlgorithm = enum(u16) {
    // Standard elliptic curve groups
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    // Post-quantum key exchange
    ml_kem_512 = 0xFE20,
    ml_kem_768 = 0xFE21,
    ml_kem_1024 = 0xFE22,

    pub fn isPostQuantum(self: KeyExchangeAlgorithm) bool {
        return switch (self) {
            .ml_kem_512, .ml_kem_768, .ml_kem_1024 => true,
            else => false,
        };
    }

    pub fn getKeySize(self: KeyExchangeAlgorithm) u32 {
        return switch (self) {
            .secp256r1 => 32,
            .secp384r1 => 48,
            .secp521r1 => 66,
            .x25519 => 32,
            .x448 => 56,
            .ml_kem_512 => 800,
            .ml_kem_768 => 1184,
            .ml_kem_1024 => 1568,
        };
    }
};

/// TLS 1.3 handshake states
pub const HandshakeState = enum {
    initial,
    wait_client_hello,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate_request,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    connected,
    wait_new_session_ticket,

    // 0-RTT states
    wait_early_data,
    early_data_accepted,
    early_data_rejected,

    // Error states
    failed,
    closed,
};

/// Enhanced QUIC Transport Parameters
pub const TransportParameters = struct {
    // Core parameters
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

    // Connection identifiers
    initial_source_connection_id: ?[]const u8 = null,
    original_destination_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    stateless_reset_token: ?[16]u8 = null,

    // Advanced parameters
    max_datagram_frame_size: ?u64 = null,
    grease_quic_bit: bool = false,
    version_information: ?[]const u32 = null,

    // Custom extensions
    custom_parameters: std.AutoHashMapUnmanaged(u64, []const u8),

    pub fn init() TransportParameters {
        return TransportParameters{
            .custom_parameters = .empty,
        };
    }

    pub fn deinit(self: *TransportParameters, allocator: std.mem.Allocator) void {
        var iterator = self.custom_parameters.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.value_ptr.*);
        }
        self.custom_parameters.deinit(allocator);
    }
};

/// Comprehensive cryptographic keys with ZCrypto integration
pub const CryptoKeys = struct {
    cipher_suite: CipherSuite,
    hash_algorithm: HashAlgorithm,

    // Traffic secret (used for Finished message computation)
    secret: []u8,

    // Key material
    client_write_key: []u8,
    server_write_key: []u8,
    client_write_iv: []u8,
    server_write_iv: []u8,

    // Header protection keys
    client_hp_key: []u8,
    server_hp_key: []u8,

    // Key update support
    update_secret: []u8,
    key_update_count: u64,

    // Post-quantum keys
    pq_shared_secret: ?[]u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, cipher_suite: CipherSuite) !Self {
        const key_len = cipher_suite.getKeyLength();
        const iv_len = 12; // All TLS 1.3 ciphers use 12-byte IV
        const hp_key_len = key_len;
        const hash_size = cipher_suite.getHashAlgorithm().getHashSize();

        return Self{
            .cipher_suite = cipher_suite,
            .hash_algorithm = cipher_suite.getHashAlgorithm(),
            .secret = try allocator.alloc(u8, hash_size),
            .client_write_key = try allocator.alloc(u8, key_len),
            .server_write_key = try allocator.alloc(u8, key_len),
            .client_write_iv = try allocator.alloc(u8, iv_len),
            .server_write_iv = try allocator.alloc(u8, iv_len),
            .client_hp_key = try allocator.alloc(u8, hp_key_len),
            .server_hp_key = try allocator.alloc(u8, hp_key_len),
            .update_secret = try allocator.alloc(u8, hash_size),
            .key_update_count = 0,
            .pq_shared_secret = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Zero out sensitive key material
        std.crypto.secureZero(u8, self.secret);
        std.crypto.secureZero(u8, self.client_write_key);
        std.crypto.secureZero(u8, self.server_write_key);
        std.crypto.secureZero(u8, self.client_write_iv);
        std.crypto.secureZero(u8, self.server_write_iv);
        std.crypto.secureZero(u8, self.client_hp_key);
        std.crypto.secureZero(u8, self.server_hp_key);
        std.crypto.secureZero(u8, self.update_secret);

        if (self.pq_shared_secret) |pq_secret| {
            std.crypto.secureZero(u8, pq_secret);
            self.allocator.free(pq_secret);
        }

        self.allocator.free(self.secret);
        self.allocator.free(self.client_write_key);
        self.allocator.free(self.server_write_key);
        self.allocator.free(self.client_write_iv);
        self.allocator.free(self.server_write_iv);
        self.allocator.free(self.client_hp_key);
        self.allocator.free(self.server_hp_key);
        self.allocator.free(self.update_secret);
    }

    /// Derive keys from traffic secret using HKDF with ZCrypto
    pub fn deriveFromTrafficSecret(self: *Self, traffic_secret: []const u8, is_client: bool) !void {
        // Store traffic secret for Finished message computation
        const copy_len = @min(traffic_secret.len, self.secret.len);
        @memcpy(self.secret[0..copy_len], traffic_secret[0..copy_len]);

        // Derive write key
        const write_key = if (is_client) self.client_write_key else self.server_write_key;
        try self.hkdfExpandLabel(traffic_secret, "quic key", &[_]u8{}, write_key);

        // Derive write IV
        const write_iv = if (is_client) self.client_write_iv else self.server_write_iv;
        try self.hkdfExpandLabel(traffic_secret, "quic iv", &[_]u8{}, write_iv);

        // Derive header protection key
        const hp_key = if (is_client) self.client_hp_key else self.server_hp_key;
        try self.hkdfExpandLabel(traffic_secret, "quic hp", &[_]u8{}, hp_key);

        // Update key update secret
        try self.hkdfExpandLabel(traffic_secret, "quic ku", &[_]u8{}, self.update_secret);
    }

    /// HKDF-Expand-Label implementation using ZCrypto
    /// Supports SHA-256 and SHA-384 for TLS 1.3 key derivation.
    /// Blake3 is not supported for TLS key derivation.
    fn hkdfExpandLabel(self: *Self, secret: []const u8, label: []const u8, context: []const u8, out: []u8) !void {
        switch (self.hash_algorithm) {
            .sha256 => {
                // zcrypto handles TLS 1.3 HKDF-Label formatting internally.
                const derived = try zcrypto.kdf.hkdfExpandLabel(self.allocator, secret, label, context, out.len);
                defer self.allocator.free(derived);
                @memcpy(out, derived);
            },
            .sha384 => {
                // SHA-384 uses std.crypto since zcrypto doesn't have SHA-384 HKDF
                const Hkdf = std.crypto.kdf.hkdf.Hkdf(std.crypto.hash.sha2.Sha384);

                // Construct TLS 1.3 HKDF-Label
                const tls_prefix = "tls13 ";
                const full_label_len = tls_prefix.len + label.len;
                const hkdf_label_size = 2 + 1 + full_label_len + 1 + context.len;
                const hkdf_label = try self.allocator.alloc(u8, hkdf_label_size);
                defer self.allocator.free(hkdf_label);

                var offset: usize = 0;
                hkdf_label[offset] = @intCast((out.len >> 8) & 0xFF);
                hkdf_label[offset + 1] = @intCast(out.len & 0xFF);
                offset += 2;
                hkdf_label[offset] = @intCast(full_label_len);
                offset += 1;
                @memcpy(hkdf_label[offset .. offset + tls_prefix.len], tls_prefix);
                offset += tls_prefix.len;
                @memcpy(hkdf_label[offset .. offset + label.len], label);
                offset += label.len;
                hkdf_label[offset] = @intCast(context.len);
                offset += 1;
                if (context.len > 0) {
                    @memcpy(hkdf_label[offset .. offset + context.len], context);
                }

                // SHA-384 PRK is 48 bytes
                if (secret.len < 48) return Error.ZquicError.CryptoError;
                Hkdf.expand(out, hkdf_label, secret[0..48].*);
            },
            .blake3 => {
                // Blake3 is not supported for TLS key derivation in v0.9.9
                return Error.ZquicError.UnsupportedAlgorithm;
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }
    }

    /// Perform key update
    pub fn updateKeys(self: *Self, is_client: bool) !void {
        const new_secret = try self.allocator.alloc(u8, self.update_secret.len);
        defer self.allocator.free(new_secret);

        try self.hkdfExpandLabel(self.update_secret, "quic ku", &[_]u8{}, new_secret);

        @memcpy(self.update_secret, new_secret);
        try self.deriveFromTrafficSecret(new_secret, is_client);

        self.key_update_count += 1;
    }
};

/// Experimental certificate container.
///
/// This stores DER bytes and exposes limited signature helper checks. It does
/// not parse X.509, build chains, validate hostnames, load trust anchors, or
/// provide production TLS certificate verification.
pub const Certificate = struct {
    encoding: CertificateEncoding,
    data: []const u8,
    signature_algorithm: SignatureAlgorithm,
    public_key: []const u8,
    subject: []const u8,
    issuer: []const u8,
    not_before: i64,
    not_after: i64,
    extensions: std.StringHashMapUnmanaged([]const u8),

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, der_data: []const u8) !Self {
        // DER parsing is intentionally not implemented here. Keep this as a
        // storage container until a real ASN.1/X.509 parser is wired in.

        return Self{
            .encoding = .der_unparsed,
            .data = try allocator.dupe(u8, der_data),
            .signature_algorithm = .ed25519, // Default
            .public_key = &[_]u8{}, // Would extract from certificate
            .subject = &[_]u8{},
            .issuer = &[_]u8{},
            .not_before = 0,
            .not_after = std.math.maxInt(i64),
            .extensions = .empty,
            .allocator = allocator,
        };
    }

    pub fn initRawEd25519PublicKey(
        allocator: std.mem.Allocator,
        public_key: []const u8,
        subject: []const u8,
        issuer: []const u8,
        not_before: i64,
        not_after: i64,
    ) !Self {
        if (public_key.len != 32) return Error.ZquicError.InvalidArgument;
        if (not_after < not_before) return Error.ZquicError.InvalidArgument;

        return Self{
            .encoding = .raw_public_key,
            .data = try allocator.dupe(u8, public_key),
            .signature_algorithm = .ed25519,
            .public_key = try allocator.dupe(u8, public_key),
            .subject = try allocator.dupe(u8, subject),
            .issuer = try allocator.dupe(u8, issuer),
            .not_before = not_before,
            .not_after = not_after,
            .extensions = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
        if (self.encoding == .raw_public_key) {
            self.allocator.free(self.public_key);
            self.allocator.free(self.subject);
            self.allocator.free(self.issuer);
        }

        var iterator = self.extensions.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.extensions.deinit(self.allocator);
    }

    pub fn verify(self: *const Self, signature: []const u8, message: []const u8) !bool {
        if (self.encoding == .der_unparsed) {
            return Error.ZquicError.NotSupported;
        }
        switch (self.signature_algorithm) {
            .ed25519 => {
                // Use zcrypto.asym stable API for Ed25519 verification
                if (signature.len < 64 or self.public_key.len < 32) {
                    return Error.ZquicError.CryptoError;
                }
                return zcrypto.asym.verifyEd25519(
                    message,
                    signature[0..64].*,
                    self.public_key[0..32].*,
                );
            },
            .ecdsa_secp256r1_sha256 => {
                // ECDSA-P256 verification - use std.crypto
                if (signature.len < 64 or self.public_key.len < 33) {
                    return Error.ZquicError.CryptoError;
                }
                // Note: Full ECDSA verification requires proper implementation
                // For now, return unsupported until proper std.crypto integration
                return Error.ZquicError.UnsupportedAlgorithm;
            },
            .dilithium3 => {
                // Dilithium3 is PQ and requires experimental-crypto
                // Gate this behind build option check at runtime
                return Error.ZquicError.UnsupportedAlgorithm;
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }
    }

    pub fn isValidAt(self: *const Self, timestamp: i64) bool {
        return timestamp >= self.not_before and timestamp <= self.not_after;
    }

    pub fn verifyRawPublicKeyAt(
        self: *const Self,
        signature: []const u8,
        message: []const u8,
        timestamp: i64,
    ) !bool {
        if (self.encoding != .raw_public_key) return Error.ZquicError.NotSupported;
        if (!self.isValidAt(timestamp)) return false;
        return try self.verify(signature, message);
    }
};

/// Session ticket for 0-RTT support
pub const SessionTicket = struct {
    ticket: []const u8,
    resumption_secret: []const u8,
    cipher_suite: CipherSuite,
    max_early_data_size: u32,
    age_add: u32,
    issued_at: i64,
    lifetime: u32,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, ticket_data: []const u8, secret: []const u8, cipher_suite: CipherSuite) !Self {
        return Self{
            .ticket = try allocator.dupe(u8, ticket_data),
            .resumption_secret = try allocator.dupe(u8, secret),
            .cipher_suite = cipher_suite,
            .max_early_data_size = 0xFFFFFFFF,
            .age_add = 0,
            .issued_at = blk: {
                const ts = try std.posix.clock_gettime(std.posix.CLOCK.REALTIME);
                break :blk ts.sec;
            },
            .lifetime = 7 * 24 * 60 * 60, // 7 days
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.ticket);
        std.crypto.secureZero(u8, @constCast(self.resumption_secret));
        self.allocator.free(self.resumption_secret);
    }

    pub fn isValid(self: *const Self) bool {
        const now = Time.nowSeconds();
        return now >= self.issued_at and now < self.issued_at + self.lifetime;
    }

    pub fn getAge(self: *const Self) u32 {
        const now = Time.nowSeconds();
        const age = @as(u32, @intCast(now - self.issued_at));
        return age +% self.age_add;
    }
};

/// Experimental TLS 1.3 context.
///
/// This is a development surface for bounded helpers, not a production TLS
/// state machine.
pub const ComprehensiveTlsContext = struct {
    // Basic state
    state: HandshakeState,
    is_server: bool,
    cipher_suite: CipherSuite,
    signature_algorithm: SignatureAlgorithm,
    key_exchange_algorithm: KeyExchangeAlgorithm,

    // Transport parameters
    transport_params: TransportParameters,
    peer_transport_params: ?TransportParameters,
    peer_quic_transport_params: ?CoreTransportParameters.TransportParameters,
    peer_quic_transport_parameter_bytes: ?[]u8,

    // Cryptographic keys
    initial_keys: ?CryptoKeys,
    handshake_keys: ?CryptoKeys,
    application_keys: ?CryptoKeys,
    zero_rtt_keys: ?CryptoKeys,

    // Certificate chain
    certificate_chain: std.ArrayListUnmanaged(Certificate),
    peer_certificate_chain: std.ArrayListUnmanaged(Certificate),

    // Session resumption
    session_ticket: ?SessionTicket,
    resumption_secret: ?[]const u8,

    // 0-RTT support
    max_early_data_size: u32,
    early_data_accepted: bool,
    negotiated_alpn: ?[]const u8,

    // Handshake transcript
    handshake_transcript: std.ArrayListUnmanaged(u8),

    // Key exchange materials
    private_key: ?[]const u8,
    public_key: ?[]const u8,
    peer_public_key: ?[]const u8,
    shared_secret: ?[]const u8,

    // Post-quantum support
    pq_private_key: ?[]const u8,
    pq_public_key: ?[]const u8,
    pq_peer_public_key: ?[]const u8,
    pq_shared_secret: ?[]const u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .state = .initial,
            .is_server = is_server,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .signature_algorithm = .ed25519,
            .key_exchange_algorithm = .x25519,
            .transport_params = TransportParameters.init(),
            .peer_transport_params = null,
            .peer_quic_transport_params = null,
            .peer_quic_transport_parameter_bytes = null,
            .initial_keys = null,
            .handshake_keys = null,
            .application_keys = null,
            .zero_rtt_keys = null,
            .certificate_chain = .empty,
            .peer_certificate_chain = .empty,
            .session_ticket = null,
            .resumption_secret = null,
            .max_early_data_size = 0,
            .early_data_accepted = false,
            .negotiated_alpn = null,
            .handshake_transcript = .empty,
            .private_key = null,
            .public_key = null,
            .peer_public_key = null,
            .shared_secret = null,
            .pq_private_key = null,
            .pq_public_key = null,
            .pq_peer_public_key = null,
            .pq_shared_secret = null,
            .allocator = allocator,
        };
    }

    pub fn validatePeerCertificatePolicy(self: *const Self, policy: CertificateValidationPolicy) Error.ZquicError!void {
        switch (policy.mode) {
            .test_insecure => return,
            .production_x509 => {
                _ = policy.hostname orelse return Error.ZquicError.CertificateError;
                if (self.peer_certificate_chain.items.len == 0) return Error.ZquicError.CertificateError;
                return Error.ZquicError.NotSupported;
            },
            .raw_public_key => {
                if (self.peer_certificate_chain.items.len == 0) return Error.ZquicError.CertificateError;
                const timestamp = policy.validation_time orelse Time.nowSeconds();
                const cert = &self.peer_certificate_chain.items[0];
                if (cert.encoding != .raw_public_key) return Error.ZquicError.CertificateError;
                if (policy.hostname) |hostname| {
                    if (!std.ascii.eqlIgnoreCase(cert.subject, hostname)) return Error.ZquicError.CertificateError;
                }
                if (!cert.isValidAt(timestamp)) return Error.ZquicError.CertificateError;
            },
        }
    }

    pub fn deinit(self: *Self) void {
        // Clean up transport parameters
        self.transport_params.deinit(self.allocator);
        if (self.peer_transport_params) |*params| {
            params.deinit(self.allocator);
        }
        if (self.peer_quic_transport_parameter_bytes) |bytes| {
            self.allocator.free(bytes);
        }

        // Clean up cryptographic keys
        if (self.initial_keys) |*keys| keys.deinit();
        if (self.handshake_keys) |*keys| keys.deinit();
        if (self.application_keys) |*keys| keys.deinit();
        if (self.zero_rtt_keys) |*keys| keys.deinit();

        // Clean up certificates
        for (self.certificate_chain.items) |*cert| {
            cert.deinit();
        }
        self.certificate_chain.deinit(self.allocator);

        for (self.peer_certificate_chain.items) |*cert| {
            cert.deinit();
        }
        self.peer_certificate_chain.deinit(self.allocator);

        // Clean up session ticket
        if (self.session_ticket) |*ticket| {
            ticket.deinit();
        }
        if (self.negotiated_alpn) |alpn| {
            self.allocator.free(alpn);
        }

        // Clean up sensitive key material
        if (self.resumption_secret) |secret| {
            std.crypto.secureZero(u8, @constCast(secret));
            self.allocator.free(secret);
        }

        if (self.private_key) |key| {
            std.crypto.secureZero(u8, @constCast(key));
            self.allocator.free(key);
        }

        if (self.public_key) |key| {
            self.allocator.free(key);
        }

        if (self.peer_public_key) |key| {
            self.allocator.free(key);
        }

        if (self.shared_secret) |secret| {
            std.crypto.secureZero(u8, @constCast(secret));
            self.allocator.free(secret);
        }

        if (self.pq_private_key) |key| {
            std.crypto.secureZero(u8, @constCast(key));
            self.allocator.free(key);
        }

        if (self.pq_public_key) |key| {
            self.allocator.free(key);
        }

        if (self.pq_peer_public_key) |key| {
            self.allocator.free(key);
        }

        if (self.pq_shared_secret) |secret| {
            std.crypto.secureZero(u8, @constCast(secret));
            self.allocator.free(secret);
        }

        self.handshake_transcript.deinit(self.allocator);
    }

    /// Initialize connection for client
    pub fn initClient(self: *Self, server_name: []const u8) !void {
        _ = server_name;
        self.state = .initial;
        try self.generateKeyPair();

        if (self.cipher_suite.isPostQuantum()) {
            try self.generatePostQuantumKeyPair();
        }
    }

    /// Initialize connection for server
    pub fn initServer(self: *Self, certificate_chain: []const []const u8) !void {
        self.state = .wait_client_hello;

        // Load server certificate chain
        for (certificate_chain) |cert_data| {
            const cert = try Certificate.init(self.allocator, cert_data);
            try self.certificate_chain.append(self.allocator, cert);
        }

        try self.generateKeyPair();

        if (self.cipher_suite.isPostQuantum()) {
            try self.generatePostQuantumKeyPair();
        }
    }

    /// Generate key pair for selected algorithm
    fn generateKeyPair(self: *Self) !void {
        switch (self.key_exchange_algorithm) {
            .x25519 => {
                // Use zcrypto.kex stable API for X25519
                const keypair = try zcrypto.kex.X25519.generateKeypair();
                self.private_key = try self.allocator.dupe(u8, &keypair.private_key);
                self.public_key = try self.allocator.dupe(u8, &keypair.public_key);
            },
            .secp256r1 => {
                // SECP256R1 key generation - use std.crypto
                // Note: Full P-256 requires proper implementation
                return Error.ZquicError.UnsupportedAlgorithm;
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }
    }

    /// Generate post-quantum key pair
    fn generatePostQuantumKeyPair(self: *Self) !void {
        // PQ key generation requires experimental-crypto flag
        // These are gated at compile time via build_options
        switch (self.key_exchange_algorithm) {
            .ml_kem_768, .ml_kem_1024 => {
                // ML-KEM requires -Dpost-quantum=true -Dexperimental-crypto=true
                // Return unsupported when not available
                return Error.ZquicError.UnsupportedAlgorithm;
            },
            else => {}, // No post-quantum support for this algorithm
        }
    }

    /// Process handshake message
    pub fn processHandshakeMessage(self: *Self, message_type: u8, message: []const u8) !void {
        try self.validateExpectedHandshakeMessage(message_type);

        const previous_state = self.state;
        errdefer self.state = previous_state;

        try self.processHandshakeMessageUnchecked(message_type, message);

        // Update transcript only after the message is accepted. Rejected
        // handshake input must not poison Finished verification state.
        try self.handshake_transcript.append(self.allocator, message_type);
        try self.handshake_transcript.writer(self.allocator).writeInt(u24, @intCast(message.len), .big);
        try self.handshake_transcript.appendSlice(self.allocator, message);
    }

    /// Parse a TLS ciphertext record with zcrypto's record layer and feed any
    /// contained plaintext handshake messages into the comprehensive state
    /// machine. This adapter is for record-orchestration tests and future live
    /// TLS wiring; encrypted TLSInnerPlaintext deprotection remains outside this
    /// helper.
    pub fn processTlsCiphertextRecord(self: *Self, record_bytes: []const u8) Error.ZquicError!usize {
        var record = try parseTlsCiphertextRecord(self.allocator, record_bytes);
        defer record.deinit();

        if (record.header.record_type != zcrypto.tls.record.RecordType.handshake) {
            return Error.ZquicError.ProtocolViolation;
        }

        return self.processPlaintextHandshakeRecordData(record.encrypted_data);
    }

    pub fn decryptTlsCiphertextRecord(
        self: *Self,
        record_bytes: []const u8,
        keys: *const CryptoKeys,
        from_client: bool,
        sequence_number: u64,
    ) Error.ZquicError!DeprotectedTlsRecord {
        if (record_bytes.len < 5) return Error.ZquicError.CryptoError;

        var record = try parseTlsCiphertextRecord(self.allocator, record_bytes);
        defer record.deinit();

        if (record.header.record_type != zcrypto.tls.record.RecordType.application_data) {
            return Error.ZquicError.ProtocolViolation;
        }
        if (record.encrypted_data.len < 17) return Error.ZquicError.CryptoError;

        const key = if (from_client) keys.client_write_key else keys.server_write_key;
        const iv = if (from_client) keys.client_write_iv else keys.server_write_iv;
        if (iv.len != 12) return Error.ZquicError.CryptoError;

        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, iv[0..12]);
        var sequence_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence_bytes, sequence_number, .big);
        for (0..8) |i| {
            nonce[4 + i] ^= sequence_bytes[i];
        }

        const tag_start = record.encrypted_data.len - 16;
        const encrypted_content = record.encrypted_data[0..tag_start];
        var tag: [16]u8 = undefined;
        @memcpy(&tag, record.encrypted_data[tag_start..]);

        const plaintext = self.allocator.alloc(u8, encrypted_content.len) catch return Error.ZquicError.OutOfMemory;
        errdefer self.allocator.free(plaintext);

        switch (keys.cipher_suite) {
            .tls_aes_128_gcm_sha256, .tls_ml_kem_768_aes_128_gcm_sha256 => {
                if (key.len < 16) return Error.ZquicError.CryptoError;
                std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    record_bytes[0..5],
                    nonce,
                    key[0..16].*,
                ) catch return Error.ZquicError.CryptoError;
            },
            .tls_aes_256_gcm_sha384, .tls_ml_kem_1024_aes_256_gcm_sha384 => {
                if (key.len < 32) return Error.ZquicError.CryptoError;
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    record_bytes[0..5],
                    nonce,
                    key[0..32].*,
                ) catch return Error.ZquicError.CryptoError;
            },
            .tls_chacha20_poly1305_sha256, .tls_ml_kem_768_chacha20_poly1305_sha256 => {
                if (key.len < 32) return Error.ZquicError.CryptoError;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                    plaintext,
                    encrypted_content,
                    tag,
                    record_bytes[0..5],
                    nonce,
                    key[0..32].*,
                ) catch return Error.ZquicError.CryptoError;
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }

        var content_end = plaintext.len;
        while (content_end > 0 and plaintext[content_end - 1] == 0) {
            content_end -= 1;
        }
        if (content_end == 0) return Error.ZquicError.CryptoError;

        const inner_type = switch (plaintext[content_end - 1]) {
            20 => zcrypto.tls.record.RecordType.change_cipher_spec,
            21 => zcrypto.tls.record.RecordType.alert,
            22 => zcrypto.tls.record.RecordType.handshake,
            23 => zcrypto.tls.record.RecordType.application_data,
            else => return Error.ZquicError.ProtocolViolation,
        };

        const content = self.allocator.alloc(u8, content_end - 1) catch return Error.ZquicError.OutOfMemory;
        @memcpy(content, plaintext[0 .. content_end - 1]);
        self.allocator.free(plaintext);

        return .{
            .record_type = inner_type,
            .plaintext = content,
        };
    }

    pub fn processEncryptedTlsCiphertextRecord(
        self: *Self,
        record_bytes: []const u8,
        keys: *const CryptoKeys,
        from_client: bool,
        sequence_number: u64,
    ) Error.ZquicError!usize {
        var record = try self.decryptTlsCiphertextRecord(record_bytes, keys, from_client, sequence_number);
        defer record.deinit(self.allocator);

        if (record.record_type != zcrypto.tls.record.RecordType.handshake) {
            return Error.ZquicError.ProtocolViolation;
        }

        return self.processPlaintextHandshakeRecordData(record.plaintext);
    }

    fn processPlaintextHandshakeRecordData(self: *Self, data: []const u8) Error.ZquicError!usize {
        var offset: usize = 0;
        var processed: usize = 0;
        while (offset < data.len) {
            if (offset + 4 > data.len) return Error.ZquicError.CryptoError;
            const message_type = data[offset];
            const message_len = (@as(usize, data[offset + 1]) << 16) |
                (@as(usize, data[offset + 2]) << 8) |
                @as(usize, data[offset + 3]);
            offset += 4;

            if (offset + message_len > data.len) return Error.ZquicError.CryptoError;
            try self.processHandshakeMessage(message_type, data[offset .. offset + message_len]);
            offset += message_len;
            processed += 1;
        }

        return processed;
    }

    fn processHandshakeMessageUnchecked(self: *Self, message_type: u8, message: []const u8) !void {
        switch (message_type) {
            1 => try self.processClientHello(message), // ClientHello
            2 => try self.processServerHello(message), // ServerHello
            8 => try self.processEncryptedExtensions(message), // EncryptedExtensions
            11 => try self.processCertificate(message), // Certificate
            15 => try self.processCertificateVerify(message), // CertificateVerify
            20 => try self.processFinished(message), // Finished
            else => return Error.ZquicError.UnsupportedMessage,
        }
    }

    fn validateExpectedHandshakeMessage(self: *const Self, message_type: u8) Error.ZquicError!void {
        const expected: u8 = switch (self.state) {
            .wait_client_hello => 1,
            .initial, .wait_server_hello => if (self.is_server) 1 else 2,
            .wait_encrypted_extensions => 8,
            .wait_certificate => 11,
            .wait_certificate_verify => 15,
            .wait_finished => 20,
            else => return Error.ZquicError.ProtocolViolation,
        };
        if (message_type != expected) return Error.ZquicError.ProtocolViolation;
    }

    /// Process ClientHello message
    fn processClientHello(self: *Self, message: []const u8) !void {
        _ = message;

        if (!self.is_server) {
            return Error.ZquicError.UnexpectedMessage;
        }

        // Parse ClientHello and extract supported cipher suites, extensions, etc.
        // This is simplified - full implementation would parse TLS message format

        self.state = .wait_server_hello;
    }

    /// Process ServerHello message
    fn processServerHello(self: *Self, message: []const u8) !void {
        _ = message;

        if (self.is_server) {
            return Error.ZquicError.UnexpectedMessage;
        }

        // Parse ServerHello and extract selected cipher suite, key share, etc.
        // This is simplified - full implementation would parse TLS message format

        self.state = .wait_encrypted_extensions;
    }

    /// Process EncryptedExtensions message
    fn processEncryptedExtensions(self: *Self, message: []const u8) !void {
        if (self.is_server) {
            return Error.ZquicError.UnexpectedMessage;
        }

        try self.processEncryptedExtensionsList(message);
        self.state = .wait_certificate;
    }

    fn processEncryptedExtensionsList(self: *Self, message: []const u8) !void {
        if (message.len < 2) return Error.ZquicError.CryptoError;
        const extensions_len = (@as(u16, message[0]) << 8) | @as(u16, message[1]);
        if (extensions_len != message.len - 2) return Error.ZquicError.CryptoError;

        var offset: usize = 2;
        var saw_alpn = false;
        var saw_quic_transport_parameters = false;
        while (offset < message.len) {
            if (offset + 4 > message.len) return Error.ZquicError.CryptoError;
            const extension_type = (@as(u16, message[offset]) << 8) | @as(u16, message[offset + 1]);
            const extension_len = (@as(u16, message[offset + 2]) << 8) | @as(u16, message[offset + 3]);
            offset += 4;
            if (offset + extension_len > message.len) return Error.ZquicError.CryptoError;
            const extension_data = message[offset .. offset + extension_len];
            offset += extension_len;

            switch (extension_type) {
                @intFromEnum(TlsExtensionType.application_layer_protocol_negotiation) => {
                    const alpn = try parseSingleAlpnProtocol(extension_data);
                    try validateQuicAlpn(default_quic_alpn, alpn);
                    if (self.negotiated_alpn) |old| self.allocator.free(old);
                    self.negotiated_alpn = try self.allocator.dupe(u8, alpn);
                    saw_alpn = true;
                },
                @intFromEnum(TlsExtensionType.quic_transport_parameters) => {
                    if (extension_data.len == 0) return Error.ZquicError.CryptoError;
                    const owned = self.allocator.dupe(u8, extension_data) catch return Error.ZquicError.OutOfMemory;
                    errdefer self.allocator.free(owned);
                    const params = try CoreTransportParameters.decode(owned);

                    if (self.peer_quic_transport_parameter_bytes) |old| self.allocator.free(old);
                    self.peer_quic_transport_parameter_bytes = owned;
                    self.peer_quic_transport_params = params;
                    saw_quic_transport_parameters = true;
                },
                else => {},
            }
        }

        if (!saw_alpn) return Error.ZquicError.ProtocolViolation;
        if (!saw_quic_transport_parameters) return Error.ZquicError.ProtocolViolation;
    }

    pub fn validatePeerQuicTransportParameters(
        self: *const Self,
        context: CoreTransportParameters.NegotiationContext,
    ) Error.ZquicError!CoreTransportParameters.TransportParameters {
        const params = self.peer_quic_transport_params orelse return Error.ZquicError.ProtocolViolation;
        try CoreTransportParameters.validateForHandshake(params, context);
        return params;
    }

    fn parseSingleAlpnProtocol(data: []const u8) Error.ZquicError![]const u8 {
        if (data.len < 3) return Error.ZquicError.CryptoError;
        const list_len = (@as(u16, data[0]) << 8) | @as(u16, data[1]);
        if (list_len != data.len - 2) return Error.ZquicError.CryptoError;

        const protocol_len = data[2];
        if (protocol_len == 0 or 3 + protocol_len != data.len) {
            return Error.ZquicError.ProtocolViolation;
        }
        return data[3 .. 3 + protocol_len];
    }

    /// Process Certificate message
    fn processCertificate(self: *Self, message: []const u8) !void {
        if (message.len < 3) {
            return Error.ZquicError.CertificateError;
        }

        // Parse certificate chain length (3 bytes)
        const cert_chain_len = (@as(u32, message[0]) << 16) | (@as(u32, message[1]) << 8) | @as(u32, message[2]);

        if (cert_chain_len == 0 or message.len < 3 + cert_chain_len) {
            return Error.ZquicError.CertificateError;
        }

        // Store certificate chain for verification
        if (self.peer_certificate_chain.items.len > 0) {
            for (self.peer_certificate_chain.items) |*cert| {
                cert.deinit();
            }
            self.peer_certificate_chain.clearRetainingCapacity();
        }

        // Parse certificate entries
        var offset: usize = 3;
        while (offset < 3 + cert_chain_len) {
            if (offset + 3 > message.len) break;

            const cert_len = (@as(u32, message[offset]) << 16) | (@as(u32, message[offset + 1]) << 8) | @as(u32, message[offset + 2]);
            offset += 3;

            if (offset + cert_len > message.len) {
                return Error.ZquicError.CertificateError;
            }

            const cert = try Certificate.init(self.allocator, message[offset .. offset + cert_len]);
            try self.peer_certificate_chain.append(self.allocator, cert);
            offset += cert_len;

            // Skip extensions (2 bytes length + data)
            if (offset + 2 > message.len) break;
            const ext_len = (@as(u16, message[offset]) << 8) | @as(u16, message[offset + 1]);
            offset += 2 + ext_len;
        }

        if (self.peer_certificate_chain.items.len == 0) {
            return Error.ZquicError.CertificateError;
        }

        self.state = .wait_certificate_verify;
    }

    fn buildCertificateVerifyInput(self: *const Self, buffer: []u8) Error.ZquicError![]const u8 {
        const context = if (self.is_server)
            "TLS 1.3, client CertificateVerify"
        else
            "TLS 1.3, server CertificateVerify";
        const hash_size = self.cipher_suite.getHashAlgorithm().getHashSize();
        const needed = 64 + context.len + 1 + hash_size;
        if (buffer.len < needed) return Error.ZquicError.BufferTooSmall;

        @memset(buffer[0..64], 0x20);
        @memcpy(buffer[64 .. 64 + context.len], context);
        buffer[64 + context.len] = 0x00;

        const hash_offset = 65 + context.len;
        switch (self.cipher_suite.getHashAlgorithm()) {
            .sha256 => {
                var transcript_hash: [32]u8 = undefined;
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(self.handshake_transcript.items);
                hasher.final(&transcript_hash);
                @memcpy(buffer[hash_offset .. hash_offset + transcript_hash.len], &transcript_hash);
            },
            .sha384 => {
                var transcript_hash: [48]u8 = undefined;
                var hasher = std.crypto.hash.sha2.Sha384.init(.{});
                hasher.update(self.handshake_transcript.items);
                hasher.final(&transcript_hash);
                @memcpy(buffer[hash_offset .. hash_offset + transcript_hash.len], &transcript_hash);
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }

        return buffer[0..needed];
    }

    /// Process CertificateVerify message
    fn processCertificateVerify(self: *Self, message: []const u8) !void {
        if (message.len < 4) {
            return Error.ZquicError.CryptoError;
        }

        // Parse signature algorithm (2 bytes)
        const sig_alg = (@as(u16, message[0]) << 8) | @as(u16, message[1]);

        // Parse signature length (2 bytes)
        const sig_len = (@as(u16, message[2]) << 8) | @as(u16, message[3]);

        if (message.len < 4 + sig_len) {
            return Error.ZquicError.CryptoError;
        }

        const signature = message[4 .. 4 + sig_len];

        var verify_data_buffer: [192]u8 = undefined;
        const verify_data = try self.buildCertificateVerifyInput(&verify_data_buffer);

        // Verify signature based on algorithm
        const verified = switch (sig_alg) {
            0x0804 => blk: { // rsa_pss_rsae_sha256
                // For production, would use actual RSA-PSS verification
                if (!allow_simplified_verification) {
                    return Error.ZquicError.CryptoError;
                }
                break :blk signature.len >= 256; // Basic length check
            },
            0x0403 => blk: { // ecdsa_secp256r1_sha256
                // For production, would use actual ECDSA verification
                if (!allow_simplified_verification) {
                    return Error.ZquicError.CryptoError;
                }
                break :blk signature.len >= 64; // Basic length check
            },
            0x0807 => blk: { // ed25519
                if (self.peer_certificate_chain.items.len == 0) {
                    break :blk false;
                }
                if (signature.len != 64) return Error.ZquicError.CryptoError;
                const cert = &self.peer_certificate_chain.items[0];
                if (cert.encoding != .raw_public_key) return Error.ZquicError.NotSupported;
                break :blk cert.verifyRawPublicKeyAt(signature, verify_data, Time.nowSeconds()) catch |err| switch (err) {
                    Error.ZquicError.NotSupported, Error.ZquicError.UnsupportedAlgorithm => return err,
                    else => return Error.ZquicError.CryptoError,
                };
            },
            else => false,
        };

        if (!verified) {
            return Error.ZquicError.CryptoError;
        }

        self.state = .wait_finished;
    }

    /// Process Finished message - supports both SHA-256 and SHA-384 based on cipher suite
    fn processFinished(self: *Self, message: []const u8) !void {
        const hash_size = self.cipher_suite.getHashAlgorithm().getHashSize();
        if (message.len < hash_size) {
            return Error.ZquicError.CryptoError;
        }

        // Get the handshake secret for computing finished key
        const handshake_keys = self.handshake_keys orelse return Error.ZquicError.CryptoError;
        const handshake_secret = handshake_keys.secret;
        if (handshake_secret.len < hash_size) return Error.ZquicError.CryptoError;

        // Build HKDF label: length (2) + "tls13 " + label + context
        const label = "tls13 finished";
        var hkdf_label: [64]u8 = undefined;
        hkdf_label[0] = 0;
        hkdf_label[1] = @intCast(hash_size);
        hkdf_label[2] = @intCast(label.len);
        @memcpy(hkdf_label[3 .. 3 + label.len], label);
        hkdf_label[3 + label.len] = 0; // Empty context

        // Compute based on hash algorithm
        switch (self.cipher_suite.getHashAlgorithm()) {
            .sha256 => {
                // SHA-256 path
                var finished_key: [32]u8 = undefined;
                var secret_array: [32]u8 = undefined;
                @memcpy(&secret_array, handshake_secret[0..32]);
                var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&secret_array);
                hmac.update(hkdf_label[0 .. 4 + label.len]);
                hmac.update(&[_]u8{1});
                hmac.final(&finished_key);

                var transcript_hash: [32]u8 = undefined;
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});
                hasher.update(self.handshake_transcript.items);
                hasher.final(&transcript_hash);

                var expected_verify_data: [32]u8 = undefined;
                var verify_hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&finished_key);
                verify_hmac.update(&transcript_hash);
                verify_hmac.final(&expected_verify_data);

                if (!std.crypto.timing_safe.eql([32]u8, message[0..32].*, expected_verify_data)) {
                    return Error.ZquicError.CryptoError;
                }
                std.crypto.secureZero(u8, &finished_key);
            },
            .sha384 => {
                // SHA-384 path
                var finished_key: [48]u8 = undefined;
                var secret_array: [48]u8 = undefined;
                @memcpy(&secret_array, handshake_secret[0..48]);
                var hmac = std.crypto.auth.hmac.sha2.HmacSha384.init(&secret_array);
                hmac.update(hkdf_label[0 .. 4 + label.len]);
                hmac.update(&[_]u8{1});
                hmac.final(&finished_key);

                var transcript_hash: [48]u8 = undefined;
                var hasher = std.crypto.hash.sha2.Sha384.init(.{});
                hasher.update(self.handshake_transcript.items);
                hasher.final(&transcript_hash);

                var expected_verify_data: [48]u8 = undefined;
                var verify_hmac = std.crypto.auth.hmac.sha2.HmacSha384.init(&finished_key);
                verify_hmac.update(&transcript_hash);
                verify_hmac.final(&expected_verify_data);

                if (!std.crypto.timing_safe.eql([48]u8, message[0..48].*, expected_verify_data)) {
                    return Error.ZquicError.CryptoError;
                }
                std.crypto.secureZero(u8, &finished_key);
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }

        self.state = .connected;
    }

    /// Generate session ticket for 0-RTT
    /// Format: random_state (32 bytes) || MAC (32 bytes)
    pub fn generateSessionTicket(self: *Self) !SessionTicket {
        const shared = self.shared_secret orelse return Error.ZquicError.InvalidState;

        // Generate random ticket state
        var ticket_state: [32]u8 = undefined;
        zcrypto.rand.fill(&ticket_state);

        // Compute MAC over the ticket state using shared secret as key
        var mac: [32]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(shared);
        hmac.update(&ticket_state);
        hmac.final(&mac);

        // Combine state and MAC: ticket_state || MAC
        const ticket_data = try self.allocator.alloc(u8, 64);
        @memcpy(ticket_data[0..32], &ticket_state);
        @memcpy(ticket_data[32..64], &mac);

        // Derive resumption secret
        const resumption_secret = try zcrypto.kdf.hkdfExpandLabel(self.allocator, shared, "resumption", "", 32);
        defer self.allocator.free(resumption_secret);

        const ticket = try SessionTicket.init(self.allocator, ticket_data, resumption_secret, self.cipher_suite);
        self.allocator.free(ticket_data);
        return ticket;
    }

    /// Validate session ticket for 0-RTT
    pub fn validateSessionTicket(self: *Self, ticket: SessionTicket) !bool {
        // Check basic validity (expiry, structure)
        if (!ticket.isValid()) {
            return false;
        }

        // Verify ticket authenticity using HMAC
        // The ticket should contain: encrypted_state || mac
        const ticket_data = ticket.ticket;

        if (ticket_data.len < 32) {
            return false; // Too short to contain MAC
        }

        // Extract MAC from end of ticket
        const mac_offset = ticket_data.len - 32;
        const encrypted_state = ticket_data[0..mac_offset];
        const provided_mac = ticket_data[mac_offset..][0..32];

        // Compute expected MAC using shared secret as key
        const shared_secret = self.shared_secret orelse {
            // No shared secret available for verification
            if (!allow_simplified_verification) {
                return false;
            }
            return true; // Allow in test mode
        };

        var expected_mac: [32]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(shared_secret);
        hmac.update(encrypted_state);
        hmac.final(&expected_mac);

        // Constant-time comparison
        if (!std.crypto.timing_safe.eql([32]u8, provided_mac.*, expected_mac)) {
            return false;
        }

        // Verify ticket hasn't been replayed (would need anti-replay window)
        // For now, basic expiry check is done by isValid()

        return true;
    }

    /// Get current encryption level
    pub fn getCurrentEncryptionLevel(self: *const Self) u8 {
        return switch (self.state) {
            .initial => 0, // Initial
            .wait_client_hello, .wait_server_hello => 0, // Initial
            .wait_encrypted_extensions, .wait_certificate, .wait_certificate_verify, .wait_finished => 2, // Handshake
            .connected => 3, // Application
            .wait_early_data, .early_data_accepted => 1, // 0-RTT
            else => 0,
        };
    }

    /// Check if ready for 0-RTT
    pub fn canSendEarlyData(self: *const Self) bool {
        return self.session_ticket != null and self.zero_rtt_keys != null;
    }

    /// Check if connection is established
    pub fn isConnected(self: *const Self) bool {
        return self.state == .connected;
    }
};

/// TLS 1.3 message types
pub const TlsMessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

/// TLS 1.3 extension types
pub const TlsExtensionType = enum(u16) {
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type = 20,
    padding = 21,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,

    // QUIC transport parameters
    quic_transport_parameters = 57,

    // Post-quantum extensions
    post_quantum_key_share = 0xFE00,
    hybrid_key_share = 0xFE01,
};

test "comprehensive TLS exposes experimental maturity markers" {
    try std.testing.expectEqualStrings("experimental-scaffold", maturity_status);
    try std.testing.expect(!supports_production_tls);
    try std.testing.expect(!supports_x509_certificate_validation);
    try std.testing.expect(supports_delegated_x509_validation);
    try std.testing.expect(supports_raw_public_key_verification);
    try std.testing.expect(!allow_simplified_verification);
}

test "TLS record parser delegates to zcrypto and fails closed on malformed records" {
    const fixture = @embedFile("../../tests/fixtures/tls/record-handshake.json");
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"record_hex\": \"16030300020102\"") != null);

    const valid = [_]u8{
        0x16, 0x03, 0x03, 0x00, 0x02,
        0x01, 0x02,
    };
    var record = try parseTlsCiphertextRecord(std.testing.allocator, &valid);
    defer record.deinit();
    try std.testing.expectEqual(zcrypto.tls.record.RecordType.handshake, record.header.record_type);
    try std.testing.expectEqual(@as(u16, 2), record.header.length);
    try std.testing.expectEqualStrings("\x01\x02", record.encrypted_data);

    const bad_version = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x00 };
    try std.testing.expectError(Error.ZquicError.CryptoError, parseTlsCiphertextRecord(std.testing.allocator, &bad_version));

    const bad_length = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x04, 0x01 };
    try std.testing.expectError(Error.ZquicError.CryptoError, parseTlsCiphertextRecord(std.testing.allocator, &bad_length));
}

test "TLS record adapter feeds plaintext handshake messages into state machine" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();

    const client_hello_record = [_]u8{
        0x16, 0x03, 0x03, 0x00, 0x04,
        0x01, 0x00, 0x00, 0x00,
    };

    try std.testing.expectEqual(@as(usize, 1), try tls.processTlsCiphertextRecord(&client_hello_record));
    try std.testing.expectEqual(HandshakeState.wait_server_hello, tls.state);
    try std.testing.expectEqual(@as(usize, 4), tls.handshake_transcript.items.len);

    const malformed_message = [_]u8{
        0x16, 0x03, 0x03, 0x00, 0x04,
        0x01, 0x00, 0x00, 0x01,
    };
    try std.testing.expectError(Error.ZquicError.CryptoError, tls.processTlsCiphertextRecord(&malformed_message));

    const alert_record = [_]u8{
        0x15, 0x03, 0x03, 0x00, 0x02,
        0x02, 0x28,
    };
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, tls.processTlsCiphertextRecord(&alert_record));
}

fn makeEncryptedTlsRecordForTest(
    allocator: std.mem.Allocator,
    keys: *const CryptoKeys,
    from_client: bool,
    sequence_number: u64,
    inner_record_type: u8,
    plaintext: []const u8,
    padding_len: usize,
) Error.ZquicError![]u8 {
    const inner = allocator.alloc(u8, plaintext.len + 1 + padding_len) catch return Error.ZquicError.OutOfMemory;
    defer allocator.free(inner);
    @memcpy(inner[0..plaintext.len], plaintext);
    inner[plaintext.len] = inner_record_type;
    @memset(inner[plaintext.len + 1 ..], 0);

    const ciphertext_len = inner.len + 16;
    const record = allocator.alloc(u8, 5 + ciphertext_len) catch return Error.ZquicError.OutOfMemory;
    errdefer allocator.free(record);

    record[0] = @intFromEnum(zcrypto.tls.record.RecordType.application_data);
    record[1] = 0x03;
    record[2] = 0x03;
    std.mem.writeInt(u16, record[3..][0..2], @intCast(ciphertext_len), .big);

    const key = if (from_client) keys.client_write_key else keys.server_write_key;
    const iv = if (from_client) keys.client_write_iv else keys.server_write_iv;

    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, iv[0..12]);
    var sequence_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_bytes, sequence_number, .big);
    for (0..8) |i| {
        nonce[4 + i] ^= sequence_bytes[i];
    }

    const encrypted_content = record[5 .. 5 + inner.len];
    const tag_bytes = record[5 + inner.len ..][0..16];
    var tag: [16]u8 = undefined;

    switch (keys.cipher_suite) {
        .tls_aes_128_gcm_sha256 => {
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                encrypted_content,
                &tag,
                inner,
                record[0..5],
                nonce,
                key[0..16].*,
            );
        },
        .tls_aes_256_gcm_sha384 => {
            std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                encrypted_content,
                &tag,
                inner,
                record[0..5],
                nonce,
                key[0..32].*,
            );
        },
        .tls_chacha20_poly1305_sha256 => {
            std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                encrypted_content,
                &tag,
                inner,
                record[0..5],
                nonce,
                key[0..32].*,
            );
        },
        else => return Error.ZquicError.UnsupportedAlgorithm,
    }

    @memcpy(tag_bytes, &tag);
    return record;
}

test "encrypted TLS record deprotection verifies tag and strips inner padding" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();

    var keys = try CryptoKeys.init(std.testing.allocator, .tls_aes_128_gcm_sha256);
    defer keys.deinit();
    @memset(keys.client_write_key, 0x11);
    @memset(keys.client_write_iv, 0x22);

    const handshake_message = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const record = try makeEncryptedTlsRecordForTest(
        std.testing.allocator,
        &keys,
        true,
        7,
        @intFromEnum(zcrypto.tls.record.RecordType.handshake),
        &handshake_message,
        3,
    );
    defer std.testing.allocator.free(record);

    var deprotected = try tls.decryptTlsCiphertextRecord(record, &keys, true, 7);
    defer deprotected.deinit(std.testing.allocator);
    try std.testing.expectEqual(zcrypto.tls.record.RecordType.handshake, deprotected.record_type);
    try std.testing.expectEqualSlices(u8, &handshake_message, deprotected.plaintext);

    const processed = try tls.processEncryptedTlsCiphertextRecord(record, &keys, true, 7);
    try std.testing.expectEqual(@as(usize, 1), processed);
    try std.testing.expectEqual(HandshakeState.wait_server_hello, tls.state);
}

test "encrypted TLS record deprotection rejects tampering and invalid inner type" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();

    var keys = try CryptoKeys.init(std.testing.allocator, .tls_aes_128_gcm_sha256);
    defer keys.deinit();
    @memset(keys.client_write_key, 0x33);
    @memset(keys.client_write_iv, 0x44);

    const handshake_message = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const record = try makeEncryptedTlsRecordForTest(
        std.testing.allocator,
        &keys,
        true,
        3,
        @intFromEnum(zcrypto.tls.record.RecordType.handshake),
        &handshake_message,
        0,
    );
    defer std.testing.allocator.free(record);

    record[record.len - 1] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        tls.decryptTlsCiphertextRecord(record, &keys, true, 3),
    );
    record[record.len - 1] ^= 0x01;

    const invalid_inner = try makeEncryptedTlsRecordForTest(
        std.testing.allocator,
        &keys,
        true,
        4,
        0x19,
        &handshake_message,
        0,
    );
    defer std.testing.allocator.free(invalid_inner);
    try std.testing.expectError(
        Error.ZquicError.ProtocolViolation,
        tls.decryptTlsCiphertextRecord(invalid_inner, &keys, true, 4),
    );
}

test "delegated X.509 verification fails closed without trust anchors or valid DER" {
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        verifyX509CertificateWithRoots(std.testing.allocator, "not der", "example.test", &.{}),
    );

    const fake_root = [_][]const u8{"not a root"};
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        verifyX509CertificateWithRoots(std.testing.allocator, "not der", "example.test", &fake_root),
    );
}

test "raw Ed25519 certificate verifies caller supplied public key and validity" {
    const key_pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
    const message = "certificate-bound handshake message";
    const signature = try key_pair.sign(message, null);

    const cert = try Certificate.initRawEd25519PublicKey(
        std.testing.allocator,
        &key_pair.public_key.bytes,
        "example.test",
        "example.test",
        1_000,
        2_000,
    );
    defer cert.deinit();

    try std.testing.expect(try cert.verifyRawPublicKeyAt(&signature.toBytes(), message, 1_500));
    try std.testing.expect(!try cert.verifyRawPublicKeyAt(&signature.toBytes(), message, 2_001));
    try std.testing.expect(!try cert.verifyRawPublicKeyAt(&signature.toBytes(), "wrong message", 1_500));
}

test "DER certificate verification fails closed until X.509 parser exists" {
    var cert = try Certificate.init(std.testing.allocator, "fake der");
    defer cert.deinit();

    const signature = std.mem.zeroes([64]u8);
    try std.testing.expectError(
        Error.ZquicError.NotSupported,
        cert.verifyRawPublicKeyAt(&signature, "message", 1),
    );
    try std.testing.expectError(
        Error.ZquicError.NotSupported,
        cert.verify(&signature, "message"),
    );
}

test "certificate validation policy fails closed outside explicit test bypass" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();

    try tls.validatePeerCertificatePolicy(.testInsecure());
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        tls.validatePeerCertificatePolicy(.production("example.test")),
    );
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        tls.validatePeerCertificatePolicy(.rawPublicKey(1_500)),
    );

    const key_pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
    const raw_cert = try Certificate.initRawEd25519PublicKey(
        std.testing.allocator,
        &key_pair.public_key.bytes,
        "example.test",
        "example.test",
        1_000,
        2_000,
    );
    try tls.peer_certificate_chain.append(std.testing.allocator, raw_cert);

    try tls.validatePeerCertificatePolicy(.rawPublicKey(1_500));
    try tls.validatePeerCertificatePolicy(.rawPublicKeyForHost("EXAMPLE.TEST", 1_500));
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        tls.validatePeerCertificatePolicy(.rawPublicKey(2_001)),
    );
    try std.testing.expectError(
        Error.ZquicError.CertificateError,
        tls.validatePeerCertificatePolicy(.rawPublicKeyForHost("wrong.example", 1_500)),
    );
    try std.testing.expectError(
        Error.ZquicError.NotSupported,
        tls.validatePeerCertificatePolicy(.production("example.test")),
    );
}

test "negative QUIC TLS validation rejects wrong ALPN and unsupported cipher suites" {
    try validateQuicAlpn(default_quic_alpn, "h3");
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, validateQuicAlpn(default_quic_alpn, "hq-29"));
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, validateQuicAlpn(default_quic_alpn, ""));

    try validateQuicCipherSuite(.tls_aes_128_gcm_sha256);
    try validateQuicCipherSuite(.tls_aes_256_gcm_sha384);
    try validateQuicCipherSuite(.tls_chacha20_poly1305_sha256);
    try std.testing.expectError(Error.ZquicError.UnsupportedAlgorithm, validateQuicCipherSuite(.tls_aes_128_ccm_sha256));
    try std.testing.expectError(Error.ZquicError.UnsupportedAlgorithm, validateQuicCipherSuite(.tls_ml_kem_768_aes_128_gcm_sha256));
}

test "negative handshake rejects out of order messages without transcript mutation" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, true);
    defer tls.deinit();
    try tls.initServer(&.{});

    try std.testing.expectEqual(HandshakeState.wait_client_hello, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);
    try std.testing.expectError(
        Error.ZquicError.ProtocolViolation,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.server_hello), "server hello"),
    );
    try std.testing.expectEqual(HandshakeState.wait_client_hello, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);
}

test "EncryptedExtensions validates h3 ALPN, requires QUIC parameters, and records negotiated protocol" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_encrypted_extensions;

    var tp_buf: [256]u8 = undefined;
    var tp_writer = std.Io.Writer.fixed(&tp_buf);
    try CoreTransportParameters.encode(.{}, &tp_writer);
    const tp_bytes = std.Io.Writer.buffered(&tp_writer);

    const alpn_ext = [_]u8{
        0x00, 0x10, // application_layer_protocol_negotiation
        0x00, 0x05, // extension data length
        0x00, 0x03, // ALPN list length
        0x02, 'h',
        '3',
    };
    const extensions_len: u16 = @intCast(alpn_ext.len + 4 + tp_bytes.len);

    var ee_buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&ee_buf);
    try writer.writeInt(u16, extensions_len, .big);
    try writer.writeAll(&alpn_ext);
    try writer.writeInt(u16, @intFromEnum(TlsExtensionType.quic_transport_parameters), .big);
    try writer.writeInt(u16, @intCast(tp_bytes.len), .big);
    try writer.writeAll(tp_bytes);
    const encrypted_extensions = std.Io.Writer.buffered(&writer);

    try tls.processHandshakeMessage(@intFromEnum(TlsMessageType.encrypted_extensions), encrypted_extensions);
    try std.testing.expectEqual(HandshakeState.wait_certificate, tls.state);
    try std.testing.expectEqualStrings(default_quic_alpn, tls.negotiated_alpn.?);
    try std.testing.expect(tls.peer_quic_transport_params != null);
}

test "EncryptedExtensions decodes and retains QUIC transport parameters" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_encrypted_extensions;

    var tp_buf: [256]u8 = undefined;
    var tp_writer = std.Io.Writer.fixed(&tp_buf);
    const expected_params = CoreTransportParameters.TransportParameters{
        .max_idle_timeout = 12_345,
        .initial_max_data = 65_536,
        .initial_max_streams_bidi = 8,
        .active_connection_id_limit = 4,
        .disable_active_migration = true,
    };
    try CoreTransportParameters.encode(expected_params, &tp_writer);
    const tp_bytes = std.Io.Writer.buffered(&tp_writer);

    const alpn_ext = [_]u8{
        0x00, 0x10,
        0x00, 0x05,
        0x00, 0x03,
        0x02, 'h',
        '3',
    };
    const extensions_len: u16 = @intCast(alpn_ext.len + 4 + tp_bytes.len);

    var ee_buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&ee_buf);
    try writer.writeInt(u16, extensions_len, .big);
    try writer.writeAll(&alpn_ext);
    try writer.writeInt(u16, @intFromEnum(TlsExtensionType.quic_transport_parameters), .big);
    try writer.writeInt(u16, @intCast(tp_bytes.len), .big);
    try writer.writeAll(tp_bytes);
    const encrypted_extensions = std.Io.Writer.buffered(&writer);

    try tls.processHandshakeMessage(@intFromEnum(TlsMessageType.encrypted_extensions), encrypted_extensions);
    try std.testing.expectEqual(HandshakeState.wait_certificate, tls.state);
    try std.testing.expectEqualStrings(default_quic_alpn, tls.negotiated_alpn.?);
    try std.testing.expect(tls.peer_quic_transport_parameter_bytes != null);
    const decoded = tls.peer_quic_transport_params.?;
    try std.testing.expectEqual(@as(u64, 12_345), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 65_536), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 8), decoded.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 4), decoded.active_connection_id_limit);
    try std.testing.expect(decoded.disable_active_migration);

    const validated = try tls.validatePeerQuicTransportParameters(.{ .peer_role = .client });
    try std.testing.expectEqual(@as(u64, 12_345), validated.max_idle_timeout);
}

test "EncryptedExtensions rejects missing or wrong ALPN without transcript mutation" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_encrypted_extensions;

    const wrong_alpn = [_]u8{
        0x00, 0x09,
        0x00, 0x10,
        0x00, 0x05,
        0x00, 0x03,
        0x02, 'h',
        'q',
    };

    try std.testing.expectError(
        Error.ZquicError.ProtocolViolation,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.encrypted_extensions), &wrong_alpn),
    );
    try std.testing.expectEqual(HandshakeState.wait_encrypted_extensions, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);

    const missing_alpn = [_]u8{ 0x00, 0x00 };
    try std.testing.expectError(
        Error.ZquicError.ProtocolViolation,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.encrypted_extensions), &missing_alpn),
    );
}

test "EncryptedExtensions rejects missing QUIC transport parameters without transcript mutation" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_encrypted_extensions;

    const alpn_only = [_]u8{
        0x00, 0x09,
        0x00, 0x10,
        0x00, 0x05,
        0x00, 0x03,
        0x02, 'h',
        '3',
    };

    try std.testing.expectError(
        Error.ZquicError.ProtocolViolation,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.encrypted_extensions), &alpn_only),
    );
    try std.testing.expectEqual(HandshakeState.wait_encrypted_extensions, tls.state);
    try std.testing.expectEqual(@as(usize, 0), tls.handshake_transcript.items.len);
}

test "negative handshake transcript mismatch rejects Finished and preserves transcript" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_finished;

    var handshake_keys = try CryptoKeys.init(std.testing.allocator, .tls_aes_128_gcm_sha256);
    const traffic_secret: [32]u8 = @splat(0x42);
    try handshake_keys.deriveFromTrafficSecret(&traffic_secret, false);
    tls.handshake_keys = handshake_keys;

    try tls.handshake_transcript.appendSlice(std.testing.allocator, "accepted transcript");
    const original_len = tls.handshake_transcript.items.len;

    const bad_finished: [32]u8 = @splat(0x11);
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.finished), &bad_finished),
    );
    try std.testing.expectEqual(HandshakeState.wait_finished, tls.state);
    try std.testing.expectEqual(original_len, tls.handshake_transcript.items.len);
}

test "negative CertificateVerify fails closed for forged raw public key signature" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_certificate_verify;

    const key_pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
    const cert = try Certificate.initRawEd25519PublicKey(
        std.testing.allocator,
        &key_pair.public_key.bytes,
        "example.test",
        "example.test",
        1_000,
        2_000,
    );
    try tls.peer_certificate_chain.append(std.testing.allocator, cert);

    var message: [68]u8 = undefined;
    message[0] = 0x08;
    message[1] = 0x07;
    message[2] = 0;
    message[3] = 64;
    @memset(message[4..], 0xaa);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        tls.processHandshakeMessage(@intFromEnum(TlsMessageType.certificate_verify), &message),
    );
    try std.testing.expectEqual(HandshakeState.wait_certificate_verify, tls.state);
}

test "raw Ed25519 CertificateVerify advances handshake with transcript-bound signature" {
    const fixture = @embedFile("../../tests/fixtures/tls/certificate-verify-ed25519.json");
    const expected_verify_input_hex = "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c2073657276657220436572746966696361746556657269667900691e101c9e9763255a33e2da573a8a2f95d5af781589f6c30da25781187cf68d";
    try std.testing.expect(std.mem.indexOf(u8, fixture, expected_verify_input_hex) != null);

    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    tls.state = .wait_certificate_verify;
    try tls.handshake_transcript.appendSlice(std.testing.allocator, "server hello transcript");

    const key_pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
    const now = Time.nowSeconds();
    const cert = try Certificate.initRawEd25519PublicKey(
        std.testing.allocator,
        &key_pair.public_key.bytes,
        "example.test",
        "example.test",
        now - 10,
        now + 60,
    );
    try tls.peer_certificate_chain.append(std.testing.allocator, cert);

    var verify_input_buffer: [192]u8 = undefined;
    const verify_input = try tls.buildCertificateVerifyInput(&verify_input_buffer);
    var expected_verify_input: [130]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_verify_input, expected_verify_input_hex);
    try std.testing.expectEqualSlices(u8, &expected_verify_input, verify_input);

    const signature = try key_pair.sign(verify_input, null);
    const signature_bytes = signature.toBytes();

    var message: [68]u8 = undefined;
    message[0] = 0x08;
    message[1] = 0x07;
    message[2] = 0;
    message[3] = 64;
    @memcpy(message[4..], &signature_bytes);

    try tls.processHandshakeMessage(@intFromEnum(TlsMessageType.certificate_verify), &message);
    try std.testing.expectEqual(HandshakeState.wait_finished, tls.state);
}

test "negative session ticket MAC tampering fails closed" {
    var tls = ComprehensiveTlsContext.init(std.testing.allocator, false);
    defer tls.deinit();
    const shared_secret: [32]u8 = @splat(0x44);
    tls.shared_secret = try std.testing.allocator.dupe(u8, &shared_secret);

    var ticket = try tls.generateSessionTicket();
    defer ticket.deinit();
    try std.testing.expect(try tls.validateSessionTicket(ticket));

    const writable_ticket: []u8 = @constCast(ticket.ticket);
    writable_ticket[writable_ticket.len - 1] ^= 0x01;
    try std.testing.expect(!try tls.validateSessionTicket(ticket));
}

test "negative transport parameters reject bad handshake inputs" {
    const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const server_initial_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };

    const bad_active_cid_limit = CoreTransportParameters.TransportParameters{
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
        .active_connection_id_limit = 1,
    };
    try std.testing.expectError(Error.ZquicError.InvalidArgument, CoreTransportParameters.validateForHandshake(bad_active_cid_limit, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    }));

    const mismatched_original_dcid = CoreTransportParameters.TransportParameters{
        .original_destination_connection_id = &[_]u8{ 0xca, 0xfe },
        .initial_source_connection_id = &server_initial_scid,
    };
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, CoreTransportParameters.validateForHandshake(mismatched_original_dcid, .{
        .peer_role = .server,
        .original_destination_connection_id = &original_dcid,
        .initial_source_connection_id = &server_initial_scid,
    }));
}
