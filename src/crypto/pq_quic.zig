//! Post-Quantum QUIC Implementation
//!
//! Provides post-quantum key exchange for QUIC handshakes using zcrypto
//! Implements hybrid classical + post-quantum cryptography with hardware acceleration
//!
//! IMPORTANT: This module requires -Dpost-quantum=true -Dexperimental-crypto=true

const std = @import("std");
const build_options = @import("build_options");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const EnhancedTlsContext = @import("enhanced_tls.zig").EnhancedTlsContext;

// Compile-time check for post-quantum support
comptime {
    if (!build_options.enable_post_quantum or !build_options.enable_experimental_crypto) {
        @compileError("pq_quic.zig requires -Dpost-quantum=true -Dexperimental-crypto=true");
    }
}

// Utility function for secure memory zeroing - uses std library implementation
fn secureZero(data: []u8) void {
    std.crypto.secureZero(u8, data);
}

// Import zcrypto post-quantum modules (ML-KEM and ML-DSA)
const MLKEMResult = struct {
    ciphertext: []u8,
    shared_secret: []u8,
};

/// Post-quantum key exchange using zcrypto ML-KEM
const PostQuantum = struct {
    const MLKEMKeyExchange = struct {
        const ML_KEM_768 = zcrypto.post_quantum.pq.ml_kem.ML_KEM_768;
        const ML_KEM_1024 = zcrypto.post_quantum.pq.ml_kem.ML_KEM_1024;

        /// ML-KEM variant selection
        pub const Variant = enum {
            ml_kem_768,
            ml_kem_1024,
        };

        pub fn generateKeyPair(allocator: std.mem.Allocator, variant: Variant) !KeyPair {
            // Generate random seed for key generation using zcrypto's secure RNG
            var seed: [32]u8 = undefined;
            zcrypto.rand.fill(&seed);

            return switch (variant) {
                .ml_kem_768 => {
                    const keypair = ML_KEM_768.KeyPair.generate(seed) catch {
                        return Error.ZquicError.CryptoError;
                    };
                    return .{
                        .public_key = try allocator.dupe(u8, &keypair.public_key),
                        .secret_key = try allocator.dupe(u8, &keypair.private_key),
                    };
                },
                .ml_kem_1024 => {
                    const keypair = ML_KEM_1024.KeyPair.generate(seed) catch {
                        return Error.ZquicError.CryptoError;
                    };
                    return .{
                        .public_key = try allocator.dupe(u8, &keypair.public_key),
                        .secret_key = try allocator.dupe(u8, &keypair.private_key),
                    };
                },
            };
        }

        pub fn encapsulate768(allocator: std.mem.Allocator, public_key: []const u8) !MLKEMResult {
            if (public_key.len != ML_KEM_768.PUBLIC_KEY_SIZE) {
                return Error.ZquicError.CryptoError;
            }

            var pk_array: [ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
            @memcpy(&pk_array, public_key[0..ML_KEM_768.PUBLIC_KEY_SIZE]);

            var randomness: [ML_KEM_768.SEED_SIZE]u8 = undefined;
            zcrypto.rand.fill(&randomness);

            const result = ML_KEM_768.KeyPair.encapsulate(pk_array, randomness) catch {
                return Error.ZquicError.CryptoError;
            };

            return .{
                .ciphertext = try allocator.dupe(u8, &result.ciphertext),
                .shared_secret = try allocator.dupe(u8, &result.shared_secret),
            };
        }

        pub fn encapsulate1024(allocator: std.mem.Allocator, public_key: []const u8) !MLKEMResult {
            if (public_key.len != ML_KEM_1024.PUBLIC_KEY_SIZE) {
                return Error.ZquicError.CryptoError;
            }

            var pk_array: [ML_KEM_1024.PUBLIC_KEY_SIZE]u8 = undefined;
            @memcpy(&pk_array, public_key[0..ML_KEM_1024.PUBLIC_KEY_SIZE]);

            var randomness: [ML_KEM_1024.SEED_SIZE]u8 = undefined;
            zcrypto.rand.fill(&randomness);

            const result = ML_KEM_1024.KeyPair.encapsulate(pk_array, randomness) catch {
                return Error.ZquicError.CryptoError;
            };

            return .{
                .ciphertext = try allocator.dupe(u8, &result.ciphertext),
                .shared_secret = try allocator.dupe(u8, &result.shared_secret),
            };
        }

        pub fn decapsulate768(allocator: std.mem.Allocator, secret_key: []const u8, ciphertext: []const u8) ![]u8 {
            if (secret_key.len != ML_KEM_768.PRIVATE_KEY_SIZE or
                ciphertext.len != ML_KEM_768.CIPHERTEXT_SIZE)
            {
                return Error.ZquicError.CryptoError;
            }

            var keypair: ML_KEM_768.KeyPair = undefined;
            @memcpy(&keypair.private_key, secret_key[0..ML_KEM_768.PRIVATE_KEY_SIZE]);

            var ct_array: [ML_KEM_768.CIPHERTEXT_SIZE]u8 = undefined;
            @memcpy(&ct_array, ciphertext[0..ML_KEM_768.CIPHERTEXT_SIZE]);

            const shared_secret = keypair.decapsulate(ct_array) catch {
                return Error.ZquicError.CryptoError;
            };

            return try allocator.dupe(u8, &shared_secret);
        }

        pub fn decapsulate1024(allocator: std.mem.Allocator, secret_key: []const u8, ciphertext: []const u8) ![]u8 {
            if (secret_key.len != ML_KEM_1024.PRIVATE_KEY_SIZE or
                ciphertext.len != ML_KEM_1024.CIPHERTEXT_SIZE)
            {
                return Error.ZquicError.CryptoError;
            }

            var keypair: ML_KEM_1024.KeyPair = undefined;
            @memcpy(&keypair.private_key, secret_key[0..ML_KEM_1024.PRIVATE_KEY_SIZE]);

            var ct_array: [ML_KEM_1024.CIPHERTEXT_SIZE]u8 = undefined;
            @memcpy(&ct_array, ciphertext[0..ML_KEM_1024.CIPHERTEXT_SIZE]);

            const shared_secret = keypair.decapsulate(ct_array) catch {
                return Error.ZquicError.CryptoError;
            };

            return try allocator.dupe(u8, &shared_secret);
        }

        /// Legacy encapsulate that auto-detects variant from public key size
        pub fn encapsulate(allocator: std.mem.Allocator, public_key: []const u8) !MLKEMResult {
            if (public_key.len == ML_KEM_768.PUBLIC_KEY_SIZE) {
                return encapsulate768(allocator, public_key);
            } else if (public_key.len == ML_KEM_1024.PUBLIC_KEY_SIZE) {
                return encapsulate1024(allocator, public_key);
            } else {
                return Error.ZquicError.CryptoError;
            }
        }

        /// Legacy decapsulate that auto-detects variant from key sizes
        pub fn decapsulate(allocator: std.mem.Allocator, secret_key: []const u8, ciphertext: []const u8) ![]u8 {
            if (secret_key.len == ML_KEM_768.PRIVATE_KEY_SIZE) {
                return decapsulate768(allocator, secret_key, ciphertext);
            } else if (secret_key.len == ML_KEM_1024.PRIVATE_KEY_SIZE) {
                return decapsulate1024(allocator, secret_key, ciphertext);
            } else {
                return Error.ZquicError.CryptoError;
            }
        }
    };
};

const KeyPair = struct {
    public_key: []u8,
    secret_key: []u8,
};

const KeyExchange = struct {
    /// X25519 key exchange using zcrypto.kex
    const X25519KeyExchange = struct {
        pub fn generateKeyPair(allocator: std.mem.Allocator) !KeyPair {
            const keypair = zcrypto.kex.X25519.generateKeypair() catch {
                return Error.ZquicError.CryptoError;
            };
            return .{
                .public_key = try allocator.dupe(u8, &keypair.public_key),
                .secret_key = try allocator.dupe(u8, &keypair.private_key),
            };
        }

        pub fn deriveSharedSecret(allocator: std.mem.Allocator, secret_key: []const u8, public_key: []const u8) ![]u8 {
            if (secret_key.len != 32 or public_key.len != 32) {
                return Error.ZquicError.CryptoError;
            }
            var sk: [32]u8 = undefined;
            var pk: [32]u8 = undefined;
            @memcpy(&sk, secret_key[0..32]);
            @memcpy(&pk, public_key[0..32]);

            const shared = zcrypto.kex.X25519.computeSharedSecret(sk, pk) catch {
                return Error.ZquicError.CryptoError;
            };
            // Allocate heap memory - caller owns and must free
            const result = try allocator.alloc(u8, 32);
            @memcpy(result, &shared);
            return result;
        }
    };
};

const HardwareCrypto = struct {
    const Capabilities = struct {
        has_aes_ni: bool = false,
        has_avx2: bool = false,
    };

    pub fn detectCapabilities() Capabilities {
        return .{};
    }
};

const ZKP = struct {
    const Bulletproofs = struct {
        pub fn generateRangeProof(allocator: std.mem.Allocator, value: u64, min: u64, max: u64) ![]u8 {
            _ = value;
            _ = min;
            _ = max;
            const fill = blk: {
                var bytes = std.mem.zeroes([256]u8);
                @memset(bytes[0..], 12);
                break :blk bytes;
            };
            return try allocator.dupe(u8, &fill);
        }

        pub fn verifyRangeProof(allocator: std.mem.Allocator, proof: []const u8, value: u64) !bool {
            _ = allocator;
            _ = proof;
            _ = value;
            return true;
        }
    };
};

/// Post-Quantum cipher suites for QUIC
pub const PQCipherSuite = enum {
    /// ML-KEM-768 + X25519 hybrid (recommended)
    ml_kem_768_x25519_sha256,
    /// ML-KEM-1024 + X25519 hybrid with SHA-384 (higher PQ security, same classical)
    ml_kem_1024_x25519_sha384,
    /// Pure ML-KEM-768 (post-quantum only)
    ml_kem_768_sha256,
    pub fn getKemAlgorithm(self: @This()) []const u8 {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => "ml_kem_768",
            .ml_kem_1024_x25519_sha384 => "ml_kem_1024",
        };
    }

    pub fn getKemVariant(self: @This()) PostQuantum.MLKEMKeyExchange.Variant {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => .ml_kem_768,
            .ml_kem_1024_x25519_sha384 => .ml_kem_1024,
        };
    }

    pub fn isHybrid(self: @This()) bool {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_1024_x25519_sha384 => true,
            .ml_kem_768_sha256 => false,
        };
    }

    pub fn getClassicalAlgorithm(self: @This()) ?[]const u8 {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_1024_x25519_sha384 => "x25519",
            .ml_kem_768_sha256 => null,
        };
    }

    pub fn id(self: @This()) u16 {
        return switch (self) {
            .ml_kem_768_x25519_sha256 => 0x0001,
            .ml_kem_1024_x25519_sha384 => 0x0002,
            .ml_kem_768_sha256 => 0x0003,
        };
    }
};

pub const PQTranscriptRole = enum(u8) {
    client = 0,
    server = 1,
};

/// Versioned transcript binder for experimental PQ handshakes.
///
/// This is not a wire format. It is the deterministic input contract zquic uses
/// to bind role, suite, public keys, ciphertext, and negotiated feature posture
/// into derived secrets and tests.
pub const PQHandshakeTranscript = struct {
    pub const version: u16 = 1;
    pub const domain = "zquic pq transcript v1";

    cipher_suite: PQCipherSuite,
    role: PQTranscriptRole,
    kem_public_key: []const u8,
    classical_public_key: ?[]const u8 = null,
    kem_ciphertext: []const u8,
    experimental_crypto: bool,

    const Self = @This();

    pub fn validate(self: Self) Error.ZquicError!void {
        if (!self.experimental_crypto) return Error.ZquicError.CryptoError;
        if (self.kem_public_key.len == 0) return Error.ZquicError.CryptoError;
        if (self.kem_ciphertext.len == 0) return Error.ZquicError.CryptoError;

        const expected_kem_public_len: usize = switch (self.cipher_suite.getKemVariant()) {
            .ml_kem_768 => PostQuantum.MLKEMKeyExchange.ML_KEM_768.PUBLIC_KEY_SIZE,
            .ml_kem_1024 => PostQuantum.MLKEMKeyExchange.ML_KEM_1024.PUBLIC_KEY_SIZE,
        };
        const expected_ciphertext_len: usize = switch (self.cipher_suite.getKemVariant()) {
            .ml_kem_768 => PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE,
            .ml_kem_1024 => PostQuantum.MLKEMKeyExchange.ML_KEM_1024.CIPHERTEXT_SIZE,
        };
        if (self.kem_public_key.len != expected_kem_public_len) return Error.ZquicError.CryptoError;
        if (self.kem_ciphertext.len != expected_ciphertext_len) return Error.ZquicError.CryptoError;

        if (self.cipher_suite.isHybrid()) {
            const classical_key = self.classical_public_key orelse return Error.ZquicError.CryptoError;
            if (classical_key.len != 32) return Error.ZquicError.CryptoError;
        } else if (self.classical_public_key) |classical_key| {
            if (classical_key.len != 0) return Error.ZquicError.CryptoError;
        }
    }

    pub fn hash(self: Self) Error.ZquicError![32]u8 {
        try self.validate();

        var hasher = zcrypto.hash.Sha256.init();
        hasher.update(domain);
        updateU16(&hasher, version);
        updateU16(&hasher, self.cipher_suite.id());
        hasher.update(&[_]u8{@intFromEnum(self.role)});
        hasher.update(&[_]u8{if (self.experimental_crypto) 1 else 0});
        updateSlice(&hasher, self.kem_public_key);
        updateSlice(&hasher, self.classical_public_key orelse &[_]u8{});
        updateSlice(&hasher, self.kem_ciphertext);
        return hasher.final();
    }

    pub fn secretsMatch(
        client_transcript: Self,
        server_transcript: Self,
        client_secret: []const u8,
        server_secret: []const u8,
    ) Error.ZquicError!bool {
        if (client_transcript.role != .client) return Error.ZquicError.CryptoError;
        if (server_transcript.role != .server) return Error.ZquicError.CryptoError;
        if (client_transcript.cipher_suite != server_transcript.cipher_suite) return Error.ZquicError.CryptoError;

        if (!sameBinderMaterial(client_transcript, server_transcript)) return false;

        // Compute both hashes to enforce validation and role-bound transcript
        // construction. The two hashes intentionally differ by role.
        _ = try client_transcript.hash();
        _ = try server_transcript.hash();

        return std.mem.eql(u8, client_secret, server_secret);
    }

    fn sameBinderMaterial(a: Self, b: Self) bool {
        if (a.experimental_crypto != b.experimental_crypto) return false;
        if (!std.mem.eql(u8, a.kem_public_key, b.kem_public_key)) return false;
        if (!std.mem.eql(u8, a.kem_ciphertext, b.kem_ciphertext)) return false;

        if (a.classical_public_key == null and b.classical_public_key == null) return true;
        if (a.classical_public_key == null or b.classical_public_key == null) return false;
        return std.mem.eql(u8, a.classical_public_key.?, b.classical_public_key.?);
    }

    fn updateU16(hasher: anytype, value: u16) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        hasher.update(&bytes);
    }

    fn updateU32(hasher: anytype, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        hasher.update(&bytes);
    }

    fn updateSlice(hasher: anytype, value: []const u8) void {
        updateU32(hasher, @intCast(value.len));
        hasher.update(value);
    }
};

/// Post-Quantum key exchange context
pub const PQKeyExchange = struct {
    cipher_suite: PQCipherSuite,
    allocator: std.mem.Allocator,

    // ML-KEM keys
    kem_public_key: ?[]u8 = null,
    kem_secret_key: ?[]u8 = null,
    kem_ciphertext: ?[]u8 = null,
    kem_shared_secret: ?[]u8 = null,

    // Classical keys (for hybrid mode)
    classical_public_key: ?[]u8 = null,
    classical_secret_key: ?[]u8 = null,
    classical_shared_secret: ?[]u8 = null,

    // Combined shared secret
    shared_secret: ?[]u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, cipher_suite: PQCipherSuite) !Self {
        return Self{
            .cipher_suite = cipher_suite,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Securely zero and free all key material
        if (self.kem_public_key) |key| {
            secureZero(key);
            self.allocator.free(key);
        }
        if (self.kem_secret_key) |key| {
            secureZero(key);
            self.allocator.free(key);
        }
        if (self.kem_ciphertext) |ct| {
            secureZero(ct);
            self.allocator.free(ct);
        }
        if (self.kem_shared_secret) |ss| {
            secureZero(ss);
            self.allocator.free(ss);
        }
        if (self.classical_public_key) |key| {
            secureZero(key);
            self.allocator.free(key);
        }
        if (self.classical_secret_key) |key| {
            secureZero(key);
            self.allocator.free(key);
        }
        if (self.classical_shared_secret) |ss| {
            secureZero(ss);
            self.allocator.free(ss);
        }
        if (self.shared_secret) |ss| {
            secureZero(ss);
            self.allocator.free(ss);
        }
    }

    /// Generate keypair for key exchange (client or server)
    pub fn generateKeypair(self: *Self) !void {
        // Generate ML-KEM keypair using zcrypto - variant determined by cipher suite
        const kem_variant = self.cipher_suite.getKemVariant();
        const kem_keypair = try PostQuantum.MLKEMKeyExchange.generateKeyPair(self.allocator, kem_variant);

        // Transfer ownership directly - no need to dupe since generateKeyPair already allocates
        self.kem_public_key = kem_keypair.public_key;
        self.kem_secret_key = kem_keypair.secret_key;

        // Generate classical X25519 keypair if hybrid mode
        if (self.cipher_suite.isHybrid()) {
            const classical_keypair = try KeyExchange.X25519KeyExchange.generateKeyPair(self.allocator);
            self.classical_public_key = classical_keypair.public_key;
            self.classical_secret_key = classical_keypair.secret_key;
        }
    }

    /// Encapsulate shared secret (client side)
    pub fn encapsulate(self: *Self, server_public_keys: PublicKeys) ![]u8 {
        // ML-KEM encapsulation - auto-detects variant from public key size
        const kem_result = try PostQuantum.MLKEMKeyExchange.encapsulate(
            self.allocator,
            server_public_keys.kem_public_key.?,
        );

        // Transfer ownership directly - encapsulate already allocates
        self.kem_ciphertext = kem_result.ciphertext;
        self.kem_shared_secret = kem_result.shared_secret;

        // Classical X25519 key exchange if hybrid mode
        if (self.cipher_suite.isHybrid()) {
            if (server_public_keys.classical_public_key) |server_classical_pk| {
                self.classical_shared_secret = try KeyExchange.X25519KeyExchange.deriveSharedSecret(
                    self.allocator,
                    self.classical_secret_key.?,
                    server_classical_pk,
                );
            } else {
                return Error.ZquicError.CryptoError;
            }
        }

        // Combine secrets
        try self.combineSecrets();

        return self.kem_ciphertext.?;
    }

    /// Decapsulate shared secret (server side)
    /// kem_ciphertext: The encapsulated ciphertext from the client (NOT the public key)
    pub fn decapsulate(self: *Self, kem_ciphertext: []const u8, client_public_keys: PublicKeys) !void {
        // ML-KEM decapsulation - auto-detects variant from key sizes
        self.kem_shared_secret = try PostQuantum.MLKEMKeyExchange.decapsulate(
            self.allocator,
            self.kem_secret_key.?,
            kem_ciphertext,
        );

        // Classical X25519 key exchange if hybrid mode
        if (self.cipher_suite.isHybrid()) {
            if (client_public_keys.classical_public_key) |client_classical_pk| {
                self.classical_shared_secret = try KeyExchange.X25519KeyExchange.deriveSharedSecret(
                    self.allocator,
                    self.classical_secret_key.?,
                    client_classical_pk,
                );
            } else {
                return Error.ZquicError.CryptoError;
            }
        }

        // Combine secrets
        try self.combineSecrets();
    }

    /// Combine ML-KEM and classical secrets for hybrid mode
    fn combineSecrets(self: *Self) !void {
        if (self.cipher_suite.isHybrid()) {
            // Hybrid mode: concatenate and hash both secrets
            const kem_ss = self.kem_shared_secret.?;
            const classical_ss = self.classical_shared_secret.?;

            const combined_len = kem_ss.len + classical_ss.len;
            const combined = try self.allocator.alloc(u8, combined_len);
            defer self.allocator.free(combined);

            @memcpy(combined[0..kem_ss.len], kem_ss);
            @memcpy(combined[kem_ss.len..], classical_ss);

            // Hash combined secrets based on cipher suite
            switch (self.cipher_suite) {
                .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => {
                    self.shared_secret = try self.allocator.alloc(u8, 32);
                    var hasher = zcrypto.hash.Sha256.init();
                    hasher.update(combined);
                    const digest = hasher.final();
                    @memcpy(self.shared_secret.?, &digest);
                },
                .ml_kem_1024_x25519_sha384 => {
                    self.shared_secret = try self.allocator.alloc(u8, 48);
                    var hasher = zcrypto.hash.Sha384.init();
                    hasher.update(combined);
                    const digest = hasher.final();
                    @memcpy(self.shared_secret.?, &digest);
                },
            }
        } else {
            // PQ-only mode: use ML-KEM shared secret directly
            self.shared_secret = try self.allocator.dupe(u8, self.kem_shared_secret.?);
        }
    }

    /// Get the combined shared secret
    pub fn getSharedSecret(self: *const Self) ?[]const u8 {
        return self.shared_secret;
    }

    /// Get public keys for transmission
    pub fn getPublicKeys(self: *const Self) PublicKeys {
        return PublicKeys{
            .kem_public_key = self.kem_public_key,
            .classical_public_key = self.classical_public_key,
        };
    }
};

/// Public keys structure for key exchange
pub const PublicKeys = struct {
    kem_public_key: ?[]const u8,
    classical_public_key: ?[]const u8,
};

/// Post-Quantum QUIC context
pub const PQQuicContext = struct {
    tls_context: *EnhancedTlsContext,
    pq_cipher_suite: PQCipherSuite,
    key_exchange: ?PQKeyExchange = null,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        tls_context: *EnhancedTlsContext,
        pq_cipher_suite: PQCipherSuite,
    ) !Self {
        return Self{
            .tls_context = tls_context,
            .pq_cipher_suite = pq_cipher_suite,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.key_exchange) |*key_ex| {
            key_ex.deinit();
        }
    }

    /// Initialize post-quantum key exchange
    pub fn initKeyExchange(self: *Self) !void {
        self.key_exchange = try PQKeyExchange.init(self.allocator, self.pq_cipher_suite);
        try self.key_exchange.?.generateKeypair();
    }

    /// Process client hello with PQ extension
    pub fn processClientHello(self: *Self, client_public_keys: PublicKeys) ![]u8 {
        if (self.key_exchange == null) {
            try self.initKeyExchange();
        }

        // Server generates keypair and encapsulates
        const ciphertext = try self.key_exchange.?.encapsulate(client_public_keys);

        // Derive handshake keys from shared secret
        const shared_secret = self.key_exchange.?.getSharedSecret().?;
        try self.tls_context.deriveHandshakeKeys(shared_secret);

        return ciphertext;
    }

    /// Process server hello with PQ extension
    pub fn processServerHello(
        self: *Self,
        server_public_keys: PublicKeys,
        ciphertext: []const u8,
    ) !void {
        if (self.key_exchange == null) {
            try self.initKeyExchange();
        }

        // Client decapsulates to get shared secret
        try self.key_exchange.?.decapsulate(ciphertext, server_public_keys);

        // Derive handshake keys from shared secret
        const shared_secret = self.key_exchange.?.getSharedSecret().?;
        try self.tls_context.deriveHandshakeKeys(shared_secret);
    }

    /// Upgrade to application keys after handshake
    pub fn upgradeToApplicationKeys(self: *Self) !void {
        const shared_secret = self.key_exchange.?.getSharedSecret().?;

        // Derive application keys using post-quantum shared secret
        try self.tls_context.deriveApplicationKeys(shared_secret);
    }
};

/// Post-Quantum authentication for QUIC using zcrypto ML-DSA-65 (FIPS 204).
///
/// Backed by Zig stdlib `std.crypto.sign.mldsa.MLDSA65` via zcrypto. This is a
/// NIST-standardized, FIPS 204 lattice signature scheme — not a hand-rolled
/// placeholder.
pub const PQAuthentication = struct {
    /// ML-DSA-65 (FIPS 204) parameters from zcrypto.
    pub const ML_DSA_65 = zcrypto.post_quantum.pq.ml_dsa.ML_DSA_65;
    pub const SIGNATURE_SIZE = ML_DSA_65.SIGNATURE_SIZE;
    pub const PUBLIC_KEY_SIZE = ML_DSA_65.PUBLIC_KEY_SIZE;
    pub const PRIVATE_KEY_SIZE = ML_DSA_65.PRIVATE_KEY_SIZE;

    /// Sign data using ML-DSA-65 (FIPS 204 post-quantum signature).
    pub fn signWithMlDsa(
        data: []const u8,
        secret_key: []const u8,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        // Validate secret key size
        if (secret_key.len != PRIVATE_KEY_SIZE) {
            return Error.ZquicError.CryptoError;
        }

        // Create keypair struct for signing (sign derives from private_key).
        var keypair: ML_DSA_65.KeyPair = undefined;
        @memcpy(&keypair.private_key, secret_key[0..PRIVATE_KEY_SIZE]);

        // Generate signing randomness using zcrypto's secure RNG.
        var randomness: [ML_DSA_65.NOISE_SIZE]u8 = undefined;
        zcrypto.rand.fill(&randomness);

        // Sign the data
        const signature = keypair.sign(data, randomness) catch {
            return Error.ZquicError.CryptoError;
        };

        // Allocate and return signature
        const result = try allocator.alloc(u8, SIGNATURE_SIZE);
        @memcpy(result, &signature);
        return result;
    }

    /// Verify an ML-DSA-65 (FIPS 204) signature.
    pub fn verifyMlDsaSignature(
        data: []const u8,
        signature: []const u8,
        public_key: []const u8,
    ) !bool {
        // Validate sizes
        if (signature.len != SIGNATURE_SIZE) {
            return false;
        }
        if (public_key.len != PUBLIC_KEY_SIZE) {
            return false;
        }

        // Convert slices to fixed arrays
        var sig_array: [SIGNATURE_SIZE]u8 = undefined;
        var pk_array: [PUBLIC_KEY_SIZE]u8 = undefined;
        @memcpy(&sig_array, signature[0..SIGNATURE_SIZE]);
        @memcpy(&pk_array, public_key[0..PUBLIC_KEY_SIZE]);

        // Verify using zcrypto ML-DSA-65 (FIPS 204).
        return ML_DSA_65.KeyPair.verify(pk_array, data, sig_array) catch false;
    }
};

test "post-quantum key exchange" {
    const allocator = std.testing.allocator;

    // Initialize PQ key exchange
    var key_exchange = try PQKeyExchange.init(allocator, .ml_kem_768_x25519_sha256);
    defer key_exchange.deinit();

    // Generate keypair
    try key_exchange.generateKeypair();

    // Verify keys were generated
    try std.testing.expect(key_exchange.kem_public_key != null);
    try std.testing.expect(key_exchange.kem_secret_key != null);
    try std.testing.expect(key_exchange.classical_public_key != null);
    try std.testing.expect(key_exchange.classical_secret_key != null);
}

test "post-quantum authentication uses ML-DSA-65" {
    const allocator = std.testing.allocator;
    const message = "zquic ML-DSA authentication test";

    const keypair = PQAuthentication.ML_DSA_65.KeyPair.generateRandom() catch {
        return Error.ZquicError.CryptoError;
    };

    const signature = try PQAuthentication.signWithMlDsa(message, &keypair.private_key, allocator);
    defer allocator.free(signature);

    try std.testing.expect(try PQAuthentication.verifyMlDsaSignature(message, signature, &keypair.public_key));

    signature[0] ^= 1;
    try std.testing.expect(!try PQAuthentication.verifyMlDsaSignature(message, signature, &keypair.public_key));
}

fn filledTestBytes(comptime len: usize, value: u8) [len]u8 {
    var bytes = std.mem.zeroes([len]u8);
    @memset(bytes[0..], value);
    return bytes;
}

test "PQ transcript hash is deterministic and binds role suite and ciphertext" {
    const kem_pk = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.PUBLIC_KEY_SIZE, 0xA1);
    const x25519_pk = filledTestBytes(32, 0xB2);
    const ciphertext = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE, 0xC3);

    const base = PQHandshakeTranscript{
        .cipher_suite = .ml_kem_768_x25519_sha256,
        .role = .client,
        .kem_public_key = &kem_pk,
        .classical_public_key = &x25519_pk,
        .kem_ciphertext = &ciphertext,
        .experimental_crypto = true,
    };

    const hash1 = try base.hash();
    const hash2 = try base.hash();
    try std.testing.expectEqualSlices(u8, &hash1, &hash2);

    var server_role = base;
    server_role.role = .server;
    const server_hash = try server_role.hash();
    try std.testing.expect(!std.mem.eql(u8, &hash1, &server_hash));

    var different_suite = base;
    different_suite.cipher_suite = .ml_kem_768_sha256;
    different_suite.classical_public_key = null;
    const suite_hash = try different_suite.hash();
    try std.testing.expect(!std.mem.eql(u8, &hash1, &suite_hash));

    var tampered_ciphertext = ciphertext;
    tampered_ciphertext[0] ^= 0x01;
    var tampered = base;
    tampered.kem_ciphertext = &tampered_ciphertext;
    const tampered_hash = try tampered.hash();
    try std.testing.expect(!std.mem.eql(u8, &hash1, &tampered_hash));
}

test "PQ transcript rejects downgraded flags and malformed keys" {
    const kem_pk = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.PUBLIC_KEY_SIZE, 0x11);
    const short_kem_pk = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.PUBLIC_KEY_SIZE - 1, 0x11);
    const x25519_pk = filledTestBytes(32, 0x22);
    const short_x25519_pk = filledTestBytes(31, 0x22);
    const ciphertext = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE, 0x33);
    const short_ciphertext = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE - 1, 0x33);

    const valid = PQHandshakeTranscript{
        .cipher_suite = .ml_kem_768_x25519_sha256,
        .role = .client,
        .kem_public_key = &kem_pk,
        .classical_public_key = &x25519_pk,
        .kem_ciphertext = &ciphertext,
        .experimental_crypto = true,
    };
    try valid.validate();

    var disabled = valid;
    disabled.experimental_crypto = false;
    try std.testing.expectError(Error.ZquicError.CryptoError, disabled.validate());

    var bad_kem = valid;
    bad_kem.kem_public_key = &short_kem_pk;
    try std.testing.expectError(Error.ZquicError.CryptoError, bad_kem.validate());

    var bad_classical = valid;
    bad_classical.classical_public_key = &short_x25519_pk;
    try std.testing.expectError(Error.ZquicError.CryptoError, bad_classical.validate());

    var bad_ciphertext = valid;
    bad_ciphertext.kem_ciphertext = &short_ciphertext;
    try std.testing.expectError(Error.ZquicError.CryptoError, bad_ciphertext.validate());
}

test "PQ transcript secret match requires expected roles and identical binders" {
    const kem_pk = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.PUBLIC_KEY_SIZE, 0x44);
    const x25519_pk = filledTestBytes(32, 0x55);
    const ciphertext = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE, 0x66);
    const tampered_ciphertext = filledTestBytes(PostQuantum.MLKEMKeyExchange.ML_KEM_768.CIPHERTEXT_SIZE, 0x67);
    const secret = filledTestBytes(32, 0x77);

    const client = PQHandshakeTranscript{
        .cipher_suite = .ml_kem_768_x25519_sha256,
        .role = .client,
        .kem_public_key = &kem_pk,
        .classical_public_key = &x25519_pk,
        .kem_ciphertext = &ciphertext,
        .experimental_crypto = true,
    };
    var server = client;
    server.role = .server;

    try std.testing.expect(try PQHandshakeTranscript.secretsMatch(client, server, &secret, &secret));

    var wrong_role = client;
    wrong_role.role = .client;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        PQHandshakeTranscript.secretsMatch(client, wrong_role, &secret, &secret),
    );

    const different_secret = filledTestBytes(32, 0x88);
    try std.testing.expect(!try PQHandshakeTranscript.secretsMatch(client, server, &secret, &different_secret));

    var tampered_server = server;
    tampered_server.kem_ciphertext = &tampered_ciphertext;
    try std.testing.expect(!try PQHandshakeTranscript.secretsMatch(client, tampered_server, &secret, &secret));

    var downgraded_suite = server;
    downgraded_suite.cipher_suite = .ml_kem_768_sha256;
    downgraded_suite.classical_public_key = null;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        PQHandshakeTranscript.secretsMatch(client, downgraded_suite, &secret, &secret),
    );
}
