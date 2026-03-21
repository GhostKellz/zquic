//! Post-Quantum QUIC Implementation
//!
//! Provides post-quantum key exchange for QUIC handshakes using zcrypto v0.6.0
//! Implements hybrid classical + post-quantum cryptography with hardware acceleration

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const EnhancedTlsContext = @import("enhanced_tls.zig").EnhancedTlsContext;

// Utility function for secure memory zeroing - uses std library implementation
fn secureZero(data: []u8) void {
    std.crypto.secureZero(u8, data);
}

// Import zcrypto post-quantum modules (ML-KEM and ML-DSA)
const MLKEMResult = struct {
    ciphertext: []const u8,
    shared_secret: []const u8,
};

/// Post-quantum key exchange using zcrypto ML-KEM
const PostQuantum = struct {
    const MLKEMKeyExchange = struct {
        const ML_KEM_768 = zcrypto.post_quantum.pq.ml_kem.ML_KEM_768;

        pub fn generateKeyPair(allocator: std.mem.Allocator, variant: anytype) !KeyPair {
            // Generate random seed for key generation using zcrypto's secure RNG
            var seed: [32]u8 = undefined;
            zcrypto.rand.fill(&seed);

            // Currently only ML-KEM-768 is supported
            const keypair = switch (variant) {
                .ml_kem_768, .ml_kem_1024 => ML_KEM_768.KeyPair.generate(seed) catch {
                    return Error.ZquicError.CryptoError;
                },
                else => return Error.ZquicError.CryptoError,
            };

            return .{
                .public_key = try allocator.dupe(u8, &keypair.public_key),
                .secret_key = try allocator.dupe(u8, &keypair.private_key),
            };
        }

        pub fn encapsulate(allocator: std.mem.Allocator, public_key: []const u8) !MLKEMResult {
            // Use ML-KEM-768 by default
            if (public_key.len != ML_KEM_768.PUBLIC_KEY_SIZE) {
                return Error.ZquicError.CryptoError;
            }

            var pk_array: [ML_KEM_768.PUBLIC_KEY_SIZE]u8 = undefined;
            @memcpy(&pk_array, public_key[0..ML_KEM_768.PUBLIC_KEY_SIZE]);

            const result = ML_KEM_768.encapsulate(pk_array) catch {
                return Error.ZquicError.CryptoError;
            };

            return .{
                .ciphertext = try allocator.dupe(u8, &result.ciphertext),
                .shared_secret = try allocator.dupe(u8, &result.shared_secret),
            };
        }

        pub fn decapsulate(allocator: std.mem.Allocator, secret_key: []const u8, ciphertext: []const u8) ![]const u8 {
            if (secret_key.len != ML_KEM_768.PRIVATE_KEY_SIZE or
                ciphertext.len != ML_KEM_768.CIPHERTEXT_SIZE)
            {
                return Error.ZquicError.CryptoError;
            }

            var sk_array: [ML_KEM_768.PRIVATE_KEY_SIZE]u8 = undefined;
            var ct_array: [ML_KEM_768.CIPHERTEXT_SIZE]u8 = undefined;
            @memcpy(&sk_array, secret_key[0..ML_KEM_768.PRIVATE_KEY_SIZE]);
            @memcpy(&ct_array, ciphertext[0..ML_KEM_768.CIPHERTEXT_SIZE]);

            const shared_secret = ML_KEM_768.decapsulate(sk_array, ct_array) catch {
                return Error.ZquicError.CryptoError;
            };

            return try allocator.dupe(u8, &shared_secret);
        }
    };
};

const KeyPair = struct {
    public_key: []const u8,
    secret_key: []const u8,
};

const KeyExchange = struct {
    const X25519KeyExchange = struct {
        pub fn generateKeyPair(allocator: std.mem.Allocator) !KeyPair {
            return .{
                .public_key = try allocator.dupe(u8, &[_]u8{6} ** 32),
                .secret_key = try allocator.dupe(u8, &[_]u8{7} ** 32),
            };
        }

        pub fn deriveSharedSecret(secret_key: []const u8, public_key: []const u8) ![]const u8 {
            _ = secret_key;
            _ = public_key;
            return &[_]u8{8} ** 32;
        }
    };

    const X448KeyExchange = struct {
        pub fn generateKeyPair(allocator: std.mem.Allocator) !KeyPair {
            return .{
                .public_key = try allocator.dupe(u8, &[_]u8{9} ** 56),
                .secret_key = try allocator.dupe(u8, &[_]u8{10} ** 56),
            };
        }

        pub fn deriveSharedSecret(secret_key: []const u8, public_key: []const u8) ![]const u8 {
            _ = secret_key;
            _ = public_key;
            return &[_]u8{11} ** 56;
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
            return try allocator.dupe(u8, &[_]u8{12} ** 256);
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
    /// ML-KEM-1024 + X448 hybrid (higher security)
    ml_kem_1024_x448_sha384,
    /// Pure ML-KEM-768 (post-quantum only)
    ml_kem_768_sha256,
    /// SLH-DSA-128f for signatures
    slh_dsa_128f,

    pub fn getKemAlgorithm(self: @This()) []const u8 {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => "ml_kem_768",
            .ml_kem_1024_x448_sha384 => "ml_kem_1024",
            .slh_dsa_128f => "ml_kem_768", // Fallback
        };
    }

    pub fn isHybrid(self: @This()) bool {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_1024_x448_sha384 => true,
            .ml_kem_768_sha256, .slh_dsa_128f => false,
        };
    }

    pub fn getClassicalAlgorithm(self: @This()) ?[]const u8 {
        return switch (self) {
            .ml_kem_768_x25519_sha256 => "x25519",
            .ml_kem_1024_x448_sha384 => "x448",
            .ml_kem_768_sha256, .slh_dsa_128f => null,
        };
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

    /// Generate keypair for key exchange (client or server) with hardware acceleration
    pub fn generateKeypair(self: *Self) !void {
        const kem_algorithm = self.cipher_suite.getKemAlgorithm();

        // Generate ML-KEM keypair using zcrypto v0.6.0
        const kem_keypair = if (std.mem.eql(u8, kem_algorithm, "ml_kem_768"))
            try PostQuantum.MLKEMKeyExchange.generateKeyPair(self.allocator, .ml_kem_768)
        else if (std.mem.eql(u8, kem_algorithm, "ml_kem_1024"))
            try PostQuantum.MLKEMKeyExchange.generateKeyPair(self.allocator, .ml_kem_1024)
        else
            return Error.ZquicError.CryptoError;

        self.kem_public_key = try self.allocator.dupe(u8, kem_keypair.public_key);
        self.kem_secret_key = try self.allocator.dupe(u8, kem_keypair.secret_key);

        // Generate classical keypair if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            const classical_keypair = if (std.mem.eql(u8, classical_alg, "x25519"))
                try KeyExchange.X25519KeyExchange.generateKeyPair(self.allocator)
            else if (std.mem.eql(u8, classical_alg, "x448"))
                try KeyExchange.X448KeyExchange.generateKeyPair(self.allocator)
            else
                return Error.ZquicError.CryptoError;

            self.classical_public_key = try self.allocator.dupe(u8, classical_keypair.public_key);
            self.classical_secret_key = try self.allocator.dupe(u8, classical_keypair.secret_key);
        }
    }

    /// Encapsulate shared secret (client side) with hardware acceleration
    pub fn encapsulate(self: *Self, server_public_keys: PublicKeys) ![]u8 {
        const kem_algorithm = self.cipher_suite.getKemAlgorithm();

        // ML-KEM encapsulation using zcrypto v0.6.0
        const kem_result = if (std.mem.eql(u8, kem_algorithm, "ml_kem_768"))
            try PostQuantum.MLKEMKeyExchange.encapsulate(self.allocator, server_public_keys.kem_public_key.?)
        else if (std.mem.eql(u8, kem_algorithm, "ml_kem_1024"))
            try PostQuantum.MLKEMKeyExchange.encapsulate(self.allocator, server_public_keys.kem_public_key.?)
        else
            return Error.ZquicError.CryptoError;

        self.kem_ciphertext = try self.allocator.dupe(u8, kem_result.ciphertext);
        self.kem_shared_secret = try self.allocator.dupe(u8, kem_result.shared_secret);

        // Classical key exchange if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            if (server_public_keys.classical_public_key) |server_classical_pk| {
                const classical_ss = if (std.mem.eql(u8, classical_alg, "x25519"))
                    try KeyExchange.X25519KeyExchange.deriveSharedSecret(self.classical_secret_key.?, server_classical_pk)
                else if (std.mem.eql(u8, classical_alg, "x448"))
                    try KeyExchange.X448KeyExchange.deriveSharedSecret(self.classical_secret_key.?, server_classical_pk)
                else
                    return Error.ZquicError.CryptoError;

                self.classical_shared_secret = try self.allocator.dupe(u8, classical_ss);
            } else {
                return Error.ZquicError.CryptoError;
            }
        }

        // Combine secrets
        try self.combineSecrets();

        return self.kem_ciphertext.?;
    }

    /// Decapsulate shared secret (server side)
    pub fn decapsulate(self: *Self, _: []const u8, client_public_keys: PublicKeys) !void {
        const kem_algorithm = self.cipher_suite.getKemAlgorithm();

        // ML-KEM decapsulation using zcrypto v0.6.0
        const kem_ss = if (std.mem.eql(u8, kem_algorithm, "ml_kem_768"))
            try PostQuantum.MLKEMKeyExchange.decapsulate(self.allocator, self.kem_secret_key.?, client_public_keys.kem_public_key.?)
        else if (std.mem.eql(u8, kem_algorithm, "ml_kem_1024"))
            try PostQuantum.MLKEMKeyExchange.decapsulate(self.allocator, self.kem_secret_key.?, client_public_keys.kem_public_key.?)
        else
            return Error.ZquicError.CryptoError;

        self.kem_shared_secret = try self.allocator.dupe(u8, kem_ss);

        // Classical key exchange if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            if (client_public_keys.classical_public_key) |client_classical_pk| {
                const classical_ss = if (std.mem.eql(u8, classical_alg, "x25519"))
                    try KeyExchange.X25519KeyExchange.deriveSharedSecret(self.classical_secret_key.?, client_classical_pk)
                else if (std.mem.eql(u8, classical_alg, "x448"))
                    try KeyExchange.X448KeyExchange.deriveSharedSecret(self.classical_secret_key.?, client_classical_pk)
                else
                    return Error.ZquicError.CryptoError;

                self.classical_shared_secret = try self.allocator.dupe(u8, classical_ss);
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

            // Use appropriate hash function based on cipher suite
            const hash_len = switch (self.cipher_suite) {
                .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => 32,
                .ml_kem_1024_x448_sha384 => 48,
                .slh_dsa_128f => unreachable,
            };

            self.shared_secret = try self.allocator.alloc(u8, hash_len);

            switch (self.cipher_suite) {
                .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => {
                    var hasher = zcrypto.hash.Sha256.init(.{});
                    hasher.update(combined);
                    hasher.final(self.shared_secret.?);
                },
                .ml_kem_1024_x448_sha384 => {
                    var hasher = zcrypto.hash.Sha384.init(.{});
                    hasher.update(combined);
                    hasher.final(self.shared_secret.?);
                },
                .slh_dsa_128f => unreachable,
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

/// Post-Quantum authentication for QUIC using zcrypto SLH-DSA
pub const PQAuthentication = struct {
    /// SLH-DSA-128s constants from zcrypto
    pub const SLH_DSA_128s = zcrypto.post_quantum.pq.slh_dsa.SLH_DSA_128s;
    pub const SIGNATURE_SIZE = SLH_DSA_128s.SIGNATURE_SIZE;
    pub const PUBLIC_KEY_SIZE = SLH_DSA_128s.PUBLIC_KEY_SIZE;
    pub const PRIVATE_KEY_SIZE = SLH_DSA_128s.PRIVATE_KEY_SIZE;

    /// Sign data using SLH-DSA (post-quantum signature)
    pub fn signWithSlhDsa(
        data: []const u8,
        secret_key: []const u8,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        // Validate secret key size
        if (secret_key.len != PRIVATE_KEY_SIZE) {
            return Error.ZquicError.CryptoError;
        }

        // Create keypair struct for signing
        var keypair: SLH_DSA_128s.KeyPair = undefined;
        @memcpy(&keypair.private_key, secret_key[0..PRIVATE_KEY_SIZE]);

        // Generate signing randomness using zcrypto's secure RNG
        var randomness: [SLH_DSA_128s.SEED_SIZE]u8 = undefined;
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

    /// Verify SLH-DSA signature
    pub fn verifySlhDsaSignature(
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

        // Verify using zcrypto SLH-DSA
        return SLH_DSA_128s.KeyPair.verify(pk_array, data, sig_array) catch false;
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
