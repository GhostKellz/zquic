//! Post-Quantum QUIC Implementation
//!
//! Provides post-quantum key exchange for QUIC handshakes using zcrypto v0.5.0
//! Implements hybrid classical + post-quantum cryptography for quantum-safe networking

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const EnhancedTlsContext = @import("enhanced_tls.zig").EnhancedTlsContext;

// Import zcrypto post-quantum modules
const pq = zcrypto.post_quantum;
const kex = zcrypto.key_exchange;
const hybrid = zcrypto.hybrid;

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

    pub fn getKemAlgorithm(self: @This()) pq.KemAlgorithm {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_768_sha256 => .ml_kem_768,
            .ml_kem_1024_x448_sha384 => .ml_kem_1024,
            .slh_dsa_128f => unreachable, // Not a KEM
        };
    }

    pub fn isHybrid(self: @This()) bool {
        return switch (self) {
            .ml_kem_768_x25519_sha256, .ml_kem_1024_x448_sha384 => true,
            .ml_kem_768_sha256, .slh_dsa_128f => false,
        };
    }

    pub fn getClassicalAlgorithm(self: @This()) ?kex.Algorithm {
        return switch (self) {
            .ml_kem_768_x25519_sha256 => .x25519,
            .ml_kem_1024_x448_sha384 => .x448,
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
            zcrypto.utils.secure_zero(key);
            self.allocator.free(key);
        }
        if (self.kem_secret_key) |key| {
            zcrypto.utils.secure_zero(key);
            self.allocator.free(key);
        }
        if (self.kem_ciphertext) |ct| {
            zcrypto.utils.secure_zero(ct);
            self.allocator.free(ct);
        }
        if (self.kem_shared_secret) |ss| {
            zcrypto.utils.secure_zero(ss);
            self.allocator.free(ss);
        }
        if (self.classical_public_key) |key| {
            zcrypto.utils.secure_zero(key);
            self.allocator.free(key);
        }
        if (self.classical_secret_key) |key| {
            zcrypto.utils.secure_zero(key);
            self.allocator.free(key);
        }
        if (self.classical_shared_secret) |ss| {
            zcrypto.utils.secure_zero(ss);
            self.allocator.free(ss);
        }
        if (self.shared_secret) |ss| {
            zcrypto.utils.secure_zero(ss);
            self.allocator.free(ss);
        }
    }

    /// Generate keypair for key exchange (client or server)
    pub fn generateKeypair(self: *Self) !void {
        const kem_alg = self.cipher_suite.getKemAlgorithm();

        // Generate ML-KEM keypair
        const kem_keypair = try pq.ml_kem_generate_keypair(kem_alg);
        
        self.kem_public_key = try self.allocator.alloc(u8, kem_keypair.public_key.len);
        self.kem_secret_key = try self.allocator.alloc(u8, kem_keypair.secret_key.len);
        
        @memcpy(self.kem_public_key.?, kem_keypair.public_key);
        @memcpy(self.kem_secret_key.?, kem_keypair.secret_key);

        // Generate classical keypair if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            const classical_keypair = try kex.generate_keypair(classical_alg);
            
            self.classical_public_key = try self.allocator.alloc(u8, classical_keypair.public_key.len);
            self.classical_secret_key = try self.allocator.alloc(u8, classical_keypair.secret_key.len);
            
            @memcpy(self.classical_public_key.?, classical_keypair.public_key);
            @memcpy(self.classical_secret_key.?, classical_keypair.secret_key);
        }
    }

    /// Encapsulate shared secret (client side)
    pub fn encapsulate(self: *Self, server_public_keys: PublicKeys) ![]u8 {
        const kem_alg = self.cipher_suite.getKemAlgorithm();

        // ML-KEM encapsulation
        const kem_result = try pq.ml_kem_encapsulate(kem_alg, server_public_keys.kem_public_key);
        
        self.kem_ciphertext = try self.allocator.alloc(u8, kem_result.ciphertext.len);
        self.kem_shared_secret = try self.allocator.alloc(u8, kem_result.shared_secret.len);
        
        @memcpy(self.kem_ciphertext.?, kem_result.ciphertext);
        @memcpy(self.kem_shared_secret.?, kem_result.shared_secret);

        // Classical key exchange if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            if (server_public_keys.classical_public_key) |server_classical_pk| {
                const classical_ss = try kex.compute_shared_secret(
                    classical_alg,
                    self.classical_secret_key.?,
                    server_classical_pk,
                );
                
                self.classical_shared_secret = try self.allocator.alloc(u8, classical_ss.len);
                @memcpy(self.classical_shared_secret.?, classical_ss);
            } else {
                return Error.ZquicError.CryptoError;
            }
        }

        // Combine secrets
        try self.combineSecrets();

        return self.kem_ciphertext.?;
    }

    /// Decapsulate shared secret (server side)
    pub fn decapsulate(self: *Self, ciphertext: []const u8, client_public_keys: PublicKeys) !void {
        const kem_alg = self.cipher_suite.getKemAlgorithm();

        // ML-KEM decapsulation
        const kem_ss = try pq.ml_kem_decapsulate(
            kem_alg,
            ciphertext,
            self.kem_secret_key.?,
        );
        
        self.kem_shared_secret = try self.allocator.alloc(u8, kem_ss.len);
        @memcpy(self.kem_shared_secret.?, kem_ss);

        // Classical key exchange if hybrid mode
        if (self.cipher_suite.getClassicalAlgorithm()) |classical_alg| {
            if (client_public_keys.classical_public_key) |client_classical_pk| {
                const classical_ss = try kex.compute_shared_secret(
                    classical_alg,
                    self.classical_secret_key.?,
                    client_classical_pk,
                );
                
                self.classical_shared_secret = try self.allocator.alloc(u8, classical_ss.len);
                @memcpy(self.classical_shared_secret.?, classical_ss);
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
        if (self.key_exchange) |*kex| {
            kex.deinit();
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

/// Post-Quantum authentication for QUIC
pub const PQAuthentication = struct {
    /// Sign data using SLH-DSA (post-quantum signature)
    pub fn signWithSlhDsa(
        data: []const u8,
        private_key: []const u8,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const signature = try pq.slh_dsa_sign(.slh_dsa_128f, data, private_key);
        const result = try allocator.alloc(u8, signature.len);
        @memcpy(result, signature);
        return result;
    }

    /// Verify SLH-DSA signature
    pub fn verifySlhDsaSignature(
        data: []const u8,
        signature: []const u8,
        public_key: []const u8,
    ) !bool {
        return try pq.slh_dsa_verify(.slh_dsa_128f, signature, data, public_key);
    }
};

test "post-quantum key exchange" {
    const allocator = std.testing.allocator;

    // Initialize PQ key exchange
    var kex = try PQKeyExchange.init(allocator, .ml_kem_768_x25519_sha256);
    defer kex.deinit();

    // Generate keypair
    try kex.generateKeypair();

    // Verify keys were generated
    try std.testing.expect(kex.kem_public_key != null);
    try std.testing.expect(kex.kem_secret_key != null);
    try std.testing.expect(kex.classical_public_key != null);
    try std.testing.expect(kex.classical_secret_key != null);
}