//! Hybrid Post-Quantum TLS 1.3 Implementation
//!
//! Implements RFC 9420 compliant hybrid key exchange using ML-KEM-768 + X25519
//! Provides quantum-safe cryptography while maintaining compatibility with classical systems
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
        @compileError("hybrid_pq_tls.zig requires -Dpost-quantum=true -Dexperimental-crypto=true");
    }
}

/// Hybrid Key Exchange Configuration
pub const HybridConfig = struct {
    enable_ml_kem: bool = true,
    enable_x25519: bool = true,
    prefer_pq: bool = true,
    fallback_to_classical: bool = true,
};

/// Hybrid key exchange result containing both classical and PQ components
pub const HybridKeyExchange = struct {
    // Classical X25519 components
    x25519_public: [32]u8,
    x25519_secret: [32]u8,
    x25519_shared: ?[32]u8,

    // ML-KEM-768 components
    ml_kem_public: []u8,
    ml_kem_secret: []u8,
    ml_kem_ciphertext: ?[]u8,
    ml_kem_shared: ?[32]u8,

    // Combined hybrid secret
    hybrid_secret: [64]u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .x25519_public = std.mem.zeroes([32]u8),
            .x25519_secret = std.mem.zeroes([32]u8),
            .x25519_shared = null,
            .ml_kem_public = try allocator.alloc(u8, 1184), // ML-KEM-768 public key size
            .ml_kem_secret = try allocator.alloc(u8, 2400), // ML-KEM-768 secret key size
            .ml_kem_ciphertext = null,
            .ml_kem_shared = null,
            .hybrid_secret = std.mem.zeroes([64]u8),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Secure zero sensitive data
        secureZero(std.mem.asBytes(&self.x25519_secret));
        secureZero(self.ml_kem_secret);
        if (self.x25519_shared) |*shared| {
            secureZero(std.mem.asBytes(shared));
        }
        if (self.ml_kem_shared) |*shared| {
            secureZero(std.mem.asBytes(shared));
        }
        secureZero(std.mem.asBytes(&self.hybrid_secret));

        self.allocator.free(self.ml_kem_public);
        self.allocator.free(self.ml_kem_secret);
        if (self.ml_kem_ciphertext) |ct| {
            self.allocator.free(ct);
        }
    }

    /// Generate hybrid key pair (X25519 + ML-KEM-768)
    pub fn generateKeyPair(self: *Self, config: HybridConfig) !void {
        if (config.enable_x25519) {
            // Generate X25519 key pair using zcrypto.kex stable API
            const keypair = try zcrypto.kex.X25519.generateKeypair();
            self.x25519_secret = keypair.private_key;
            self.x25519_public = keypair.public_key;
        }

        if (config.enable_ml_kem) {
            // Generate ML-KEM-768 key pair using zcrypto post_quantum API
            const ml_kem = zcrypto.post_quantum.ML_KEM_768;
            const keypair = try ml_kem.generateKeypair();
            @memcpy(self.ml_kem_secret, &keypair.private_key);
            @memcpy(self.ml_kem_public, &keypair.public_key);
        }
    }

    /// Perform client-side key encapsulation
    pub fn clientEncapsulate(self: *Self, server_x25519_public: [32]u8, server_ml_kem_public: []const u8, config: HybridConfig) !void {
        if (config.enable_x25519) {
            // X25519 key agreement using zcrypto.kex stable API
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.x25519_secret, server_x25519_public);
            self.x25519_shared = x25519_shared;
        }

        if (config.enable_ml_kem) {
            // ML-KEM-768 encapsulation using zcrypto post_quantum API
            self.ml_kem_ciphertext = try self.allocator.alloc(u8, 1088); // ML-KEM-768 ciphertext size
            const ml_kem = zcrypto.post_quantum.ML_KEM_768;
            const result = try ml_kem.encapsulate(server_ml_kem_public[0..1184].*);
            @memcpy(self.ml_kem_ciphertext.?, &result.ciphertext);
            self.ml_kem_shared = result.shared_secret;
        }

        // Combine secrets using KDF
        try self.deriveHybridSecret(config);
    }

    /// Perform server-side key decapsulation
    pub fn serverDecapsulate(self: *Self, client_x25519_public: [32]u8, ml_kem_ciphertext: []const u8, config: HybridConfig) !void {
        if (config.enable_x25519) {
            // X25519 key agreement using zcrypto.kex stable API
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.x25519_secret, client_x25519_public);
            self.x25519_shared = x25519_shared;
        }

        if (config.enable_ml_kem) {
            // ML-KEM-768 decapsulation using zcrypto post_quantum API
            const ml_kem = zcrypto.post_quantum.ML_KEM_768;
            const secret_key: [2400]u8 = self.ml_kem_secret[0..2400].*;
            const ciphertext: [1088]u8 = ml_kem_ciphertext[0..1088].*;
            const ml_kem_shared = try ml_kem.decapsulate(ciphertext, secret_key);
            self.ml_kem_shared = ml_kem_shared;
        }

        // Combine secrets using KDF
        try self.deriveHybridSecret(config);
    }

    /// Derive hybrid secret from both classical and post-quantum components
    fn deriveHybridSecret(self: *Self, config: HybridConfig) !void {
        var kdf_input: [96]u8 = undefined; // 32 bytes X25519 + 32 bytes ML-KEM + 32 bytes domain separator
        var offset: usize = 0;

        // Add X25519 shared secret if available
        if (config.enable_x25519 and self.x25519_shared != null) {
            @memcpy(kdf_input[offset .. offset + 32], &self.x25519_shared.?);
            offset += 32;
        }

        // Add ML-KEM shared secret if available
        if (config.enable_ml_kem and self.ml_kem_shared != null) {
            @memcpy(kdf_input[offset .. offset + 32], &self.ml_kem_shared.?);
            offset += 32;
        }

        // Add domain separator for hybrid derivation
        const domain_sep = "ZQUIC-HYBRID-PQ-TLS-1.3\x00\x00\x00\x00\x00\x00\x00\x00";
        @memcpy(kdf_input[offset .. offset + 32], domain_sep);
        offset += 32;

        // Use HKDF to derive final hybrid secret (zcrypto v1.0.0 API)
        const salt = "zquic-hybrid-kdf-salt";
        const derived = try zcrypto.kdf.hkdfSha256(self.allocator, kdf_input[0..offset], salt, "hybrid-shared-secret", 64);
        @memcpy(&self.hybrid_secret, derived);
        self.allocator.free(derived);
    }

    /// Get the hybrid shared secret for TLS key derivation
    pub fn getSharedSecret(self: *const Self) [64]u8 {
        return self.hybrid_secret;
    }
};

/// Hybrid Post-Quantum TLS Context
pub const HybridPQTlsContext = struct {
    hybrid_kx: HybridKeyExchange,
    config: HybridConfig,
    is_server: bool,
    tls_context: ?*EnhancedTlsContext,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool, config: HybridConfig) !Self {
        return Self{
            .hybrid_kx = try HybridKeyExchange.init(allocator),
            .config = config,
            .is_server = is_server,
            .tls_context = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.hybrid_kx.deinit();
    }

    /// Initialize hybrid TLS handshake
    pub fn initializeHandshake(self: *Self) !void {
        // Generate our hybrid key pair
        try self.hybrid_kx.generateKeyPair(self.config);

        std.log.info("Hybrid PQ-TLS handshake initialized (ML-KEM-768 + X25519)", .{});
    }

    /// Process client hello and generate server response
    /// Server receives client's public keys, performs encapsulation, and returns its own
    /// public keys plus the ML-KEM ciphertext for the client to decapsulate.
    pub fn processClientHello(self: *Self, client_hello: []const u8) ![]u8 {
        if (!self.is_server) return Error.ZquicError.InvalidState;
        if (client_hello.len < 32 + 1184) return Error.ZquicError.CryptoError;

        // Parse client hybrid key exchange data
        const client_x25519_public = std.mem.bytesToValue([32]u8, client_hello[0..32]);
        const client_ml_kem_public = client_hello[32..];

        // Perform server-side key exchange: X25519 agreement + ML-KEM encapsulation
        if (self.config.enable_x25519) {
            // X25519 key agreement using client's public key
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.hybrid_kx.x25519_secret, client_x25519_public);
            self.hybrid_kx.x25519_shared = x25519_shared;
        }

        if (self.config.enable_ml_kem) {
            // ML-KEM encapsulation to client's public key
            self.hybrid_kx.ml_kem_ciphertext = try self.allocator.alloc(u8, 1088); // ML-KEM-768 ciphertext size
            const ml_kem = zcrypto.post_quantum.ML_KEM_768;
            const result = try ml_kem.encapsulate(client_ml_kem_public[0..1184].*);
            @memcpy(self.hybrid_kx.ml_kem_ciphertext.?, &result.ciphertext);
            self.hybrid_kx.ml_kem_shared = result.shared_secret;
        }

        // Derive combined hybrid secret
        try self.hybrid_kx.deriveHybridSecret(self.config);

        // Generate server hello response: our public keys + ML-KEM ciphertext
        // Format: X25519 public (32) + ML-KEM public (1184) + ML-KEM ciphertext (1088)
        var response = try self.allocator.alloc(u8, 32 + 1184 + 1088);
        @memcpy(response[0..32], &self.hybrid_kx.x25519_public);
        @memcpy(response[32..1216], self.hybrid_kx.ml_kem_public);
        if (self.hybrid_kx.ml_kem_ciphertext) |ct| {
            @memcpy(response[1216..2304], ct);
        }

        std.log.info("Server processed client hello with hybrid PQ keys", .{});
        return response;
    }

    /// Process server hello and complete client handshake
    /// Client receives server's public keys and ciphertext, performs X25519 agreement
    /// and ML-KEM decapsulation to derive the same shared secret.
    pub fn processServerHello(self: *Self, server_hello: []const u8) !void {
        if (self.is_server) return Error.ZquicError.InvalidState;
        if (server_hello.len < 32 + 1184 + 1088) return Error.ZquicError.CryptoError;

        // Parse server response: X25519 public (32) + ML-KEM public (1184) + ML-KEM ciphertext (1088)
        const server_x25519_public = std.mem.bytesToValue([32]u8, server_hello[0..32]);
        // Server ML-KEM public key at [32..1216] - not used by client for decapsulation
        const ml_kem_ciphertext = server_hello[1216..2304];

        // Perform client-side key exchange: X25519 agreement + ML-KEM decapsulation
        if (self.config.enable_x25519) {
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.hybrid_kx.x25519_secret, server_x25519_public);
            self.hybrid_kx.x25519_shared = x25519_shared;
        }

        if (self.config.enable_ml_kem) {
            // ML-KEM decapsulation using our secret key and server's ciphertext
            const ml_kem = zcrypto.post_quantum.ML_KEM_768;
            const secret_key: [2400]u8 = self.hybrid_kx.ml_kem_secret[0..2400].*;
            const ciphertext: [1088]u8 = ml_kem_ciphertext[0..1088].*;
            const ml_kem_shared = try ml_kem.decapsulate(ciphertext, secret_key);
            self.hybrid_kx.ml_kem_shared = ml_kem_shared;
        }

        // Derive combined hybrid secret
        try self.hybrid_kx.deriveHybridSecret(self.config);

        std.log.info("Client processed server hello with hybrid PQ keys", .{});
    }

    /// Get the derived keys for QUIC encryption
    pub fn deriveQuicKeys(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const shared_secret = self.hybrid_kx.getSharedSecret();

        // Derive QUIC traffic keys from hybrid secret (zcrypto v1.0.0 API)
        var quic_keys = try allocator.alloc(u8, 128); // 64 bytes client + 64 bytes server keys
        errdefer allocator.free(quic_keys);

        const label = "QUIC client traffic secret";
        const client_derived = try zcrypto.kdf.hkdfSha256(allocator, &shared_secret, label, "", 64);
        @memcpy(quic_keys[0..64], client_derived);
        allocator.free(client_derived);

        const server_label = "QUIC server traffic secret";
        const server_derived = try zcrypto.kdf.hkdfSha256(allocator, &shared_secret, server_label, "", 64);
        @memcpy(quic_keys[64..128], server_derived);
        allocator.free(server_derived);

        return quic_keys;
    }

    /// Check if post-quantum cryptography is active
    pub fn isPostQuantumActive(self: *const Self) bool {
        return self.config.enable_ml_kem and self.hybrid_kx.ml_kem_shared != null;
    }

    /// Get security level description
    pub fn getSecurityLevel(self: *const Self) []const u8 {
        if (self.isPostQuantumActive() and self.hybrid_kx.x25519_shared != null) {
            return "Hybrid Post-Quantum (ML-KEM-768 + X25519)";
        } else if (self.isPostQuantumActive()) {
            return "Post-Quantum Only (ML-KEM-768)";
        } else if (self.hybrid_kx.x25519_shared != null) {
            return "Classical Only (X25519)";
        } else {
            return "No Key Exchange";
        }
    }
};

/// Utility function for secure memory zeroing - uses std library implementation
fn secureZero(data: []u8) void {
    std.crypto.secureZero(u8, data);
}

/// Test hybrid PQ-TLS functionality
pub fn testHybridPQTLS() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const config = HybridConfig{
        .enable_ml_kem = true,
        .enable_x25519 = true,
        .prefer_pq = true,
        .fallback_to_classical = true,
    };

    // Create server and client contexts
    var server = try HybridPQTlsContext.init(allocator, true, config);
    defer server.deinit();

    var client = try HybridPQTlsContext.init(allocator, false, config);
    defer client.deinit();

    // Initialize handshakes - generates key pairs for both sides
    try server.initializeHandshake();
    try client.initializeHandshake();

    // Client sends hello with its public keys: X25519 (32) + ML-KEM public (1184)
    var client_hello = try allocator.alloc(u8, 32 + 1184);
    defer allocator.free(client_hello);
    @memcpy(client_hello[0..32], &client.hybrid_kx.x25519_public);
    @memcpy(client_hello[32..], client.hybrid_kx.ml_kem_public);

    // Server processes client hello, encapsulates to client's ML-KEM public key
    // Returns: X25519 public (32) + ML-KEM public (1184) + ML-KEM ciphertext (1088)
    const server_hello = try server.processClientHello(client_hello);
    defer allocator.free(server_hello);

    // Client processes server hello, decapsulates using its secret key
    try client.processServerHello(server_hello);

    // Verify both sides have the same shared secret
    const server_secret = server.hybrid_kx.getSharedSecret();
    const client_secret = client.hybrid_kx.getSharedSecret();

    if (!std.mem.eql(u8, &server_secret, &client_secret)) {
        return Error.ZquicError.CryptoError;
    }

    std.log.info("Hybrid PQ-TLS test passed! Security level: {s}", .{client.getSecurityLevel()});
}
