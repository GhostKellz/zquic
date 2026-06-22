//! Hybrid Post-Quantum TLS 1.3 Implementation
//!
//! Implements RFC 9420 compliant hybrid key exchange using ML-KEM-768 + X25519
//! Provides experimental hybrid key exchange while maintaining compatibility with classical systems.
//!
//! IMPORTANT: This module requires -Dpost-quantum=true -Dexperimental-crypto=true

const std = @import("std");
const build_options = @import("build_options");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const EnhancedTlsContext = @import("enhanced_tls.zig").EnhancedTlsContext;
const ML_KEM_768 = zcrypto.post_quantum.ML_KEM_768;

const X25519_KEY_SIZE: usize = 32;
const ML_KEM_PUBLIC_KEY_SIZE: usize = ML_KEM_768.PUBLIC_KEY_SIZE;
const ML_KEM_PRIVATE_KEY_SIZE: usize = ML_KEM_768.PRIVATE_KEY_SIZE;
const ML_KEM_CIPHERTEXT_SIZE: usize = ML_KEM_768.CIPHERTEXT_SIZE;
const HYBRID_SECRET_SIZE: usize = 64;

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
    fallback_to_classical: bool = false,

    pub fn validate(self: HybridConfig) Error.ZquicError!void {
        if (!self.enable_ml_kem and !self.enable_x25519) return Error.ZquicError.CryptoError;
        if (!self.enable_ml_kem and self.enable_x25519 and !self.fallback_to_classical) {
            return Error.ZquicError.CryptoError;
        }
    }

    fn clientHelloLen(self: HybridConfig) usize {
        var len: usize = 0;
        if (self.enable_x25519) len += X25519_KEY_SIZE;
        if (self.enable_ml_kem) len += ML_KEM_PUBLIC_KEY_SIZE;
        return len;
    }

    fn serverHelloLen(self: HybridConfig) usize {
        var len: usize = 0;
        if (self.enable_x25519) len += X25519_KEY_SIZE;
        if (self.enable_ml_kem) len += ML_KEM_PUBLIC_KEY_SIZE + ML_KEM_CIPHERTEXT_SIZE;
        return len;
    }
};

/// Hybrid key exchange result containing both classical and PQ components
pub const HybridKeyExchange = struct {
    // Classical X25519 components
    x25519_public: [X25519_KEY_SIZE]u8,
    x25519_secret: [X25519_KEY_SIZE]u8,
    x25519_shared: ?[X25519_KEY_SIZE]u8,

    // ML-KEM-768 components
    ml_kem_public: []u8,
    ml_kem_secret: []u8,
    ml_kem_ciphertext: ?[]u8,
    ml_kem_shared: ?[32]u8,

    // Combined hybrid secret
    hybrid_secret: [HYBRID_SECRET_SIZE]u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .x25519_public = std.mem.zeroes([X25519_KEY_SIZE]u8),
            .x25519_secret = std.mem.zeroes([X25519_KEY_SIZE]u8),
            .x25519_shared = null,
            .ml_kem_public = try allocator.alloc(u8, ML_KEM_PUBLIC_KEY_SIZE),
            .ml_kem_secret = try allocator.alloc(u8, ML_KEM_PRIVATE_KEY_SIZE),
            .ml_kem_ciphertext = null,
            .ml_kem_shared = null,
            .hybrid_secret = std.mem.zeroes([HYBRID_SECRET_SIZE]u8),
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
        try config.validate();

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
    pub fn clientEncapsulate(self: *Self, server_x25519_public: [X25519_KEY_SIZE]u8, server_ml_kem_public: []const u8, config: HybridConfig) !void {
        try config.validate();

        if (config.enable_x25519) {
            // X25519 key agreement using zcrypto.kex stable API
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.x25519_secret, server_x25519_public);
            self.x25519_shared = x25519_shared;
        }

        if (config.enable_ml_kem) {
            if (server_ml_kem_public.len != ML_KEM_PUBLIC_KEY_SIZE) return Error.ZquicError.CryptoError;
            // ML-KEM-768 encapsulation using zcrypto post_quantum API
            self.ml_kem_ciphertext = try self.allocator.alloc(u8, ML_KEM_CIPHERTEXT_SIZE);
            const result = try ML_KEM_768.encapsulate(server_ml_kem_public[0..ML_KEM_PUBLIC_KEY_SIZE].*);
            @memcpy(self.ml_kem_ciphertext.?, &result.ciphertext);
            self.ml_kem_shared = result.shared_secret;
        }

        // Combine secrets using KDF
        try self.deriveHybridSecret(config);
    }

    /// Perform server-side key decapsulation
    pub fn serverDecapsulate(self: *Self, client_x25519_public: [X25519_KEY_SIZE]u8, ml_kem_ciphertext: []const u8, config: HybridConfig) !void {
        try config.validate();

        if (config.enable_x25519) {
            // X25519 key agreement using zcrypto.kex stable API
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.x25519_secret, client_x25519_public);
            self.x25519_shared = x25519_shared;
        }

        if (config.enable_ml_kem) {
            if (ml_kem_ciphertext.len != ML_KEM_CIPHERTEXT_SIZE) return Error.ZquicError.CryptoError;
            // ML-KEM-768 decapsulation using zcrypto post_quantum API
            const secret_key: [ML_KEM_PRIVATE_KEY_SIZE]u8 = self.ml_kem_secret[0..ML_KEM_PRIVATE_KEY_SIZE].*;
            const ciphertext: [ML_KEM_CIPHERTEXT_SIZE]u8 = ml_kem_ciphertext[0..ML_KEM_CIPHERTEXT_SIZE].*;
            const ml_kem_shared = try ML_KEM_768.decapsulate(secret_key, ciphertext);
            self.ml_kem_shared = ml_kem_shared;
        }

        // Combine secrets using KDF
        try self.deriveHybridSecret(config);
    }

    /// Derive hybrid secret from both classical and post-quantum components
    fn deriveHybridSecret(self: *Self, config: HybridConfig) !void {
        try config.validate();

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

        // Add zero-padded domain separator for hybrid derivation.
        const domain_sep = "ZQUIC-HYBRID-PQ-TLS-1.3";
        var domain_block = std.mem.zeroes([32]u8);
        @memcpy(domain_block[0..domain_sep.len], domain_sep);
        @memcpy(kdf_input[offset .. offset + 32], &domain_block);
        offset += 32;

        // Use HKDF to derive final hybrid secret.
        const salt = "zquic-hybrid-kdf-salt";
        const derived = try zcrypto.kdf.hkdfSha256(self.allocator, kdf_input[0..offset], salt, "hybrid-shared-secret", 64);
        @memcpy(&self.hybrid_secret, derived);
        self.allocator.free(derived);
    }

    /// Get the hybrid shared secret for TLS key derivation
    pub fn getSharedSecret(self: *const Self) [HYBRID_SECRET_SIZE]u8 {
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
        try config.validate();
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
        try self.config.validate();
        // Generate our hybrid key pair
        try self.hybrid_kx.generateKeyPair(self.config);

        std.log.info("Hybrid PQ-TLS handshake initialized (ML-KEM-768 + X25519)", .{});
    }

    /// Process client hello and generate server response
    /// Server receives client's public keys, performs encapsulation, and returns its own
    /// public keys plus the ML-KEM ciphertext for the client to decapsulate.
    pub fn processClientHello(self: *Self, client_hello: []const u8) ![]u8 {
        if (!self.is_server) return Error.ZquicError.InvalidState;
        try self.config.validate();
        if (client_hello.len != self.config.clientHelloLen()) return Error.ZquicError.CryptoError;

        // Parse client hybrid key exchange data
        var offset: usize = 0;
        const client_x25519_public = if (self.config.enable_x25519) blk: {
            const key = std.mem.bytesToValue([X25519_KEY_SIZE]u8, client_hello[offset .. offset + X25519_KEY_SIZE]);
            offset += X25519_KEY_SIZE;
            break :blk key;
        } else std.mem.zeroes([X25519_KEY_SIZE]u8);
        const client_ml_kem_public = if (self.config.enable_ml_kem) blk: {
            const key = client_hello[offset .. offset + ML_KEM_PUBLIC_KEY_SIZE];
            offset += ML_KEM_PUBLIC_KEY_SIZE;
            break :blk key;
        } else &[_]u8{};

        // Perform server-side key exchange: X25519 agreement + ML-KEM encapsulation
        if (self.config.enable_x25519) {
            // X25519 key agreement using client's public key
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.hybrid_kx.x25519_secret, client_x25519_public);
            self.hybrid_kx.x25519_shared = x25519_shared;
        }

        if (self.config.enable_ml_kem) {
            // ML-KEM encapsulation to client's public key
            self.hybrid_kx.ml_kem_ciphertext = try self.allocator.alloc(u8, ML_KEM_CIPHERTEXT_SIZE);
            const result = try ML_KEM_768.encapsulate(client_ml_kem_public[0..ML_KEM_PUBLIC_KEY_SIZE].*);
            @memcpy(self.hybrid_kx.ml_kem_ciphertext.?, &result.ciphertext);
            self.hybrid_kx.ml_kem_shared = result.shared_secret;
        }

        // Derive combined hybrid secret
        try self.hybrid_kx.deriveHybridSecret(self.config);

        var response = try self.allocator.alloc(u8, self.config.serverHelloLen());
        offset = 0;
        if (self.config.enable_x25519) {
            @memcpy(response[offset .. offset + X25519_KEY_SIZE], &self.hybrid_kx.x25519_public);
            offset += X25519_KEY_SIZE;
        }
        if (self.config.enable_ml_kem) {
            @memcpy(response[offset .. offset + ML_KEM_PUBLIC_KEY_SIZE], self.hybrid_kx.ml_kem_public);
            offset += ML_KEM_PUBLIC_KEY_SIZE;
            if (self.hybrid_kx.ml_kem_ciphertext) |ct| {
                @memcpy(response[offset .. offset + ML_KEM_CIPHERTEXT_SIZE], ct);
            } else {
                self.allocator.free(response);
                return Error.ZquicError.CryptoError;
            }
        }

        std.log.info("Server processed client hello with hybrid PQ keys", .{});
        return response;
    }

    /// Process server hello and complete client handshake
    /// Client receives server's public keys and ciphertext, performs X25519 agreement
    /// and ML-KEM decapsulation to derive the same shared secret.
    pub fn processServerHello(self: *Self, server_hello: []const u8) !void {
        if (self.is_server) return Error.ZquicError.InvalidState;
        try self.config.validate();
        if (server_hello.len != self.config.serverHelloLen()) return Error.ZquicError.CryptoError;

        var offset: usize = 0;
        const server_x25519_public = if (self.config.enable_x25519) blk: {
            const key = std.mem.bytesToValue([X25519_KEY_SIZE]u8, server_hello[offset .. offset + X25519_KEY_SIZE]);
            offset += X25519_KEY_SIZE;
            break :blk key;
        } else std.mem.zeroes([X25519_KEY_SIZE]u8);
        if (self.config.enable_ml_kem) offset += ML_KEM_PUBLIC_KEY_SIZE; // server ML-KEM public key is not used for decapsulation
        const ml_kem_ciphertext = if (self.config.enable_ml_kem) blk: {
            const ct = server_hello[offset .. offset + ML_KEM_CIPHERTEXT_SIZE];
            offset += ML_KEM_CIPHERTEXT_SIZE;
            break :blk ct;
        } else &[_]u8{};

        // Perform client-side key exchange: X25519 agreement + ML-KEM decapsulation
        if (self.config.enable_x25519) {
            const x25519_shared = try zcrypto.kex.X25519.computeSharedSecret(self.hybrid_kx.x25519_secret, server_x25519_public);
            self.hybrid_kx.x25519_shared = x25519_shared;
        }

        if (self.config.enable_ml_kem) {
            // ML-KEM decapsulation using our secret key and server's ciphertext
            const secret_key: [ML_KEM_PRIVATE_KEY_SIZE]u8 = self.hybrid_kx.ml_kem_secret[0..ML_KEM_PRIVATE_KEY_SIZE].*;
            const ciphertext: [ML_KEM_CIPHERTEXT_SIZE]u8 = ml_kem_ciphertext[0..ML_KEM_CIPHERTEXT_SIZE].*;
            const ml_kem_shared = try ML_KEM_768.decapsulate(secret_key, ciphertext);
            self.hybrid_kx.ml_kem_shared = ml_kem_shared;
        }

        // Derive combined hybrid secret
        try self.hybrid_kx.deriveHybridSecret(self.config);

        std.log.info("Client processed server hello with hybrid PQ keys", .{});
    }

    /// Get the derived keys for QUIC encryption
    pub fn deriveQuicKeys(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const shared_secret = self.hybrid_kx.getSharedSecret();

        // Derive QUIC traffic keys from hybrid secret.
        var quic_keys = try allocator.alloc(u8, HYBRID_SECRET_SIZE * 2);
        errdefer allocator.free(quic_keys);

        const label = "QUIC client traffic secret";
        const client_derived = try zcrypto.kdf.hkdfSha256(allocator, &shared_secret, label, "", HYBRID_SECRET_SIZE);
        @memcpy(quic_keys[0..HYBRID_SECRET_SIZE], client_derived);
        allocator.free(client_derived);

        const server_label = "QUIC server traffic secret";
        const server_derived = try zcrypto.kdf.hkdfSha256(allocator, &shared_secret, server_label, "", HYBRID_SECRET_SIZE);
        @memcpy(quic_keys[HYBRID_SECRET_SIZE .. HYBRID_SECRET_SIZE * 2], server_derived);
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
        .fallback_to_classical = false,
    };

    // Create server and client contexts
    var server = try HybridPQTlsContext.init(allocator, true, config);
    defer server.deinit();

    var client = try HybridPQTlsContext.init(allocator, false, config);
    defer client.deinit();

    // Initialize handshakes - generates key pairs for both sides
    try server.initializeHandshake();
    try client.initializeHandshake();

    // Client sends hello with its public keys: X25519 + ML-KEM public.
    var client_hello = try allocator.alloc(u8, config.clientHelloLen());
    defer allocator.free(client_hello);
    @memcpy(client_hello[0..X25519_KEY_SIZE], &client.hybrid_kx.x25519_public);
    @memcpy(client_hello[X25519_KEY_SIZE..], client.hybrid_kx.ml_kem_public);

    // Server processes client hello, encapsulates to client's ML-KEM public key
    // Returns: X25519 public + ML-KEM public + ML-KEM ciphertext.
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

test "HybridConfig rejects implicit classical-only fallback" {
    try std.testing.expectError(Error.ZquicError.CryptoError, (HybridConfig{
        .enable_ml_kem = false,
        .enable_x25519 = true,
        .fallback_to_classical = false,
    }).validate());

    try (HybridConfig{
        .enable_ml_kem = false,
        .enable_x25519 = true,
        .fallback_to_classical = true,
    }).validate();

    try std.testing.expectError(Error.ZquicError.CryptoError, (HybridConfig{
        .enable_ml_kem = false,
        .enable_x25519 = false,
    }).validate());
}

test "Hybrid PQ-TLS rejects malformed key share lengths" {
    const allocator = std.testing.allocator;
    const config = HybridConfig{};

    var server = try HybridPQTlsContext.init(allocator, true, config);
    defer server.deinit();
    try server.initializeHandshake();

    var client = try HybridPQTlsContext.init(allocator, false, config);
    defer client.deinit();
    try client.initializeHandshake();

    var client_hello = try allocator.alloc(u8, config.clientHelloLen());
    defer allocator.free(client_hello);
    @memcpy(client_hello[0..X25519_KEY_SIZE], &client.hybrid_kx.x25519_public);
    @memcpy(client_hello[X25519_KEY_SIZE..], client.hybrid_kx.ml_kem_public);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        server.processClientHello(client_hello[0 .. client_hello.len - 1]),
    );

    const server_hello = try server.processClientHello(client_hello);
    defer allocator.free(server_hello);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        client.processServerHello(server_hello[0 .. server_hello.len - 1]),
    );
}

test "Hybrid key exchange rejects malformed ML-KEM slices before fixed-array conversion" {
    const allocator = std.testing.allocator;
    const config = HybridConfig{};

    var kx = try HybridKeyExchange.init(allocator);
    defer kx.deinit();
    try kx.generateKeyPair(config);

    const peer_x25519 = fixedTestBytes(X25519_KEY_SIZE, 0x55);
    const short_public = fixedTestBytes(ML_KEM_PUBLIC_KEY_SIZE - 1, 0x66);
    const short_ciphertext = fixedTestBytes(ML_KEM_CIPHERTEXT_SIZE - 1, 0x77);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        kx.clientEncapsulate(peer_x25519, &short_public, config),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        kx.serverDecapsulate(peer_x25519, &short_ciphertext, config),
    );
}

fn fixedTestBytes(comptime len: usize, value: u8) [len]u8 {
    var bytes = std.mem.zeroes([len]u8);
    @memset(bytes[0..], value);
    return bytes;
}
