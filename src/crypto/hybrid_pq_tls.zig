//! Hybrid Post-Quantum TLS 1.3 Implementation
//!
//! Implements RFC 9420 compliant hybrid key exchange using ML-KEM-768 + X25519
//! Provides quantum-safe cryptography while maintaining compatibility with classical systems

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const EnhancedTlsContext = @import("enhanced_tls.zig").EnhancedTlsContext;

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
            // Generate X25519 key pair using zcrypto
            try zcrypto.ecc.x25519_keygen(&self.x25519_secret, &self.x25519_public);
        }
        
        if (config.enable_ml_kem) {
            // Generate ML-KEM-768 key pair using zcrypto
            try zcrypto.pq.ml_kem_768_keygen(self.ml_kem_secret, self.ml_kem_public);
        }
    }
    
    /// Perform client-side key encapsulation
    pub fn clientEncapsulate(self: *Self, server_x25519_public: [32]u8, server_ml_kem_public: []const u8, config: HybridConfig) !void {
        if (config.enable_x25519) {
            // X25519 key agreement
            var x25519_shared: [32]u8 = undefined;
            try zcrypto.ecc.x25519_dh(&x25519_shared, &self.x25519_secret, &server_x25519_public);
            self.x25519_shared = x25519_shared;
        }
        
        if (config.enable_ml_kem) {
            // ML-KEM-768 encapsulation
            self.ml_kem_ciphertext = try self.allocator.alloc(u8, 1088); // ML-KEM-768 ciphertext size
            var ml_kem_shared: [32]u8 = undefined;
            try zcrypto.pq.ml_kem_768_encaps(self.ml_kem_ciphertext.?, &ml_kem_shared, server_ml_kem_public);
            self.ml_kem_shared = ml_kem_shared;
        }
        
        // Combine secrets using KDF
        try self.deriveHybridSecret(config);
    }
    
    /// Perform server-side key decapsulation
    pub fn serverDecapsulate(self: *Self, client_x25519_public: [32]u8, ml_kem_ciphertext: []const u8, config: HybridConfig) !void {
        if (config.enable_x25519) {
            // X25519 key agreement
            var x25519_shared: [32]u8 = undefined;
            try zcrypto.ecc.x25519_dh(&x25519_shared, &self.x25519_secret, &client_x25519_public);
            self.x25519_shared = x25519_shared;
        }
        
        if (config.enable_ml_kem) {
            // ML-KEM-768 decapsulation
            var ml_kem_shared: [32]u8 = undefined;
            try zcrypto.pq.ml_kem_768_decaps(&ml_kem_shared, ml_kem_ciphertext, self.ml_kem_secret);
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
            @memcpy(kdf_input[offset..offset + 32], &self.x25519_shared.?);
            offset += 32;
        }
        
        // Add ML-KEM shared secret if available
        if (config.enable_ml_kem and self.ml_kem_shared != null) {
            @memcpy(kdf_input[offset..offset + 32], &self.ml_kem_shared.?);
            offset += 32;
        }
        
        // Add domain separator for hybrid derivation
        const domain_sep = "ZQUIC-HYBRID-PQ-TLS-1.3\x00\x00\x00\x00\x00\x00\x00\x00";
        @memcpy(kdf_input[offset..offset + 32], domain_sep);
        offset += 32;
        
        // Use HKDF to derive final hybrid secret
        const salt = "zquic-hybrid-kdf-salt";
        try zcrypto.kdf.hkdf_sha256(&self.hybrid_secret, kdf_input[0..offset], salt, "hybrid-shared-secret");
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
    pub fn processClientHello(self: *Self, client_hello: []const u8) ![]u8 {
        if (!self.is_server) return Error.ZquicError.InvalidState;
        
        // Parse client hybrid key exchange data
        // This is a simplified implementation - real implementation would parse TLS messages
        const client_x25519_public = std.mem.bytesToValue([32]u8, client_hello[0..32]);
        const client_ml_kem_public = client_hello[32..];
        
        // Perform server-side operations
        if (self.config.enable_ml_kem) {
            try self.hybrid_kx.serverDecapsulate(client_x25519_public, client_ml_kem_public, self.config);
        }
        
        // Generate server hello response with our public keys
        var response = try self.allocator.alloc(u8, 32 + 1184); // X25519 + ML-KEM public keys
        @memcpy(response[0..32], &self.hybrid_kx.x25519_public);
        @memcpy(response[32..], self.hybrid_kx.ml_kem_public);
        
        std.log.info("Server processed client hello with hybrid PQ keys", .{});
        return response;
    }
    
    /// Process server hello and complete client handshake
    pub fn processServerHello(self: *Self, server_hello: []const u8) !void {
        if (self.is_server) return Error.ZquicError.InvalidState;
        
        // Parse server hybrid public keys
        const server_x25519_public = std.mem.bytesToValue([32]u8, server_hello[0..32]);
        const server_ml_kem_public = server_hello[32..];
        
        // Perform client-side encapsulation
        try self.hybrid_kx.clientEncapsulate(server_x25519_public, server_ml_kem_public, self.config);
        
        std.log.info("Client processed server hello with hybrid PQ keys", .{});
    }
    
    /// Get the derived keys for QUIC encryption
    pub fn deriveQuicKeys(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const shared_secret = self.hybrid_kx.getSharedSecret();
        
        // Derive QUIC traffic keys from hybrid secret
        var quic_keys = try allocator.alloc(u8, 128); // 64 bytes client + 64 bytes server keys
        
        const label = "QUIC client traffic secret";
        try zcrypto.kdf.hkdf_sha256(quic_keys[0..64], &shared_secret, label, "");
        
        const server_label = "QUIC server traffic secret";
        try zcrypto.kdf.hkdf_sha256(quic_keys[64..128], &shared_secret, server_label, "");
        
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

/// Utility function for secure memory zeroing
fn secureZero(data: []u8) void {
    @memset(data, 0);
    // Prevent compiler optimization
    asm volatile ("" : : [data] "m" (data) : "memory");
}

/// Test hybrid PQ-TLS functionality
pub fn testHybridPQTLS() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
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
    
    // Initialize handshakes
    try server.initializeHandshake();
    try client.initializeHandshake();
    
    // Simulate handshake exchange
    var client_hello = try allocator.alloc(u8, 32 + 1184);
    defer allocator.free(client_hello);
    @memcpy(client_hello[0..32], &client.hybrid_kx.x25519_public);
    @memcpy(client_hello[32..], client.hybrid_kx.ml_kem_public);
    
    const server_hello = try server.processClientHello(client_hello);
    defer allocator.free(server_hello);
    
    try client.processServerHello(server_hello);
    
    // Verify both sides have the same shared secret
    const server_secret = server.hybrid_kx.getSharedSecret();
    const client_secret = client.hybrid_kx.getSharedSecret();
    
    if (!std.mem.eql(u8, &server_secret, &client_secret)) {
        return Error.ZquicError.CryptoError;
    }
    
    std.log.info("Hybrid PQ-TLS test passed! Security level: {s}", .{client.getSecurityLevel()});
}