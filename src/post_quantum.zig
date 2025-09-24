//! ZQUIC Post-Quantum Feature Module
//!
//! Provides post-quantum cryptographic extensions for QUIC.
//! Only included when the 'post-quantum' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Post-Quantum crypto support (zcrypto integration)
pub const PostQuantum = @import("crypto/pq_quic.zig");

// Re-export main PQ types
pub const PQCipherSuite = PostQuantum.PQCipherSuite;
pub const PQKeyExchange = PostQuantum.PQKeyExchange;
pub const PQQuicContext = PostQuantum.PQQuicContext;
pub const PQAuthentication = PostQuantum.PQAuthentication;

// Assembly optimizations for high-performance crypto
pub const Optimizations = @import("crypto/asm_optimizations.zig");

// PQ-specific configuration
pub const PQConfig = struct {
    enable_hybrid_mode: bool = true,  // Use ML-KEM + X25519 hybrid
    enable_hw_acceleration: bool = true,
    key_rotation_interval_ms: u32 = 3600000, // 1 hour
    max_key_age_ms: u32 = 86400000, // 24 hours
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: PQConfig) !void {
    _ = allocator;
    _ = config;
    // Initialize PQ-specific crypto state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up PQ-specific crypto state
}

// PQ crypto utilities
pub const PQUtils = struct {
    /// Generate a new PQ keypair
    pub fn generateKeypair(allocator: std.mem.Allocator, algorithm: PQCipherSuite) !PQKeyExchange.PublicKeys {
        _ = allocator;
        _ = algorithm;
        // Implementation would use zcrypto PQ functions
        return undefined;
    }

    /// Perform PQ key exchange
    pub fn keyExchange(allocator: std.mem.Allocator, private_key: []const u8, public_key: []const u8) ![]u8 {
        _ = allocator;
        _ = private_key;
        _ = public_key;
        // Implementation would use zcrypto PQ functions
        return undefined;
    }
};