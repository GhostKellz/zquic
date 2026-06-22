//! ZQUIC Post-Quantum Feature Module
//!
//! Provides post-quantum cryptographic extensions for QUIC.
//! Only included when the 'post-quantum' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Post-Quantum crypto support (zcrypto integration)
pub const PostQuantum = @import("crypto/pq_quic.zig");
pub const HybridPQTls = @import("crypto/hybrid_pq_tls.zig");

// Re-export main PQ types
pub const PQCipherSuite = PostQuantum.PQCipherSuite;
pub const PQKeyExchange = PostQuantum.PQKeyExchange;
pub const PQQuicContext = PostQuantum.PQQuicContext;
pub const PQAuthentication = PostQuantum.PQAuthentication;
pub const HybridConfig = HybridPQTls.HybridConfig;
pub const HybridKeyExchange = HybridPQTls.HybridKeyExchange;
pub const HybridPQTlsContext = HybridPQTls.HybridPQTlsContext;

test {
    _ = @import("performance/crypto_connection_multiplexer.zig");
}

// Assembly optimizations for high-performance crypto
pub const Optimizations = @import("crypto/asm_optimizations.zig");

// Re-export optimization types for convenience
pub const CpuOptimizer = Optimizations.CpuOptimizer;
pub const OptimizedBlake3 = Optimizations.OptimizedBlake3;
pub const OptimizedChaCha20Poly1305 = Optimizations.OptimizedChaCha20Poly1305;
pub const OptimizedPacketProcessor = Optimizations.OptimizedPacketProcessor;

// PQ-specific configuration
pub const PQConfig = struct {
    enable_hybrid_mode: bool = true, // Use ML-KEM + X25519 hybrid
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

// PQ crypto utilities - use PQKeyExchange and PQQuicContext directly
// The real implementation lives in crypto/pq_quic.zig
