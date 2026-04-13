//! ZCrypto Integration Tests
//!
//! Tests for zcrypto v1.0.1 integration with ZQUIC.
//!
//! NOTE: This test file is only compiled when both flags are set:
//!   -Dpost-quantum=true -Dexperimental-crypto=true
//!
//! ## Testing Strategy (v0.9.9)
//!
//! 1. **Stable Core Primitives (std.crypto)**:
//!    AES-GCM and ChaCha20-Poly1305 tests use std.crypto directly.
//!    This validates that zcrypto's internal use of std.crypto matches behavior.
//!
//! 2. **ZCrypto-Specific APIs**:
//!    - `zcrypto.hash` (Sha256, Blake3) - streaming hash wrappers
//!    - `zcrypto.kex` (X25519) - key exchange primitives
//!    - `zcrypto.kdf` (hkdfSha256) - key derivation
//!    - `zcrypto.rand` (fillBytes) - random number generation
//!    - `zcrypto.util` - secure memory operations
//!
//! 3. **Post-Quantum**: All PQ tests run since this file is only compiled
//!    when PQ is enabled by the build system.

const std = @import("std");
const zquic = @import("zquic");
const zcrypto = @import("zcrypto");

const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;
const PQQuicContext = zquic.PQQuicContext;

// ============================================================================
// ZCRYPTO HASH TESTS
// ============================================================================

test "zcrypto hash: SHA-256 streaming" {
    const data = "Hello, Post-Quantum QUIC!";

    var hasher = zcrypto.hash.Sha256.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 32);

    // Verify against one-shot function
    const one_shot = zcrypto.hash.sha256(data);
    try std.testing.expectEqualSlices(u8, &one_shot, &digest);
}

test "zcrypto hash: Blake3 streaming" {
    const data = "Hello, Post-Quantum QUIC!";

    // Blake3 is in its own module at zcrypto.blake3
    var hasher = zcrypto.blake3.Blake3.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 32);
}

// ============================================================================
// SYMMETRIC ENCRYPTION TESTS (std.crypto baseline)
// ============================================================================

test "std.crypto: AES-256-GCM baseline" {
    // Uses std.crypto directly - zcrypto wraps this internally
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const nonce: [12]u8 = [_]u8{0x11} ** 12;
    const plaintext = "Secret QUIC packet data";
    const aad = "additional authenticated data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(&ciphertext, &tag, plaintext, aad, nonce, key);

    var decrypted: [plaintext.len]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(&decrypted, &ciphertext, tag, aad, nonce, key) catch {
        try std.testing.expect(false);
        return;
    };

    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "std.crypto: ChaCha20-Poly1305 baseline" {
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const nonce: [12]u8 = [_]u8{0x11} ** 12;
    const plaintext = "QUIC packet with ChaCha20";
    const aad = "header data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, aad, nonce, key);

    var decrypted: [plaintext.len]u8 = undefined;
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, aad, nonce, key) catch {
        try std.testing.expect(false);
        return;
    };

    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

// ============================================================================
// KEY EXCHANGE TESTS
// ============================================================================

test "zcrypto.kex: X25519 key agreement" {
    const kp1 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };
    const kp2 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };

    // Both parties compute shared secret
    const shared1 = zcrypto.kex.X25519.computeSharedSecret(kp1.private_key, kp2.public_key) catch {
        try std.testing.expect(false);
        return;
    };
    const shared2 = zcrypto.kex.X25519.computeSharedSecret(kp2.private_key, kp1.public_key) catch {
        try std.testing.expect(false);
        return;
    };

    // DH property: both sides derive same secret
    try std.testing.expectEqualSlices(u8, &shared1, &shared2);
}

// ============================================================================
// KEY DERIVATION TESTS
// ============================================================================

test "zcrypto.kdf: HKDF-SHA256" {
    const allocator = std.testing.allocator;

    const ikm = "input key material";
    const salt = "salt value";
    const info = "quic key expansion";

    const okm = try zcrypto.kdf.hkdfSha256(allocator, ikm, salt, info, 42);
    defer allocator.free(okm);

    try std.testing.expect(okm.len == 42);

    // Verify determinism - same inputs produce same output
    const okm2 = try zcrypto.kdf.hkdfSha256(allocator, ikm, salt, info, 42);
    defer allocator.free(okm2);

    try std.testing.expectEqualSlices(u8, okm, okm2);
}

// ============================================================================
// RANDOM NUMBER GENERATION TESTS
// ============================================================================

test "zcrypto.rand: fillBytes produces unique output" {
    var buffer1: [32]u8 = undefined;
    var buffer2: [32]u8 = undefined;

    zcrypto.rand.fill(&buffer1);
    zcrypto.rand.fill(&buffer2);

    // Extremely high probability they differ
    try std.testing.expect(!std.mem.eql(u8, &buffer1, &buffer2));
}

// ============================================================================
// SECURE MEMORY OPERATIONS TESTS
// ============================================================================

test "zcrypto.util: secureZero clears memory" {
    var sensitive: [64]u8 = [_]u8{0xFF} ** 64;

    zcrypto.util.secureZero(&sensitive);

    for (sensitive) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "zcrypto.util: constantTimeCompare" {
    const data1 = [_]u8{ 1, 2, 3, 4, 5 };
    const data2 = [_]u8{ 1, 2, 3, 4, 5 };
    const data3 = [_]u8{ 1, 2, 3, 4, 6 };

    try std.testing.expect(zcrypto.util.constantTimeCompare(&data1, &data2));
    try std.testing.expect(!zcrypto.util.constantTimeCompare(&data1, &data3));
}

// ============================================================================
// ENHANCED TLS CONTEXT TESTS
// ============================================================================

test "EnhancedTlsContext: packet encryption roundtrip" {
    const allocator = std.testing.allocator;

    var tls_ctx = try EnhancedTlsContext.init(
        allocator,
        false, // client
        .aes_256_gcm_sha384,
    );
    defer tls_ctx.deinit();

    const connection_id = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try tls_ctx.initializeInitialKeys(&connection_id);

    const plaintext = "QUIC packet payload";
    const packet_number: u64 = 42;
    const aad = "header";

    const ciphertext = try tls_ctx.encryptPacket(
        .initial,
        plaintext,
        packet_number,
        aad,
    );
    defer allocator.free(ciphertext);

    const decrypted = try tls_ctx.decryptPacket(
        .initial,
        ciphertext,
        packet_number,
        aad,
    );
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

// ============================================================================
// POST-QUANTUM KEY EXCHANGE TESTS
// ============================================================================

test "PQQuicContext: hybrid key exchange" {
    const allocator = std.testing.allocator;

    // Client and server TLS contexts
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();

    // PQ contexts with ML-KEM-768 hybrid
    var client_pq = try PQQuicContext.init(allocator, &client_tls, .ml_kem_768_x25519_sha256);
    defer client_pq.deinit();

    var server_pq = try PQQuicContext.init(allocator, &server_tls, .ml_kem_768_x25519_sha256);
    defer server_pq.deinit();

    // Server generates keypair
    try server_pq.initKeyExchange();
    const server_public_keys = server_pq.key_exchange.?.getPublicKeys();

    // Client generates keypair and encapsulates
    try client_pq.initKeyExchange();
    const client_public_keys = client_pq.key_exchange.?.getPublicKeys();

    // Key exchange
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);
    try server_pq.key_exchange.?.decapsulate(ciphertext, client_public_keys);

    // Verify shared secrets match
    const client_secret = client_pq.key_exchange.?.getSharedSecret().?;
    const server_secret = server_pq.key_exchange.?.getSharedSecret().?;

    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}

// ============================================================================
// REGRESSION TESTS - Prevent recurrence of v0.9.9 bugs
// ============================================================================

test "regression: PQ decapsulation uses ciphertext parameter" {
    // Regression for v0.9.9 bug: decapsulation ignored ciphertext parameter
    // and used public key instead (ML-KEM requires actual ciphertext)
    const allocator = std.testing.allocator;

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();

    var client_pq = try PQQuicContext.init(allocator, &client_tls, .ml_kem_768_x25519_sha256);
    defer client_pq.deinit();

    var server_pq = try PQQuicContext.init(allocator, &server_tls, .ml_kem_768_x25519_sha256);
    defer server_pq.deinit();

    try server_pq.initKeyExchange();
    try client_pq.initKeyExchange();

    const server_public_keys = server_pq.key_exchange.?.getPublicKeys();
    const client_public_keys = client_pq.key_exchange.?.getPublicKeys();

    // Client encapsulates -> produces ciphertext
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);

    // Server MUST use ciphertext (the bug passed public key here)
    try server_pq.key_exchange.?.decapsulate(ciphertext, client_public_keys);

    // This would FAIL if decapsulation used public key instead of ciphertext
    const client_secret = client_pq.key_exchange.?.getSharedSecret().?;
    const server_secret = server_pq.key_exchange.?.getSharedSecret().?;
    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}

test "regression: X25519 shared secret via zcrypto is valid" {
    // Regression for v0.9.9 bug: deriveSharedSecret returned pointer to
    // stack memory causing use-after-free. This test verifies the zcrypto
    // API itself works correctly (the wrapper fix is in pq_quic.zig).
    const kp1 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };
    const kp2 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };

    const secret1 = zcrypto.kex.X25519.computeSharedSecret(kp1.private_key, kp2.public_key) catch {
        try std.testing.expect(false);
        return;
    };
    const secret2 = zcrypto.kex.X25519.computeSharedSecret(kp2.private_key, kp1.public_key) catch {
        try std.testing.expect(false);
        return;
    };

    // DH property
    try std.testing.expectEqualSlices(u8, &secret1, &secret2);

    // Verify non-zero (valid DH output)
    var all_zero = true;
    for (secret1) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

// ============================================================================
// ZCRYPTO v1.0.1 NEW FEATURES
// ============================================================================

test "zcrypto hash: SHA-384 streaming (v1.0.1)" {
    const data = "Hello, Post-Quantum QUIC with SHA-384!";

    var hasher = zcrypto.hash.Sha384.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 48);
}

test "PQQuicContext: ML-KEM-1024 hybrid key exchange" {
    const allocator = std.testing.allocator;

    // Client and server TLS contexts
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();

    // PQ contexts with ML-KEM-1024 + X25519 hybrid (renamed from ml_kem_1024_x448)
    var client_pq = try PQQuicContext.init(allocator, &client_tls, .ml_kem_1024_x25519_sha384);
    defer client_pq.deinit();

    var server_pq = try PQQuicContext.init(allocator, &server_tls, .ml_kem_1024_x25519_sha384);
    defer server_pq.deinit();

    // Server generates keypair
    try server_pq.initKeyExchange();
    const server_public_keys = server_pq.key_exchange.?.getPublicKeys();

    // Verify ML-KEM-1024 public key size (1568 bytes)
    try std.testing.expect(server_public_keys.kem_public_key.?.len == 1568);

    // Client generates keypair and encapsulates
    try client_pq.initKeyExchange();
    const client_public_keys = client_pq.key_exchange.?.getPublicKeys();

    // Key exchange
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);

    // Verify ML-KEM-1024 ciphertext size (1568 bytes)
    try std.testing.expect(ciphertext.len == 1568);

    try server_pq.key_exchange.?.decapsulate(ciphertext, client_public_keys);

    // Verify shared secrets match (SHA-384 = 48 bytes)
    const client_secret = client_pq.key_exchange.?.getSharedSecret().?;
    const server_secret = server_pq.key_exchange.?.getSharedSecret().?;

    try std.testing.expect(client_secret.len == 48);
    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}
