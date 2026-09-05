//! ZCrypto Integration Tests
//!
//! Tests for zcrypto integration with ZQUIC.
//!
//! NOTE: This test file is only compiled when both flags are set:
//!   -Dpost-quantum=true -Dexperimental-crypto=true
//!
//! ## Testing Strategy
//!
//! 1. **Stable ZCrypto APIs**:
//!    - `zcrypto.hash` (Sha256, Blake3) - streaming hash wrappers
//!    - `zcrypto.kex` (X25519) - key exchange primitives
//!    - `zcrypto.kdf` (hkdfSha256) - key derivation
//!    - `zcrypto.rand` (fill) - random number generation
//!    - `zcrypto.util` - secure memory operations
//!    - `zcrypto.sym` / `zcrypto.auth` - stable wrappers covered by
//!      `tests/zcrypto_stable_test.zig`
//!
//! 2. **Post-Quantum**: All PQ tests run since this file is only compiled
//!    when PQ is enabled by the build system.

const std = @import("std");
const zquic = @import("zquic");
const zcrypto = @import("zcrypto");

const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;
const PQQuicContext = zquic.PQQuicContext;
const PQAuthentication = zquic.PQAuthentication;
const PublicKeys = zquic.PostQuantum.PublicKeys;
const PQCipherSuite = zquic.PQCipherSuite;
const PQHandshakeTranscript = zquic.PostQuantum.PQHandshakeTranscript;

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
// STDLIB SYMMETRIC REFERENCE TESTS
// ============================================================================

test "stdlib reference: AES-256-GCM round trip" {
    const key: [32]u8 = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const nonce: [12]u8 = blk: {
        var bytes = std.mem.zeroes([12]u8);
        @memset(bytes[0..], 0x11);
        break :blk bytes;
    };
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

test "stdlib reference: ChaCha20-Poly1305 round trip" {
    const key: [32]u8 = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0x42);
        break :blk bytes;
    };
    const nonce: [12]u8 = blk: {
        var bytes = std.mem.zeroes([12]u8);
        @memset(bytes[0..], 0x11);
        break :blk bytes;
    };
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

test "zcrypto.rand: fill produces unique output" {
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
    var sensitive: [64]u8 = blk: {
        var bytes = std.mem.zeroes([64]u8);
        @memset(bytes[0..], 0xFF);
        break :blk bytes;
    };

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
// ZCRYPTO HASH COVERAGE
// ============================================================================

test "zcrypto hash: SHA-384 streaming" {
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

    // PQ contexts with ML-KEM-1024 + X25519 hybrid.
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

test "PQQuicContext: malformed ML-KEM inputs are rejected" {
    const allocator = std.testing.allocator;

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();

    var client_pq = try PQQuicContext.init(allocator, &client_tls, .ml_kem_768_x25519_sha256);
    defer client_pq.deinit();

    var server_pq = try PQQuicContext.init(allocator, &server_tls, .ml_kem_768_x25519_sha256);
    defer server_pq.deinit();

    try client_pq.initKeyExchange();
    try server_pq.initKeyExchange();

    const server_public_keys = server_pq.key_exchange.?.getPublicKeys();
    const client_public_keys = client_pq.key_exchange.?.getPublicKeys();
    const server_kem_key = server_public_keys.kem_public_key.?;
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);

    const malformed_server_keys = PublicKeys{
        .kem_public_key = server_kem_key[0 .. server_kem_key.len - 1],
        .classical_public_key = server_public_keys.classical_public_key,
    };
    try std.testing.expectError(
        error.CryptoError,
        client_pq.key_exchange.?.encapsulate(malformed_server_keys),
    );

    try std.testing.expectError(
        error.CryptoError,
        server_pq.key_exchange.?.decapsulate(ciphertext[0 .. ciphertext.len - 1], client_public_keys),
    );
}

test "PQQuicContext: tampered ML-KEM ciphertext causes shared secret mismatch" {
    const allocator = std.testing.allocator;

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();

    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();

    var client_pq = try PQQuicContext.init(allocator, &client_tls, .ml_kem_768_x25519_sha256);
    defer client_pq.deinit();

    var server_pq = try PQQuicContext.init(allocator, &server_tls, .ml_kem_768_x25519_sha256);
    defer server_pq.deinit();

    try client_pq.initKeyExchange();
    try server_pq.initKeyExchange();

    const server_public_keys = server_pq.key_exchange.?.getPublicKeys();
    const client_public_keys = client_pq.key_exchange.?.getPublicKeys();
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);

    const tampered_ciphertext = try allocator.dupe(u8, ciphertext);
    defer allocator.free(tampered_ciphertext);
    tampered_ciphertext[0] ^= 0x01;

    try server_pq.key_exchange.?.decapsulate(tampered_ciphertext, client_public_keys);

    const client_secret = client_pq.key_exchange.?.getSharedSecret().?;
    const server_secret = server_pq.key_exchange.?.getSharedSecret().?;
    try std.testing.expect(!std.mem.eql(u8, client_secret, server_secret));
}

test "PQAuthentication: ML-DSA rejects tampered signature message and key sizes" {
    const allocator = std.testing.allocator;
    const message = "zquic pq authentication transcript";
    const bad_message = "zquic pq authentication transcript mutated";

    const keypair = PQAuthentication.ML_DSA_65.KeyPair.generateRandom() catch {
        try std.testing.expect(false);
        return;
    };

    const signature = try PQAuthentication.signWithMlDsa(message, &keypair.private_key, allocator);
    defer allocator.free(signature);

    try std.testing.expect(try PQAuthentication.verifyMlDsaSignature(message, signature, &keypair.public_key));
    try std.testing.expect(!try PQAuthentication.verifyMlDsaSignature(bad_message, signature, &keypair.public_key));

    signature[0] ^= 0x01;
    try std.testing.expect(!try PQAuthentication.verifyMlDsaSignature(message, signature, &keypair.public_key));
    try std.testing.expect(!try PQAuthentication.verifyMlDsaSignature(message, signature[0 .. signature.len - 1], &keypair.public_key));
    try std.testing.expect(!try PQAuthentication.verifyMlDsaSignature(message, signature, keypair.public_key[0 .. keypair.public_key.len - 1]));
}

fn fixedBytes(comptime len: usize, value: u8) [len]u8 {
    var bytes = std.mem.zeroes([len]u8);
    @memset(bytes[0..], value);
    return bytes;
}

fn expectSha256(label: []const u8, data: []const u8, expected: [32]u8) !void {
    _ = label;
    const digest = zcrypto.hash.sha256(data);
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "PQC deterministic vectors: ML-KEM-768 and ML-KEM-1024" {
    const MLKEM768 = zcrypto.post_quantum.pq.ml_kem.ML_KEM_768;
    const MLKEM1024 = zcrypto.post_quantum.pq.ml_kem.ML_KEM_1024;

    const seed768 = fixedBytes(MLKEM768.SEED_SIZE, 0x21);
    const rand768 = fixedBytes(MLKEM768.SEED_SIZE, 0x22);
    const kp768 = try MLKEM768.KeyPair.generate(seed768);
    const enc768 = try MLKEM768.KeyPair.encapsulate(kp768.public_key, rand768);
    const dec768 = try kp768.decapsulate(enc768.ciphertext);

    try expectSha256("mlkem768 public", &kp768.public_key, .{ 0xe6, 0x80, 0x66, 0x9a, 0x5f, 0x0b, 0x84, 0x2f, 0x7c, 0x33, 0x06, 0x49, 0x7b, 0xdc, 0xc0, 0x24, 0x02, 0xcf, 0x4e, 0x69, 0x55, 0xae, 0xfb, 0x0e, 0xcc, 0x29, 0x75, 0x62, 0xe2, 0xe2, 0x15, 0x9a });
    try expectSha256("mlkem768 private", &kp768.private_key, .{ 0x32, 0xad, 0xb7, 0x6a, 0x48, 0x2a, 0x92, 0xeb, 0x4e, 0x3b, 0x94, 0x15, 0x70, 0x8f, 0xe8, 0x58, 0x66, 0x4c, 0xf2, 0xa4, 0x1d, 0x77, 0x32, 0x45, 0x3f, 0x63, 0x50, 0xa7, 0x20, 0x5a, 0xa9, 0x3d });
    try expectSha256("mlkem768 ciphertext", &enc768.ciphertext, .{ 0x95, 0xc1, 0xb1, 0x9a, 0x16, 0xf4, 0x91, 0x1a, 0x00, 0x04, 0x7d, 0xef, 0x01, 0x48, 0x20, 0xf9, 0x84, 0x56, 0xbc, 0x97, 0x3b, 0xbb, 0xd4, 0x48, 0xa2, 0x5b, 0x7a, 0x21, 0x17, 0x82, 0xa1, 0xda });
    try expectSha256("mlkem768 shared", &enc768.shared_secret, .{ 0x2c, 0x19, 0xfb, 0xc1, 0x55, 0xec, 0x35, 0xdf, 0x6b, 0xd8, 0xfd, 0xbf, 0xc3, 0x8e, 0x29, 0xd6, 0xba, 0xac, 0x6e, 0xc9, 0x1f, 0x91, 0xc8, 0x38, 0xfb, 0xc3, 0xd0, 0xcf, 0x93, 0x66, 0xab, 0x57 });
    try std.testing.expectEqualSlices(u8, &enc768.shared_secret, &dec768);

    const seed1024 = fixedBytes(MLKEM1024.SEED_SIZE, 0x31);
    const rand1024 = fixedBytes(MLKEM1024.SEED_SIZE, 0x32);
    const kp1024 = try MLKEM1024.KeyPair.generate(seed1024);
    const enc1024 = try MLKEM1024.KeyPair.encapsulate(kp1024.public_key, rand1024);
    const dec1024 = try kp1024.decapsulate(enc1024.ciphertext);

    try expectSha256("mlkem1024 public", &kp1024.public_key, .{ 0x37, 0x84, 0x54, 0x42, 0x89, 0x87, 0xbe, 0x5b, 0xc1, 0xec, 0x01, 0x4d, 0x7a, 0xd1, 0x0b, 0xf0, 0xe2, 0x62, 0x32, 0xab, 0x7a, 0x30, 0x82, 0xf5, 0x35, 0x2c, 0x18, 0x7d, 0xfa, 0xea, 0xa4, 0xf8 });
    try expectSha256("mlkem1024 private", &kp1024.private_key, .{ 0xe0, 0x7b, 0x8b, 0x77, 0x14, 0x64, 0x78, 0xe5, 0x86, 0xb6, 0x6d, 0xaa, 0x8c, 0xde, 0x6b, 0x6c, 0x1f, 0x7d, 0x67, 0x14, 0x36, 0x08, 0x49, 0xd8, 0x26, 0x5d, 0xb6, 0xcf, 0x09, 0x3d, 0x3d, 0x50 });
    try expectSha256("mlkem1024 ciphertext", &enc1024.ciphertext, .{ 0xb8, 0xfe, 0x83, 0x62, 0x6d, 0xed, 0x7c, 0xed, 0x5c, 0x01, 0x1f, 0x87, 0x79, 0x0c, 0xc5, 0x3e, 0x0b, 0xdb, 0x42, 0xba, 0x60, 0xc7, 0x43, 0xfe, 0xf7, 0x0b, 0xd8, 0x57, 0xcd, 0xb2, 0x23, 0x4e });
    try expectSha256("mlkem1024 shared", &enc1024.shared_secret, .{ 0x71, 0xf6, 0xbe, 0x69, 0x23, 0x61, 0xe9, 0x75, 0xc7, 0x40, 0x23, 0x2f, 0xab, 0x70, 0x41, 0x68, 0x3e, 0xf5, 0x1e, 0x5f, 0x42, 0x26, 0x49, 0x64, 0xe0, 0x74, 0x16, 0xb6, 0x52, 0xd6, 0x82, 0x5f });
    try std.testing.expectEqualSlices(u8, &enc1024.shared_secret, &dec1024);
}

test "PQC deterministic vectors: ML-DSA-65 signature" {
    const MLDSA65 = zcrypto.post_quantum.pq.ml_dsa.ML_DSA_65;
    const seed = fixedBytes(MLDSA65.SEED_SIZE, 0x41);
    const randomness = fixedBytes(MLDSA65.NOISE_SIZE, 0x42);
    const message = "zquic phase 6 deterministic ML-DSA vector";

    const keypair = try MLDSA65.KeyPair.generate(seed);
    const signature = try keypair.sign(message, randomness);

    try expectSha256("mldsa65 public", &keypair.public_key, .{ 0xb3, 0x9d, 0x9c, 0xfb, 0x66, 0x08, 0x2c, 0x73, 0x94, 0x80, 0x9e, 0xf1, 0x52, 0x54, 0x2a, 0xa8, 0x82, 0x00, 0xff, 0x9c, 0xe7, 0xf5, 0x2f, 0x46, 0xd9, 0xcf, 0x80, 0x40, 0xda, 0xdc, 0x49, 0x13 });
    try expectSha256("mldsa65 private", &keypair.private_key, .{ 0xc9, 0x23, 0xf2, 0x6a, 0xf2, 0xf6, 0x13, 0xe5, 0x91, 0x44, 0xb5, 0xf7, 0x14, 0xce, 0xfb, 0xd4, 0x7f, 0x67, 0x8a, 0x18, 0xdb, 0xf8, 0x94, 0x96, 0x76, 0xbb, 0x81, 0xc3, 0xf6, 0x41, 0x1c, 0x5e });
    try expectSha256("mldsa65 signature", &signature, .{ 0x41, 0xcb, 0xa9, 0xce, 0x6a, 0x5f, 0x41, 0xec, 0x1b, 0xfe, 0xe2, 0xb6, 0x2a, 0xc9, 0x02, 0x7f, 0x81, 0x3a, 0x73, 0xe4, 0x0a, 0x7c, 0x85, 0x66, 0xff, 0x56, 0x56, 0x13, 0xce, 0x04, 0xf0, 0x89 });
    try std.testing.expect(try MLDSA65.KeyPair.verify(keypair.public_key, message, signature));
    try std.testing.expect(!try MLDSA65.KeyPair.verify(keypair.public_key, "wrong message", signature));
}

test "PQC deterministic vectors: transcript hash binding" {
    const kem_pk = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE, 0xA1);
    const x25519_pk = fixedBytes(32, 0xB2);
    const ciphertext = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE, 0xC3);

    const base = PQHandshakeTranscript{
        .cipher_suite = .ml_kem_768_x25519_sha256,
        .role = .client,
        .kem_public_key = &kem_pk,
        .classical_public_key = &x25519_pk,
        .kem_ciphertext = &ciphertext,
        .experimental_crypto = true,
    };

    try std.testing.expectEqualSlices(u8, &.{ 0xf7, 0xc2, 0x4b, 0xab, 0xbc, 0xe4, 0x7e, 0xea, 0xde, 0x19, 0x2e, 0x4e, 0xd0, 0x06, 0x9a, 0x89, 0xaf, 0x69, 0xd0, 0xe3, 0xa0, 0x45, 0xf7, 0x98, 0x12, 0xf8, 0xaa, 0x4f, 0x6c, 0xc8, 0xd7, 0x2e }, &(try base.hash()));

    var server_role = base;
    server_role.role = .server;
    try std.testing.expectEqualSlices(u8, &.{ 0x45, 0xf6, 0xe1, 0x11, 0x6b, 0x1d, 0xba, 0x9a, 0x3d, 0x15, 0xc3, 0x01, 0x33, 0x46, 0xe7, 0x04, 0xf9, 0xfd, 0xf9, 0xed, 0x95, 0xac, 0xaf, 0x68, 0x48, 0xeb, 0xf0, 0x10, 0xf1, 0x94, 0xf7, 0x45 }, &(try server_role.hash()));

    var suite_changed = base;
    suite_changed.cipher_suite = .ml_kem_768_sha256;
    suite_changed.classical_public_key = null;
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0x56, 0x36, 0x70, 0x0b, 0x01, 0xd4, 0x4e, 0xf0, 0xa0, 0xb4, 0xb5, 0xfa, 0x80, 0x9c, 0x7f, 0xef, 0x39, 0x0c, 0x40, 0x11, 0xed, 0xfa, 0x5a, 0x47, 0x6a, 0x1d, 0x19, 0x45, 0x0c, 0x89, 0xfd }, &(try suite_changed.hash()));

    var ciphertext_changed_bytes = ciphertext;
    ciphertext_changed_bytes[0] = 0xC2;
    var ciphertext_changed = base;
    ciphertext_changed.kem_ciphertext = &ciphertext_changed_bytes;
    try std.testing.expectEqualSlices(u8, &.{ 0x39, 0xbc, 0x4c, 0x3d, 0xdd, 0x1e, 0xb2, 0x6b, 0xc5, 0x3f, 0xd2, 0x66, 0xb9, 0xf8, 0xc5, 0x8e, 0x27, 0x7d, 0xd1, 0xb1, 0x97, 0xbd, 0x89, 0xac, 0xaf, 0xad, 0xf9, 0x99, 0xe0, 0x82, 0xbb, 0x35 }, &(try ciphertext_changed.hash()));
}

fn appendU16(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .big);
    try buffer.appendSlice(allocator, &bytes);
}

fn appendU32(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .big);
    try buffer.appendSlice(allocator, &bytes);
}

fn appendSliceField(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try appendU32(buffer, allocator, @intCast(value.len));
    try buffer.appendSlice(allocator, value);
}

fn serializeTranscriptTrace(allocator: std.mem.Allocator, transcript: PQHandshakeTranscript) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);

    try appendU16(&buffer, allocator, PQHandshakeTranscript.version);
    try appendU16(&buffer, allocator, transcript.cipher_suite.id());
    try buffer.append(allocator, @backingInt(transcript.role));
    try buffer.append(allocator, if (transcript.experimental_crypto) 1 else 0);
    try appendSliceField(&buffer, allocator, transcript.kem_public_key);
    try appendSliceField(&buffer, allocator, transcript.classical_public_key orelse &[_]u8{});
    try appendSliceField(&buffer, allocator, transcript.kem_ciphertext);

    return try buffer.toOwnedSlice(allocator);
}

fn readU16(trace: []const u8, offset: *usize) !u16 {
    if (offset.* + 2 > trace.len) return error.InvalidTrace;
    const value = std.mem.readInt(u16, trace[offset.*..][0..2], .big);
    offset.* += 2;
    return value;
}

fn readU32(trace: []const u8, offset: *usize) !u32 {
    if (offset.* + 4 > trace.len) return error.InvalidTrace;
    const value = std.mem.readInt(u32, trace[offset.*..][0..4], .big);
    offset.* += 4;
    return value;
}

fn readSlice(trace: []const u8, offset: *usize) ![]const u8 {
    const len = try readU32(trace, offset);
    if (offset.* + len > trace.len) return error.InvalidTrace;
    const value = trace[offset.* .. offset.* + len];
    offset.* += len;
    return value;
}

fn suiteFromTraceId(id: u16) !PQCipherSuite {
    return switch (id) {
        0x0001 => .ml_kem_768_x25519_sha256,
        0x0002 => .ml_kem_1024_x25519_sha384,
        0x0003 => .ml_kem_768_sha256,
        else => error.InvalidTrace,
    };
}

fn parseTranscriptTrace(trace: []const u8) !PQHandshakeTranscript {
    var offset: usize = 0;
    const version = try readU16(trace, &offset);
    if (version != PQHandshakeTranscript.version) return error.InvalidTrace;

    const cipher_suite = try suiteFromTraceId(try readU16(trace, &offset));
    if (offset + 2 > trace.len) return error.InvalidTrace;
    const role: zquic.PostQuantum.PQTranscriptRole = switch (trace[offset]) {
        0 => .client,
        1 => .server,
        else => return error.InvalidTrace,
    };
    offset += 1;
    const experimental_crypto = switch (trace[offset]) {
        0 => false,
        1 => true,
        else => return error.InvalidTrace,
    };
    offset += 1;

    const kem_public_key = try readSlice(trace, &offset);
    const classical_public_key = try readSlice(trace, &offset);
    const kem_ciphertext = try readSlice(trace, &offset);
    if (offset != trace.len) return error.InvalidTrace;

    return .{
        .cipher_suite = cipher_suite,
        .role = role,
        .kem_public_key = kem_public_key,
        .classical_public_key = if (classical_public_key.len == 0) null else classical_public_key,
        .kem_ciphertext = kem_ciphertext,
        .experimental_crypto = experimental_crypto,
    };
}

const interop_magic = "ZQIC-PQTR";

fn serializeInteropTraceBundle(allocator: std.mem.Allocator, client: PQHandshakeTranscript, server: PQHandshakeTranscript) ![]u8 {
    const client_trace = try serializeTranscriptTrace(allocator, client);
    defer allocator.free(client_trace);
    const server_trace = try serializeTranscriptTrace(allocator, server);
    defer allocator.free(server_trace);
    const client_hash = try client.hash();
    const server_hash = try server.hash();

    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);
    try buffer.appendSlice(allocator, interop_magic);
    try appendU16(&buffer, allocator, PQHandshakeTranscript.version);
    try appendSliceField(&buffer, allocator, client_trace);
    try appendSliceField(&buffer, allocator, server_trace);
    try buffer.appendSlice(allocator, &client_hash);
    try buffer.appendSlice(allocator, &server_hash);
    return try buffer.toOwnedSlice(allocator);
}

const ParsedInteropTraceBundle = struct {
    client: PQHandshakeTranscript,
    server: PQHandshakeTranscript,
    client_hash: [32]u8,
    server_hash: [32]u8,
};

fn parseInteropTraceBundle(bundle: []const u8) !ParsedInteropTraceBundle {
    var offset: usize = 0;
    if (bundle.len < interop_magic.len + 2) return error.InvalidTrace;
    if (!std.mem.eql(u8, bundle[offset..][0..interop_magic.len], interop_magic)) return error.InvalidTrace;
    offset += interop_magic.len;

    const version = try readU16(bundle, &offset);
    if (version != PQHandshakeTranscript.version) return error.InvalidTrace;

    const client_trace = try readSlice(bundle, &offset);
    const server_trace = try readSlice(bundle, &offset);
    if (offset + 64 != bundle.len) return error.InvalidTrace;

    const client = try parseTranscriptTrace(client_trace);
    const server = try parseTranscriptTrace(server_trace);
    const client_hash: [32]u8 = bundle[offset..][0..32].*;
    offset += 32;
    const server_hash: [32]u8 = bundle[offset..][0..32].*;

    if (!std.mem.eql(u8, &client_hash, &(try client.hash()))) return error.InvalidTrace;
    if (!std.mem.eql(u8, &server_hash, &(try server.hash()))) return error.InvalidTrace;

    return .{
        .client = client,
        .server = server,
        .client_hash = client_hash,
        .server_hash = server_hash,
    };
}

fn serializeInteropTraceBundleWithTransport(
    allocator: std.mem.Allocator,
    client: PQHandshakeTranscript,
    server: PQHandshakeTranscript,
    transport_parameters: []const u8,
) ![]u8 {
    const base = try serializeInteropTraceBundle(allocator, client, server);
    defer allocator.free(base);
    const tp_hash = zcrypto.hash.sha256(transport_parameters);

    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);
    try appendSliceField(&buffer, allocator, base);
    try appendSliceField(&buffer, allocator, transport_parameters);
    try buffer.appendSlice(allocator, &tp_hash);
    return try buffer.toOwnedSlice(allocator);
}

fn parseInteropTraceBundleWithTransport(bundle: []const u8) !struct {
    base: ParsedInteropTraceBundle,
    transport_parameters: []const u8,
    transport_hash: [32]u8,
} {
    var offset: usize = 0;
    const base_bundle = try readSlice(bundle, &offset);
    const transport_parameters = try readSlice(bundle, &offset);
    if (offset + 32 != bundle.len) return error.InvalidTrace;
    const transport_hash: [32]u8 = bundle[offset..][0..32].*;
    if (!std.mem.eql(u8, &transport_hash, &zcrypto.hash.sha256(transport_parameters))) return error.InvalidTrace;

    return .{
        .base = try parseInteropTraceBundle(base_bundle),
        .transport_parameters = transport_parameters,
        .transport_hash = transport_hash,
    };
}

test "PQC interop trace: serialized transcript replay" {
    const allocator = std.testing.allocator;
    const kem_pk = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE, 0xA1);
    const x25519_pk = fixedBytes(32, 0xB2);
    const ciphertext = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE, 0xC3);
    const secret = fixedBytes(32, 0xD4);

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

    const client_trace = try serializeTranscriptTrace(allocator, client);
    defer allocator.free(client_trace);
    const server_trace = try serializeTranscriptTrace(allocator, server);
    defer allocator.free(server_trace);

    const replayed_client = try parseTranscriptTrace(client_trace);
    const replayed_server = try parseTranscriptTrace(server_trace);

    try std.testing.expectEqualSlices(u8, &(try client.hash()), &(try replayed_client.hash()));
    try std.testing.expectEqualSlices(u8, &(try server.hash()), &(try replayed_server.hash()));
    try std.testing.expect(try PQHandshakeTranscript.secretsMatch(replayed_client, replayed_server, &secret, &secret));

    const tampered_trace = try allocator.dupe(u8, server_trace);
    defer allocator.free(tampered_trace);
    tampered_trace[tampered_trace.len - 1] ^= 0x01;
    const tampered_server = try parseTranscriptTrace(tampered_trace);
    try std.testing.expect(!try PQHandshakeTranscript.secretsMatch(replayed_client, tampered_server, &secret, &secret));
}

test "PQC interop trace: bundled multi-suite replay and tamper rejection" {
    const allocator = std.testing.allocator;

    const cases = .{
        .{
            .suite = PQCipherSuite.ml_kem_768_x25519_sha256,
            .kem_len = zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE,
            .ct_len = zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE,
            .seed = 0x31,
        },
        .{
            .suite = PQCipherSuite.ml_kem_1024_x25519_sha384,
            .kem_len = zcrypto.post_quantum.pq.ml_kem.ML_KEM_1024.PUBLIC_KEY_SIZE,
            .ct_len = zcrypto.post_quantum.pq.ml_kem.ML_KEM_1024.CIPHERTEXT_SIZE,
            .seed = 0x63,
        },
    };

    inline for (cases) |case| {
        const kem_pk = fixedBytes(case.kem_len, case.seed);
        const x25519_pk = fixedBytes(32, case.seed + 1);
        const ciphertext = fixedBytes(case.ct_len, case.seed + 2);
        const secret = fixedBytes(32, case.seed + 3);

        const client = PQHandshakeTranscript{
            .cipher_suite = case.suite,
            .role = .client,
            .kem_public_key = &kem_pk,
            .classical_public_key = &x25519_pk,
            .kem_ciphertext = &ciphertext,
            .experimental_crypto = true,
        };
        var server = client;
        server.role = .server;

        const bundle = try serializeInteropTraceBundle(allocator, client, server);
        defer allocator.free(bundle);
        const parsed = try parseInteropTraceBundle(bundle);
        try std.testing.expect(try PQHandshakeTranscript.secretsMatch(parsed.client, parsed.server, &secret, &secret));

        const truncated = bundle[0 .. bundle.len - 1];
        try std.testing.expectError(error.InvalidTrace, parseInteropTraceBundle(truncated));

        const tampered = try allocator.dupe(u8, bundle);
        defer allocator.free(tampered);
        tampered[tampered.len - 5] ^= 0x80;
        try std.testing.expectError(error.InvalidTrace, parseInteropTraceBundle(tampered));
    }
}

test "PQC interop trace: transport parameter replay and mutation rejection" {
    const allocator = std.testing.allocator;
    const kem_pk = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE, 0x91);
    const x25519_pk = fixedBytes(32, 0x92);
    const ciphertext = fixedBytes(zcrypto.post_quantum.pq.ml_kem.ML_KEM_768.CIPHERTEXT_SIZE, 0x93);
    const secret = fixedBytes(32, 0x94);

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

    const transport_parameters = [_]u8{
        0x04, 0x02, 0x40, 0x64, // initial_max_data
        0x0c, 0x00, // disable_active_migration
        0x0e, 0x01, 0x02, // active_connection_id_limit
    };

    const bundle = try serializeInteropTraceBundleWithTransport(allocator, client, server, &transport_parameters);
    defer allocator.free(bundle);

    const parsed = try parseInteropTraceBundleWithTransport(bundle);
    try std.testing.expectEqualSlices(u8, &transport_parameters, parsed.transport_parameters);
    try std.testing.expect(try PQHandshakeTranscript.secretsMatch(parsed.base.client, parsed.base.server, &secret, &secret));

    const replayed = try parseInteropTraceBundleWithTransport(bundle);
    try std.testing.expectEqualSlices(u8, &parsed.transport_hash, &replayed.transport_hash);

    var tampered = try allocator.dupe(u8, bundle);
    defer allocator.free(tampered);
    tampered[tampered.len - 33] ^= 0x01;
    try std.testing.expectError(error.InvalidTrace, parseInteropTraceBundleWithTransport(tampered));
}
