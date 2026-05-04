//! ZCrypto Stable API Tests
//!
//! Tests for stable zcrypto v1.0.1 APIs that run on every build.
//! These do not require post-quantum flags.
//!
//! Stable modules tested:
//! - zcrypto.hash (Sha256, Sha384, Blake3)
//! - zcrypto.kex (X25519)
//! - zcrypto.kdf (hkdfSha256)
//! - zcrypto.rand (fill)
//! - zcrypto.util (secureZero, constantTimeCompare)

const std = @import("std");
const zcrypto = @import("zcrypto");

// ============================================================================
// HASH TESTS
// ============================================================================

test "zcrypto hash: SHA-256 streaming" {
    const data = "Hello, ZQUIC!";

    var hasher = zcrypto.hash.Sha256.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 32);

    // Verify determinism - same input produces same output
    var hasher2 = zcrypto.hash.Sha256.init();
    hasher2.update(data);
    const digest2 = hasher2.final();
    try std.testing.expectEqualSlices(u8, &digest, &digest2);
}

test "zcrypto hash: SHA-256 one-shot" {
    const data = "Hello, ZQUIC!";
    const digest = zcrypto.hash.sha256(data);
    try std.testing.expect(digest.len == 32);
}

test "zcrypto hash: SHA-384 streaming (v1.0.1)" {
    const data = "Hello, ZQUIC with SHA-384!";

    var hasher = zcrypto.hash.Sha384.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 48);
}

test "zcrypto hash: Blake3 streaming" {
    const data = "Hello, ZQUIC!";

    // Blake3 is in its own module
    var hasher = zcrypto.blake3.Blake3.init();
    hasher.update(data);
    const digest = hasher.final();

    try std.testing.expect(digest.len == 32);
}

// ============================================================================
// SYMMETRIC ENCRYPTION TESTS (std.crypto baseline)
// ============================================================================

test "std.crypto: AES-256-GCM baseline" {
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

test "std.crypto: ChaCha20-Poly1305 baseline" {
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

test "zcrypto.kex: X25519 shared secret is valid (non-zero)" {
    const kp1 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };
    const kp2 = zcrypto.kex.X25519.generateKeypair() catch {
        try std.testing.expect(false);
        return;
    };

    const secret = zcrypto.kex.X25519.computeSharedSecret(kp1.private_key, kp2.public_key) catch {
        try std.testing.expect(false);
        return;
    };

    // Verify non-zero (valid DH output)
    var all_zero = true;
    for (secret) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
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
