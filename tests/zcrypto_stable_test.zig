//! ZCrypto Stable API Tests
//!
//! Tests for stable zcrypto APIs that run on every build.
//! These do not require post-quantum flags.
//!
//! Stable modules tested:
//! - zcrypto root stable exports and CryptoError alias
//! - zcrypto.hash / blake3
//! - zcrypto.sym and key wrappers
//! - zcrypto.auth HMAC key wrapper
//! - zcrypto.kex / asym / kdf / rand / util
//! - zcrypto.quic_crypto / quic / key_rotation root exports

const std = @import("std");
const zcrypto = @import("zcrypto");

test "zcrypto stable root exports are available" {
    comptime {
        const stable_decls = .{
            "core",
            "CryptoError",
            "hash",
            "auth",
            "sym",
            "asym",
            "kdf",
            "rand",
            "util",
            "kex",
            "blake3",
            "quic_crypto",
            "quic",
            "key_rotation",
            "version",
            "build_config",
        };

        for (stable_decls) |decl| {
            if (!@hasDecl(zcrypto, decl)) {
                @compileError("missing zcrypto stable root export: " ++ decl);
            }
        }

        if (!@hasDecl(zcrypto.sym, "Aes256GcmKey")) @compileError("missing zcrypto.sym.Aes256GcmKey");
        if (!@hasDecl(zcrypto.sym, "ChaCha20Poly1305Key")) @compileError("missing zcrypto.sym.ChaCha20Poly1305Key");
        if (!@hasDecl(zcrypto.auth, "HmacKey")) @compileError("missing zcrypto.auth.HmacKey");
        if (!@hasDecl(zcrypto.quic_crypto, "QuicCrypto")) @compileError("missing zcrypto.quic_crypto.QuicCrypto");
        if (!@hasDecl(zcrypto.quic, "QuicCrypto")) @compileError("missing zcrypto.quic.QuicCrypto");
    }
}

test "zcrypto stable function signatures are force referenced" {
    const sha256_fn: fn ([]const u8) [32]u8 = zcrypto.hash.sha256;
    const sha384_fn: fn ([]const u8) [48]u8 = zcrypto.hash.sha384;
    const rand_fill_fn: fn ([]u8) void = zcrypto.rand.fill;
    const zero_fn: fn ([]u8) void = zcrypto.util.secureZero;
    const ct_cmp_fn: fn ([]const u8, []const u8) bool = zcrypto.util.constantTimeCompare;
    const aes_encrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.encryptAesGcm;
    const aes_decrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.decryptAesGcm;
    const chacha_encrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.encryptChaCha20;
    const chacha_decrypt_fn: fn (std.mem.Allocator, []const u8, *const [32]u8) zcrypto.sym.SymError![]u8 = zcrypto.sym.decryptChaCha20;

    _ = sha256_fn;
    _ = sha384_fn;
    _ = rand_fill_fn;
    _ = zero_fn;
    _ = ct_cmp_fn;
    _ = aes_encrypt_fn;
    _ = aes_decrypt_fn;
    _ = chacha_encrypt_fn;
    _ = chacha_decrypt_fn;
}

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

test "zcrypto hash: SHA-384 streaming" {
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
// SYMMETRIC ENCRYPTION TESTS
// ============================================================================

test "zcrypto.sym: stable AEAD wrappers round trip and reject tampering" {
    const allocator = std.testing.allocator;
    const plaintext = "Secret QUIC packet data";
    var key: [32]u8 = @splat(0x42);
    defer zcrypto.util.secureZero(&key);

    const aes_ciphertext = try zcrypto.sym.encryptAesGcm(allocator, plaintext, &key);
    defer allocator.free(aes_ciphertext);

    const aes_plaintext = try zcrypto.sym.decryptAesGcm(allocator, aes_ciphertext, &key);
    defer allocator.free(aes_plaintext);
    try std.testing.expectEqualStrings(plaintext, aes_plaintext);

    var tampered = try allocator.dupe(u8, aes_ciphertext);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(zcrypto.sym.SymError.DecryptionFailed, zcrypto.sym.decryptAesGcm(allocator, tampered, &key));

    const chacha_ciphertext = try zcrypto.sym.encryptChaCha20(allocator, plaintext, &key);
    defer allocator.free(chacha_ciphertext);

    const chacha_plaintext = try zcrypto.sym.decryptChaCha20(allocator, chacha_ciphertext, &key);
    defer allocator.free(chacha_plaintext);
    try std.testing.expectEqualStrings(plaintext, chacha_plaintext);
}

test "zcrypto.sym and auth key wrappers are callable" {
    const allocator = std.testing.allocator;

    var aes_key = zcrypto.sym.Aes256GcmKey.random();
    defer aes_key.zeroize();
    const aes_copy = aes_key.bytesCopy();
    try std.testing.expectEqualSlices(u8, aes_key.asBytes(), &aes_copy);

    var chacha_key = zcrypto.sym.ChaCha20Poly1305Key.random();
    defer chacha_key.zeroize();
    const chacha_copy = chacha_key.bytesCopy();
    try std.testing.expectEqualSlices(u8, chacha_key.asBytes(), &chacha_copy);

    var hmac_key = try zcrypto.auth.HmacKey.fromBytes(allocator, "zquic-hmac-key");
    defer hmac_key.deinit();
    const tag = zcrypto.auth.hmac.sha256("zquic-authenticated-data", hmac_key.asBytes());
    try std.testing.expect(zcrypto.auth.verifyHmacSha256("zquic-authenticated-data", hmac_key.asBytes(), tag));
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
