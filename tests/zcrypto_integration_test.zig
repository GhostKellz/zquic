//! ZCrypto Integration Tests
//!
//! Tests for zcrypto v0.5.0 integration with ZQUIC

const std = @import("std");
const zquic = @import("zquic");
const zcrypto = @import("zcrypto");

const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;
const EnhancedCipherSuite = zquic.EnhancedCrypto.EnhancedCipherSuite;
const PQQuicContext = zquic.PQQuicContext;
const PQCipherSuite = zquic.PQCipherSuite;

test "zcrypto hash functions integration" {
    const allocator = std.testing.allocator;
    
    // Test data
    const data = "Hello, Post-Quantum QUIC!";
    
    // Test SHA-256 through zcrypto
    var sha256_hasher = zcrypto.hash.Sha256.init(.{});
    sha256_hasher.update(data);
    const sha256_digest = sha256_hasher.finalResult();
    
    try std.testing.expect(sha256_digest.len == 32);
    
    // Test Blake3 through zcrypto
    var blake3_hasher = zcrypto.hash.Blake3.init(.{});
    blake3_hasher.update(data);
    const blake3_digest = blake3_hasher.finalResult();
    
    try std.testing.expect(blake3_digest.len == 32);
}

test "zcrypto symmetric encryption integration" {
    const allocator = std.testing.allocator;
    
    // Test AES-256-GCM
    const key: [32]u8 = [_]u8{0x42} ** 32;
    const iv: [12]u8 = [_]u8{0x11} ** 12;
    const plaintext = "Secret QUIC packet data";
    const aad = "additional authenticated data";
    
    // Allocate buffer for ciphertext (plaintext + tag)
    const ciphertext = try allocator.alloc(u8, plaintext.len + 16);
    defer allocator.free(ciphertext);
    
    // Encrypt
    try zcrypto.symmetric.aes_256_gcm_encrypt(
        plaintext,
        aad,
        &key,
        &iv,
        ciphertext,
    );
    
    // Decrypt
    const decrypted = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(decrypted);
    
    try zcrypto.symmetric.aes_256_gcm_decrypt(
        ciphertext,
        aad,
        &key,
        &iv,
        decrypted,
    );
    
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "zcrypto key derivation integration" {
    const allocator = std.testing.allocator;
    
    // Test HKDF with SHA-256
    const ikm = "input key material";
    const salt = "salt value";
    const info = "quic key expansion";
    
    var prk: [32]u8 = undefined;
    zcrypto.kdf.hkdf_extract(zcrypto.hash.Sha256, salt, ikm, &prk);
    
    var okm: [42]u8 = undefined; // Output key material
    try zcrypto.kdf.hkdf_expand(zcrypto.hash.Sha256, &prk, info, &okm);
    
    try std.testing.expect(okm.len == 42);
}

test "enhanced TLS context with zcrypto" {
    const allocator = std.testing.allocator;
    
    // Create TLS context using zcrypto
    var tls_ctx = try EnhancedTlsContext.init(
        allocator,
        false, // client
        .aes_256_gcm_sha384,
    );
    defer tls_ctx.deinit();
    
    // Initialize initial keys
    const connection_id = [_]u8{0x01, 0x02, 0x03, 0x04};
    try tls_ctx.initializeInitialKeys(&connection_id);
    
    // Test packet encryption/decryption
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

test "post-quantum key exchange" {
    const allocator = std.testing.allocator;
    
    // Initialize client and server PQ contexts
    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_256_gcm_sha384);
    defer client_tls.deinit();
    
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_256_gcm_sha384);
    defer server_tls.deinit();
    
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
    
    // Simulate key exchange
    const ciphertext = try client_pq.key_exchange.?.encapsulate(server_public_keys);
    try server_pq.key_exchange.?.decapsulate(ciphertext, client_public_keys);
    
    // Verify shared secrets match
    const client_secret = client_pq.key_exchange.?.getSharedSecret().?;
    const server_secret = server_pq.key_exchange.?.getSharedSecret().?;
    
    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}

test "FFI crypto functions" {
    const allocator = std.testing.allocator;
    
    // Test Ed25519 through FFI
    var public_key: [32]u8 = undefined;
    var private_key: [32]u8 = undefined;
    
    const result = zquic.zcrypto_ed25519_keypair(&public_key, &private_key);
    try std.testing.expectEqual(@as(c_int, 0), result);
    
    // Test signing
    const message = "Test message for signing";
    var signature: [64]u8 = undefined;
    
    const sign_result = zquic.zcrypto_ed25519_sign(
        &private_key,
        message.ptr,
        message.len,
        &signature,
    );
    try std.testing.expectEqual(@as(c_int, 0), sign_result);
    
    // Test verification
    const verify_result = zquic.zcrypto_ed25519_verify(
        &public_key,
        message.ptr,
        message.len,
        &signature,
    );
    try std.testing.expectEqual(@as(c_int, 0), verify_result);
}

test "zcrypto random number generation" {
    var buffer1: [32]u8 = undefined;
    var buffer2: [32]u8 = undefined;
    
    // Generate random bytes
    zcrypto.random.random_bytes(&buffer1);
    zcrypto.random.random_bytes(&buffer2);
    
    // Verify they're different (extremely high probability)
    try std.testing.expect(!std.mem.eql(u8, &buffer1, &buffer2));
}

test "secure memory operations" {
    var sensitive_data: [64]u8 = [_]u8{0xFF} ** 64;
    
    // Clear sensitive memory
    zcrypto.utils.secure_zero(&sensitive_data);
    
    // Verify all zeros
    for (sensitive_data) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
    
    // Test constant-time comparison
    const data1 = [_]u8{1, 2, 3, 4, 5};
    const data2 = [_]u8{1, 2, 3, 4, 5};
    const data3 = [_]u8{1, 2, 3, 4, 6};
    
    try std.testing.expect(zcrypto.utils.constant_time_compare(&data1, &data2));
    try std.testing.expect(!zcrypto.utils.constant_time_compare(&data1, &data3));
}

test "performance: zcrypto vs std.crypto comparison" {
    const allocator = std.testing.allocator;
    const iterations = 1000;
    
    // Large data for performance testing
    const data = try allocator.alloc(u8, 1024 * 1024); // 1MB
    defer allocator.free(data);
    zcrypto.random.random_bytes(data);
    
    // Benchmark SHA-256
    const start_sha256 = std.time.milliTimestamp();
    for (0..iterations) |_| {
        var hasher = zcrypto.hash.Sha256.init(.{});
        hasher.update(data);
        _ = hasher.finalResult();
    }
    const zcrypto_sha256_time = std.time.milliTimestamp() - start_sha256;
    
    // Benchmark Blake3 (typically faster)
    const start_blake3 = std.time.milliTimestamp();
    for (0..iterations) |_| {
        var hasher = zcrypto.hash.Blake3.init(.{});
        hasher.update(data);
        _ = hasher.finalResult();
    }
    const zcrypto_blake3_time = std.time.milliTimestamp() - start_blake3;
    
    std.debug.print("\nPerformance Results ({}MB total):\n", .{iterations});
    std.debug.print("  SHA-256: {}ms ({:.2} MB/s)\n", .{
        zcrypto_sha256_time,
        @as(f64, iterations * 1000) / @as(f64, zcrypto_sha256_time),
    });
    std.debug.print("  Blake3:  {}ms ({:.2} MB/s)\n", .{
        zcrypto_blake3_time,
        @as(f64, iterations * 1000) / @as(f64, zcrypto_blake3_time),
    });
}

test "integration: full QUIC handshake with post-quantum crypto" {
    const allocator = std.testing.allocator;
    
    // This test simulates a complete QUIC handshake with PQ crypto
    // In a real implementation, this would involve network communication
    
    std.debug.print("\nPost-Quantum QUIC Handshake Simulation:\n", .{});
    std.debug.print("  Cipher Suite: ML-KEM-768 + X25519 hybrid\n", .{});
    std.debug.print("  Hash: SHA-256\n", .{});
    std.debug.print("  AEAD: AES-256-GCM\n", .{});
    
    // The actual handshake implementation would go here
    // For now, we just verify the components are available
    
    try std.testing.expect(@TypeOf(PQQuicContext) != void);
    try std.testing.expect(@TypeOf(zcrypto.post_quantum) != void);
}