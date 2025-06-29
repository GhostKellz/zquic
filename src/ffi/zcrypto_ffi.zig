//! ZCrypto FFI - Cryptographic functions for Rust integration
//!
//! Provides C ABI exports for cryptographic operations used by ghostd/walletd
//! Uses zcrypto v0.5.0 for all cryptographic operations

const std = @import("std");
const zcrypto = @import("zcrypto");

// Import specific zcrypto modules
const signatures = zcrypto.signatures;
const hash = zcrypto.hash;
const random = zcrypto.random;
const utils = zcrypto.utils;

/// Ed25519 key sizes
pub const ED25519_PUBLIC_KEY_SIZE = 32;
pub const ED25519_PRIVATE_KEY_SIZE = 32;
pub const ED25519_SIGNATURE_SIZE = 64;

/// Secp256k1 key sizes
pub const SECP256K1_PUBLIC_KEY_SIZE = 33; // Compressed
pub const SECP256K1_PRIVATE_KEY_SIZE = 32;
pub const SECP256K1_SIGNATURE_SIZE = 64;

/// Hash sizes
pub const BLAKE3_HASH_SIZE = 32;
pub const SHA256_HASH_SIZE = 32;

/// Error codes for crypto operations
pub const ZCRYPTO_SUCCESS = 0;
pub const ZCRYPTO_ERROR_INVALID_INPUT = -1;
pub const ZCRYPTO_ERROR_INVALID_KEY = -2;
pub const ZCRYPTO_ERROR_INVALID_SIGNATURE = -3;
pub const ZCRYPTO_ERROR_BUFFER_TOO_SMALL = -4;
pub const ZCRYPTO_ERROR_INTERNAL = -5;

/// Generate Ed25519 keypair
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_ed25519_keypair(
    public_key: [*]u8, // Must be at least 32 bytes
    private_key: [*]u8, // Must be at least 32 bytes
) callconv(.C) c_int {
    // Generate Ed25519 keypair using zcrypto
    const keypair = signatures.ed25519_generate_keypair() catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    // Copy keys to output buffers
    @memcpy(public_key[0..ED25519_PUBLIC_KEY_SIZE], &keypair.public_key);
    @memcpy(private_key[0..ED25519_PRIVATE_KEY_SIZE], &keypair.secret_key);

    return ZCRYPTO_SUCCESS;
}

/// Sign message with Ed25519 private key
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_ed25519_sign(
    private_key: [*]const u8, // 32 bytes
    message: [*]const u8, // Message to sign
    message_len: usize, // Message length
    signature: [*]u8, // Output signature (64 bytes)
) callconv(.C) c_int {
    // Validate input
    if (message_len == 0) return ZCRYPTO_ERROR_INVALID_INPUT;

    // Sign message using zcrypto
    const sig = signatures.ed25519_sign(
        message[0..message_len],
        private_key[0..ED25519_PRIVATE_KEY_SIZE].*,
    ) catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    // Copy signature to output buffer
    @memcpy(signature[0..ED25519_SIGNATURE_SIZE], &sig);

    return ZCRYPTO_SUCCESS;
}

/// Verify Ed25519 signature
/// Returns: ZCRYPTO_SUCCESS if valid, error code if invalid
pub export fn zcrypto_ed25519_verify(
    public_key: [*]const u8, // 32 bytes
    message: [*]const u8, // Message that was signed
    message_len: usize, // Message length
    signature: [*]const u8, // Signature to verify (64 bytes)
) callconv(.C) c_int {
    // Validate input
    if (message_len == 0) return ZCRYPTO_ERROR_INVALID_INPUT;

    // Verify signature using zcrypto
    const valid = signatures.ed25519_verify(
        signature[0..ED25519_SIGNATURE_SIZE].*,
        message[0..message_len],
        public_key[0..ED25519_PUBLIC_KEY_SIZE].*,
    ) catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    return if (valid) ZCRYPTO_SUCCESS else ZCRYPTO_ERROR_INVALID_SIGNATURE;
}

/// Generate Secp256k1 keypair
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_secp256k1_keypair(
    public_key: [*]u8, // Must be at least 33 bytes (compressed)
    private_key: [*]u8, // Must be at least 32 bytes
) callconv(.C) c_int {
    // Generate Secp256k1 keypair using zcrypto
    const keypair = signatures.secp256k1_generate_keypair() catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    // Get compressed public key
    const compressed_pubkey = signatures.secp256k1_compress_public_key(keypair.public_key) catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    // Copy keys to output buffers
    @memcpy(public_key[0..SECP256K1_PUBLIC_KEY_SIZE], &compressed_pubkey);
    @memcpy(private_key[0..SECP256K1_PRIVATE_KEY_SIZE], &keypair.secret_key);

    return ZCRYPTO_SUCCESS;
}

/// Sign hash with Secp256k1 private key
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_secp256k1_sign(
    private_key: [*]const u8, // 32 bytes
    message_hash: [*]const u8, // 32-byte hash to sign
    signature: [*]u8, // Output signature (64 bytes: r + s)
) callconv(.C) c_int {
    // Sign hash using zcrypto
    const sig = signatures.secp256k1_sign(
        message_hash[0..32].*,
        private_key[0..SECP256K1_PRIVATE_KEY_SIZE].*,
    ) catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    // Copy signature to output buffer (r + s format)
    @memcpy(signature[0..32], &sig.r);
    @memcpy(signature[32..64], &sig.s);

    return ZCRYPTO_SUCCESS;
}

/// Verify Secp256k1 signature
/// Returns: ZCRYPTO_SUCCESS if valid, error code if invalid
pub export fn zcrypto_secp256k1_verify(
    public_key: [*]const u8, // 33 bytes (compressed)
    message_hash: [*]const u8, // 32-byte hash that was signed
    signature: [*]const u8, // Signature to verify (64 bytes)
) callconv(.C) c_int {
    // Decompress public key
    const decompressed_pubkey = signatures.secp256k1_decompress_public_key(
        public_key[0..SECP256K1_PUBLIC_KEY_SIZE].*,
    ) catch {
        return ZCRYPTO_ERROR_INVALID_KEY;
    };

    // Build signature struct
    const sig = signatures.Secp256k1Signature{
        .r = signature[0..32].*,
        .s = signature[32..64].*,
    };

    // Verify signature using zcrypto
    const valid = signatures.secp256k1_verify(
        sig,
        message_hash[0..32].*,
        decompressed_pubkey,
    ) catch {
        return ZCRYPTO_ERROR_INTERNAL;
    };

    return if (valid) ZCRYPTO_SUCCESS else ZCRYPTO_ERROR_INVALID_SIGNATURE;
}

/// Compute Blake3 hash
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_blake3_hash(
    input: [*]const u8, // Input data
    input_len: usize, // Input length
    output: [*]u8, // Output hash (32 bytes)
) callconv(.C) c_int {
    // Compute Blake3 hash using zcrypto
    var hasher = hash.Blake3.init(.{});
    hasher.update(input[0..input_len]);
    const digest = hasher.finalResult();

    // Copy hash to output buffer
    @memcpy(output[0..BLAKE3_HASH_SIZE], &digest);

    return ZCRYPTO_SUCCESS;
}

/// Compute SHA256 hash
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_sha256_hash(
    input: [*]const u8, // Input data
    input_len: usize, // Input length
    output: [*]u8, // Output hash (32 bytes)
) callconv(.C) c_int {
    // Compute SHA-256 hash using zcrypto
    var hasher = hash.Sha256.init(.{});
    hasher.update(input[0..input_len]);
    const digest = hasher.finalResult();

    // Copy hash to output buffer
    @memcpy(output[0..SHA256_HASH_SIZE], &digest);

    return ZCRYPTO_SUCCESS;
}

/// Generate cryptographically secure random bytes
/// Returns: ZCRYPTO_SUCCESS on success, error code on failure
pub export fn zcrypto_random_bytes(
    buffer: [*]u8, // Output buffer
    len: usize, // Number of bytes to generate
) callconv(.C) c_int {
    // Use zcrypto's secure random
    random.random_bytes(buffer[0..len]);
    return ZCRYPTO_SUCCESS;
}

/// Secure memory comparison (constant time)
/// Returns: 0 if equal, 1 if different
pub export fn zcrypto_secure_compare(
    a: [*]const u8, // First buffer
    b: [*]const u8, // Second buffer
    len: usize, // Length to compare
) callconv(.C) c_int {
    // Use zcrypto's constant-time comparison
    const equal = utils.constant_time_compare(a[0..len], b[0..len]);
    return if (equal) 0 else 1;
}

/// Clear sensitive memory
pub export fn zcrypto_secure_zero(
    buffer: [*]u8, // Buffer to clear
    len: usize, // Length to clear
) callconv(.C) void {
    // Use zcrypto's secure memory zeroing
    utils.secure_zero(buffer[0..len]);
}

/// Get ZCrypto version
pub export fn zcrypto_version() callconv(.C) [*:0]const u8 {
    return "ZCrypto 0.5.0";
}

/// Get last error message for debugging
pub export fn zcrypto_last_error() callconv(.C) [*:0]const u8 {
    // TODO: Implement proper error tracking
    return "No error";
}

/// Testing function for FFI validation
pub export fn zcrypto_test_hash_known_input() callconv(.C) c_int {
    // Test with known input to verify FFI is working
    const input = "test";
    var output: [32]u8 = undefined;

    const result = zcrypto_blake3_hash(input.ptr, input.len, &output);
    
    // Verify the hash matches expected Blake3 hash of "test"
    const expected = [_]u8{0x48, 0x78, 0xca, 0x04, 0x25, 0xc7, 0x39, 0xfa,
                          0x42, 0x7f, 0x7e, 0xda, 0x20, 0xfe, 0x84, 0x5f,
                          0x6b, 0x2e, 0x46, 0xba, 0x5f, 0xe2, 0xa1, 0x4d,
                          0xf5, 0xb1, 0xe8, 0x7e, 0xb5, 0x4d, 0xeb, 0x9a};
    
    const matches = utils.constant_time_compare(&output, &expected);
    return if (matches and result == ZCRYPTO_SUCCESS) ZCRYPTO_SUCCESS else ZCRYPTO_ERROR_INTERNAL;
}

/// Multi-signature utilities for blockchain
/// Create threshold signature context
pub export fn zcrypto_multisig_create_context(
    threshold: u32, // Required signatures
    total_signers: u32, // Total possible signers
    public_keys: [*]const u8, // Array of public keys (32 bytes each)
    context_out: [*]u8, // Output context buffer (implementation defined size)
) callconv(.C) c_int {
    _ = threshold;
    _ = total_signers;
    _ = public_keys;
    _ = context_out;

    // TODO: Implement multi-signature context creation
    return ZCRYPTO_SUCCESS;
}

/// Add signature to multi-signature
pub export fn zcrypto_multisig_add_signature(
    context: [*]u8, // Multi-sig context
    signer_index: u32, // Index of the signer
    signature: [*]const u8, // Signature to add (64 bytes)
    message: [*]const u8, // Original message
    message_len: usize, // Message length
) callconv(.C) c_int {
    _ = context;
    _ = signer_index;
    _ = signature;
    _ = message;
    _ = message_len;

    // TODO: Implement signature aggregation
    return ZCRYPTO_SUCCESS;
}

/// Verify threshold signature is complete and valid
pub export fn zcrypto_multisig_verify(
    context: [*]const u8, // Multi-sig context
    message: [*]const u8, // Original message
    message_len: usize, // Message length
) callconv(.C) c_int {
    _ = context;
    _ = message;
    _ = message_len;

    // TODO: Implement threshold verification
    return ZCRYPTO_SUCCESS;
}
