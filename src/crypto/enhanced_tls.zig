//! Enhanced TLS 1.3 implementation for QUIC
//!
//! Provides QUIC TLS key derivation, packet AEAD, and header-protection helpers.
//! This is a utility surface, not a standalone production TLS implementation.

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const KeySchedule = @import("tls13_key_schedule.zig");

const hkdfExpandLabelSha256 = KeySchedule.hkdfExpandLabelSha256;

// Utility function for secure memory zeroing - uses std library implementation
fn secureZero(data: []u8) void {
    std.crypto.secureZero(u8, data);
}

// Import specific zcrypto modules
const hash = zcrypto.hash;
const symmetric = zcrypto.sym;
const kdf = zcrypto.kdf;
const random = zcrypto.rand;

/// Enhanced cipher suite with real cryptographic implementations
pub const EnhancedCipherSuite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,

    pub fn getKeyLength(self: @This()) u32 {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384 => 32,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    pub fn getIvLength(self: @This()) u32 {
        return switch (self) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 12,
            .chacha20_poly1305_sha256 => 12,
        };
    }

    pub fn getTagLength(_: @This()) u32 {
        return 16; // All supported cipher suites use 16-byte auth tags
    }

    pub fn getHashFunction(self: @This()) type {
        return switch (self) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => hash.Sha256,
            .aes_256_gcm_sha384 => hash.Sha384,
        };
    }

    /// Get the hash size for this cipher suite
    pub fn getHashSize(self: @This()) u32 {
        return switch (self) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
        };
    }
};

/// HKDF-based key derivation using std.crypto
/// Uses std.crypto.kdf.hkdf which provides HKDF per RFC 5869
pub const Hkdf = struct {
    /// HKDF-Extract function: (salt, IKM) -> PRK
    pub fn extract(comptime HashType: type, salt: []const u8, ikm: []const u8, prk: []u8) void {
        // Map zcrypto hash types to std.crypto HKDF
        const HkdfType = getHkdfType(HashType);
        const extracted = HkdfType.extract(salt, ikm);
        @memcpy(prk, &extracted);
    }

    /// HKDF-Expand function: (PRK, info) -> OKM
    pub fn expand(comptime HashType: type, prk: []const u8, info: []const u8, okm: []u8) !void {
        const HkdfType = getHkdfType(HashType);
        const prk_len = HkdfType.prk_length;
        if (prk.len < prk_len) return Error.ZquicError.CryptoError;
        HkdfType.expand(okm, info, prk[0..prk_len].*);
    }

    /// Map zcrypto/hash types to std.crypto HKDF types
    fn getHkdfType(comptime HashType: type) type {
        // Handle both zcrypto.hash and std.crypto.hash types.
        if (HashType == hash.Sha256 or HashType == std.crypto.hash.sha2.Sha256) {
            return std.crypto.kdf.hkdf.HkdfSha256;
        } else if (HashType == hash.Sha384 or HashType == std.crypto.hash.sha2.Sha384) {
            // Use HmacSha384 to construct the HKDF type
            return std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
        } else {
            @compileError("Unsupported hash type for HKDF");
        }
    }
};

pub const Rfc9001InitialDirection = struct {
    secret: [32]u8,
    key: [16]u8,
    iv: [12]u8,
    header_protection_key: [16]u8,
};

pub const Rfc9001InitialKeys = struct {
    initial_secret: [32]u8,
    client: Rfc9001InitialDirection,
    server: Rfc9001InitialDirection,
};

pub fn deriveRfc9001InitialKeys(destination_connection_id: []const u8) Error.ZquicError!Rfc9001InitialKeys {
    const initial_salt = [_]u8{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };

    var result: Rfc9001InitialKeys = undefined;
    result.initial_secret = std.crypto.kdf.hkdf.HkdfSha256.extract(
        &initial_salt,
        destination_connection_id,
    );

    try hkdfExpandLabelSha256(&result.initial_secret, "client in", &.{}, &result.client.secret);
    try hkdfExpandLabelSha256(&result.initial_secret, "server in", &.{}, &result.server.secret);
    try deriveRfc9001InitialDirection(&result.client);
    try deriveRfc9001InitialDirection(&result.server);

    return result;
}

fn deriveRfc9001InitialDirection(keys: *Rfc9001InitialDirection) Error.ZquicError!void {
    try hkdfExpandLabelSha256(&keys.secret, "quic key", &.{}, &keys.key);
    try hkdfExpandLabelSha256(&keys.secret, "quic iv", &.{}, &keys.iv);
    try hkdfExpandLabelSha256(&keys.secret, "quic hp", &.{}, &keys.header_protection_key);
}

/// Enhanced cryptographic keys with proper key derivation
pub const EnhancedCryptoKeys = struct {
    cipher_suite: EnhancedCipherSuite,
    secret: []u8,
    key: []u8,
    iv: []u8,
    header_protection_key: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, cipher_suite: EnhancedCipherSuite) !Self {
        const key_len = cipher_suite.getKeyLength();
        const iv_len = cipher_suite.getIvLength();

        const secret = try allocator.alloc(u8, 32); // 256-bit secret
        const key = try allocator.alloc(u8, key_len);
        const iv = try allocator.alloc(u8, iv_len);
        const hp_key = try allocator.alloc(u8, key_len);

        return Self{
            .cipher_suite = cipher_suite,
            .secret = secret,
            .key = key,
            .iv = iv,
            .header_protection_key = hp_key,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Zero out sensitive data securely
        secureZero(self.secret);
        secureZero(self.key);
        secureZero(self.iv);
        secureZero(self.header_protection_key);

        self.allocator.free(self.secret);
        self.allocator.free(self.key);
        self.allocator.free(self.iv);
        self.allocator.free(self.header_protection_key);
    }

    /// Derive keys from a master secret using HKDF
    pub fn deriveFromSecret(self: *Self, master_secret: []const u8, label: []const u8, context: []const u8) !void {
        // Build HKDF labels
        const info_key = try self.buildHkdfLabel(label, "key", context, self.key.len);
        defer self.allocator.free(info_key);
        const info_iv = try self.buildHkdfLabel(label, "iv", context, self.iv.len);
        defer self.allocator.free(info_iv);
        const info_hp = try self.buildHkdfLabel(label, "hp", context, self.header_protection_key.len);
        defer self.allocator.free(info_hp);

        // Runtime dispatch based on cipher suite
        switch (self.cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                var prk: [32]u8 = undefined;
                Hkdf.extract(hash.Sha256, "", master_secret, &prk);
                try Hkdf.expand(hash.Sha256, &prk, info_key, self.key);
                try Hkdf.expand(hash.Sha256, &prk, info_iv, self.iv);
                try Hkdf.expand(hash.Sha256, &prk, info_hp, self.header_protection_key);
                @memcpy(self.secret, prk[0..@min(self.secret.len, prk.len)]);
            },
            .aes_256_gcm_sha384 => {
                var prk: [48]u8 = undefined;
                Hkdf.extract(std.crypto.hash.sha2.Sha384, "", master_secret, &prk);
                try Hkdf.expand(std.crypto.hash.sha2.Sha384, &prk, info_key, self.key);
                try Hkdf.expand(std.crypto.hash.sha2.Sha384, &prk, info_iv, self.iv);
                try Hkdf.expand(std.crypto.hash.sha2.Sha384, &prk, info_hp, self.header_protection_key);
                @memcpy(self.secret, prk[0..@min(self.secret.len, prk.len)]);
            },
        }
    }

    /// Build HKDF label according to TLS 1.3 specification
    fn buildHkdfLabel(self: *Self, label: []const u8, purpose: []const u8, context: []const u8, length: usize) ![]u8 {
        const full_label = try std.fmt.allocPrint(self.allocator, "tls13 {s} {s}", .{ label, purpose });
        defer self.allocator.free(full_label);

        // HkdfLabel structure: length (2 bytes) + label length (1 byte) + label + context length (1 byte) + context
        const total_len = 2 + 1 + full_label.len + 1 + context.len;
        const hkdf_label = try self.allocator.alloc(u8, total_len);

        var offset: usize = 0;

        // Length (2 bytes, big-endian)
        std.mem.writeInt(u16, hkdf_label[offset..][0..2], @intCast(length), .big);
        offset += 2;

        // Label length and label
        hkdf_label[offset] = @intCast(full_label.len);
        offset += 1;
        @memcpy(hkdf_label[offset .. offset + full_label.len], full_label);
        offset += full_label.len;

        // Context length and context
        hkdf_label[offset] = @intCast(context.len);
        offset += 1;
        @memcpy(hkdf_label[offset .. offset + context.len], context);

        return hkdf_label;
    }
};

/// Enhanced AEAD encryption/decryption
pub const EnhancedAead = struct {
    /// Encrypt data using AES-GCM
    pub fn encryptAesGcm(key: []const u8, iv: []const u8, plaintext: []const u8, aad: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (key.len == 16) {
            const result = symmetric.encryptAes128Gcm(
                allocator,
                key[0..16].*,
                iv[0..12].*,
                plaintext,
                aad,
            ) catch {
                return Error.ZquicError.CryptoError;
            };
            defer result.deinit();

            // Combine ciphertext and tag
            const combined = try allocator.alloc(u8, result.data.len + 16);
            @memcpy(combined[0..result.data.len], result.data);
            @memcpy(combined[result.data.len..][0..16], &result.tag);
            return combined;
        } else if (key.len == 32) {
            const result = symmetric.encryptAes256Gcm(
                allocator,
                key[0..32].*,
                iv[0..12].*,
                plaintext,
                aad,
            ) catch {
                return Error.ZquicError.CryptoError;
            };
            defer result.deinit();

            // Combine ciphertext and tag
            const combined = try allocator.alloc(u8, result.data.len + 16);
            @memcpy(combined[0..result.data.len], result.data);
            @memcpy(combined[result.data.len..][0..16], &result.tag);
            return combined;
        } else {
            return Error.ZquicError.CryptoError;
        }
    }

    /// Decrypt data using AES-GCM
    pub fn decryptAesGcm(key: []const u8, iv: []const u8, ciphertext: []const u8, aad: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (ciphertext.len < 16) return Error.ZquicError.CryptoError;

        const plaintext_len = ciphertext.len - 16;

        // Extract tag from end of ciphertext
        var tag: [16]u8 = undefined;
        @memcpy(&tag, ciphertext[plaintext_len..][0..16]);

        if (key.len == 16) {
            const result = symmetric.decryptAes128Gcm(
                allocator,
                key[0..16].*,
                iv[0..12].*,
                ciphertext[0..plaintext_len],
                tag,
                aad,
            ) catch {
                return Error.ZquicError.CryptoError;
            };
            return result;
        } else if (key.len == 32) {
            const result = symmetric.decryptAes256Gcm(
                allocator,
                key[0..32].*,
                iv[0..12].*,
                ciphertext[0..plaintext_len],
                tag,
                aad,
            ) catch {
                return Error.ZquicError.CryptoError;
            };
            return result;
        } else {
            return Error.ZquicError.CryptoError;
        }
    }

    /// Encrypt data using ChaCha20-Poly1305
    pub fn encryptChaCha20Poly1305(key: []const u8, iv: []const u8, plaintext: []const u8, aad: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (key.len != 32 or iv.len != 12) return Error.ZquicError.CryptoError;

        const result = symmetric.encryptChaCha20Poly1305(
            allocator,
            key[0..32].*,
            iv[0..12].*,
            plaintext,
            aad,
        ) catch {
            return Error.ZquicError.CryptoError;
        };
        defer result.deinit();

        // Combine ciphertext and tag into single buffer
        const combined = try allocator.alloc(u8, result.data.len + 16);
        @memcpy(combined[0..result.data.len], result.data);
        @memcpy(combined[result.data.len..][0..16], &result.tag);

        return combined;
    }

    /// Decrypt data using ChaCha20-Poly1305
    pub fn decryptChaCha20Poly1305(key: []const u8, iv: []const u8, ciphertext: []const u8, aad: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (key.len != 32 or iv.len != 12 or ciphertext.len < 16) return Error.ZquicError.CryptoError;

        const plaintext_len = ciphertext.len - 16;

        // Extract tag from end of ciphertext
        var tag: [16]u8 = undefined;
        @memcpy(&tag, ciphertext[plaintext_len..][0..16]);

        const result = symmetric.decryptChaCha20Poly1305(
            allocator,
            key[0..32].*,
            iv[0..12].*,
            ciphertext[0..plaintext_len],
            tag,
            aad,
        ) catch {
            return Error.ZquicError.CryptoError;
        };
        return result;
    }
};

/// Enhanced header protection using AES-ECB or ChaCha20
pub const EnhancedHeaderProtection = struct {
    /// Generate header protection mask using AES-ECB
    pub fn generateAesMask(hp_key: []const u8, sample: []const u8) ![5]u8 {
        if (sample.len < 16) return Error.ZquicError.CryptoError;

        var mask: [16]u8 = undefined;

        if (hp_key.len == 16) {
            // AES-128-ECB using zcrypto
            symmetric.aes_128_ecb_encrypt(sample[0..16], hp_key[0..16], &mask) catch {
                return Error.ZquicError.CryptoError;
            };
        } else if (hp_key.len == 32) {
            // AES-256-ECB using zcrypto
            symmetric.aes_256_ecb_encrypt(sample[0..16], hp_key[0..32], &mask) catch {
                return Error.ZquicError.CryptoError;
            };
        } else {
            return Error.ZquicError.CryptoError;
        }

        return mask[0..5].*;
    }

    /// Generate header protection mask using ChaCha20
    pub fn generateChaCha20Mask(hp_key: []const u8, sample: []const u8) ![5]u8 {
        if (hp_key.len != 32 or sample.len < 16) return Error.ZquicError.CryptoError;

        // Use sample as nonce (first 12 bytes) and counter (last 4 bytes)
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, sample[0..12]);

        const counter = std.mem.readInt(u32, sample[12..16], .little);

        // ChaCha20 mask generation using zcrypto
        var mask: [64]u8 = undefined;
        symmetric.chacha20_generate_keystream(hp_key[0..32], &nonce, counter, &mask) catch {
            return Error.ZquicError.CryptoError;
        };

        return mask[0..5].*;
    }

    /// Apply header protection to packet
    /// The packet number length is determined from header[0] bits 0-1 (pn_len = bits + 1)
    /// For protection: read pn_length before masking, then apply mask
    pub fn protectHeader(cipher_suite: EnhancedCipherSuite, hp_key: []const u8, header: []u8, sample: []const u8) !void {
        if (header.len == 0) return Error.ZquicError.CryptoError;

        const mask = switch (cipher_suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => try generateAesMask(hp_key, sample),
            .chacha20_poly1305_sha256 => try generateChaCha20Mask(hp_key, sample),
        };

        // Determine packet number length from header flags (before protection)
        // Bits 0-1 encode (pn_length - 1), so values 0-3 mean 1-4 bytes
        const pn_length: usize = (header[0] & 0x03) + 1;

        // Verify header is long enough for the packet number
        if (header.len < pn_length) return Error.ZquicError.CryptoError;
        const pn_offset = header.len - pn_length;

        // Apply mask to first byte (protect flags)
        if ((header[0] & 0x80) != 0) {
            // Long header: protect lower 4 bits
            header[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: protect lower 5 bits
            header[0] ^= mask[0] & 0x1f;
        }

        // Apply mask to packet number bytes (only as many as indicated by pn_length)
        for (0..pn_length) |i| {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }

    /// Remove header protection from packet
    /// For unprotection: first unmask byte 0 to reveal pn_length, then unmask pn bytes
    pub fn unprotectHeader(cipher_suite: EnhancedCipherSuite, hp_key: []const u8, header: []u8, sample: []const u8) !void {
        if (header.len == 0) return Error.ZquicError.CryptoError;

        const mask = switch (cipher_suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => try generateAesMask(hp_key, sample),
            .chacha20_poly1305_sha256 => try generateChaCha20Mask(hp_key, sample),
        };

        // First, unmask the first byte to reveal the packet number length
        if ((header[0] & 0x80) != 0) {
            // Long header: unprotect lower 4 bits
            header[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: unprotect lower 5 bits
            header[0] ^= mask[0] & 0x1f;
        }

        // Now read the unmasked packet number length
        const pn_length: usize = (header[0] & 0x03) + 1;

        // Verify header is long enough for the packet number
        if (header.len < pn_length) return Error.ZquicError.CryptoError;
        const pn_offset = header.len - pn_length;

        // Unmask the packet number bytes
        for (0..pn_length) |i| {
            header[pn_offset + i] ^= mask[1 + i];
        }
    }
};

/// Enhanced TLS context with proper cryptography
pub const EnhancedTlsContext = struct {
    cipher_suite: EnhancedCipherSuite,
    is_server: bool,
    allocator: std.mem.Allocator,

    // Key material
    initial_keys: ?EnhancedCryptoKeys = null,
    handshake_keys: ?EnhancedCryptoKeys = null,
    application_keys: ?EnhancedCryptoKeys = null,

    // Random values
    client_random: [32]u8,
    server_random: [32]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool, cipher_suite: EnhancedCipherSuite) !Self {
        var context = Self{
            .cipher_suite = cipher_suite,
            .is_server = is_server,
            .allocator = allocator,
            .client_random = undefined,
            .server_random = undefined,
        };

        // Generate random values using zcrypto
        random.fill(&context.client_random);
        random.fill(&context.server_random);

        return context;
    }

    pub fn deinit(self: *Self) void {
        if (self.initial_keys) |*keys| keys.deinit();
        if (self.handshake_keys) |*keys| keys.deinit();
        if (self.application_keys) |*keys| keys.deinit();
    }

    /// Initialize initial keys for QUIC
    pub fn initializeInitialKeys(self: *Self, connection_id: []const u8) !void {
        const initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
        var salt_bytes: [20]u8 = undefined;
        _ = try std.fmt.hexToBytes(&salt_bytes, initial_salt);

        // Create initial keys first
        self.initial_keys = try EnhancedCryptoKeys.init(self.allocator, self.cipher_suite);

        // Derive initial secret based on cipher suite (runtime dispatch)
        // Use fixed buffer for largest hash size (SHA-384 = 48 bytes)
        var initial_secret: [48]u8 = undefined;
        const secret_len: usize = switch (self.cipher_suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => blk: {
                Hkdf.extract(hash.Sha256, &salt_bytes, connection_id, initial_secret[0..32]);
                break :blk 32;
            },
            .aes_256_gcm_sha384 => blk: {
                Hkdf.extract(hash.Sha384, &salt_bytes, connection_id, initial_secret[0..48]);
                break :blk 48;
            },
        };

        try self.initial_keys.?.deriveFromSecret(initial_secret[0..secret_len], "quic", "");
    }

    /// Derive handshake keys
    pub fn deriveHandshakeKeys(self: *Self, handshake_secret: []const u8) !void {
        self.handshake_keys = try EnhancedCryptoKeys.init(self.allocator, self.cipher_suite);
        try self.handshake_keys.?.deriveFromSecret(handshake_secret, "quic", "");
    }

    /// Derive application keys
    pub fn deriveApplicationKeys(self: *Self, master_secret: []const u8) !void {
        self.application_keys = try EnhancedCryptoKeys.init(self.allocator, self.cipher_suite);
        try self.application_keys.?.deriveFromSecret(master_secret, "quic", "");
    }

    /// Encrypt packet payload
    pub fn encryptPacket(self: *const Self, level: EncryptionLevel, plaintext: []const u8, packet_number: u64, aad: []const u8) ![]u8 {
        const keys = switch (level) {
            .initial => &self.initial_keys.?,
            .handshake => &self.handshake_keys.?,
            .application => &self.application_keys.?,
        };

        // Construct nonce by XORing IV with packet number
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv);

        const pn_bytes = std.mem.toBytes(packet_number);
        const iv_len = keys.iv.len;
        for (0..@min(8, iv_len)) |i| {
            nonce[iv_len - 8 + i] ^= pn_bytes[i];
        }

        return switch (self.cipher_suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => try EnhancedAead.encryptAesGcm(keys.key, &nonce, plaintext, aad, self.allocator),
            .chacha20_poly1305_sha256 => try EnhancedAead.encryptChaCha20Poly1305(keys.key, &nonce, plaintext, aad, self.allocator),
        };
    }

    /// Decrypt packet payload
    pub fn decryptPacket(self: *const Self, level: EncryptionLevel, ciphertext: []const u8, packet_number: u64, aad: []const u8) ![]u8 {
        const keys = switch (level) {
            .initial => &self.initial_keys.?,
            .handshake => &self.handshake_keys.?,
            .application => &self.application_keys.?,
        };

        // Construct nonce by XORing IV with packet number
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, keys.iv);

        const pn_bytes = std.mem.toBytes(packet_number);
        const iv_len = keys.iv.len;
        for (0..@min(8, iv_len)) |i| {
            nonce[iv_len - 8 + i] ^= pn_bytes[i];
        }

        return switch (self.cipher_suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => try EnhancedAead.decryptAesGcm(keys.key, &nonce, ciphertext, aad, self.allocator),
            .chacha20_poly1305_sha256 => try EnhancedAead.decryptChaCha20Poly1305(keys.key, &nonce, ciphertext, aad, self.allocator),
        };
    }

    /// Apply header protection
    pub fn protectHeader(self: *const Self, level: EncryptionLevel, header: []u8, sample: []const u8) !void {
        const keys = switch (level) {
            .initial => &self.initial_keys.?,
            .handshake => &self.handshake_keys.?,
            .application => &self.application_keys.?,
        };

        try EnhancedHeaderProtection.protectHeader(self.cipher_suite, keys.header_protection_key, header, sample);
    }

    /// Remove header protection
    pub fn unprotectHeader(self: *const Self, level: EncryptionLevel, header: []u8, sample: []const u8) !void {
        const keys = switch (level) {
            .initial => &self.initial_keys.?,
            .handshake => &self.handshake_keys.?,
            .application => &self.application_keys.?,
        };

        try EnhancedHeaderProtection.unprotectHeader(self.cipher_suite, keys.header_protection_key, header, sample);
    }
};

/// Encryption levels for QUIC
pub const EncryptionLevel = enum {
    initial,
    handshake,
    application,
};

test "enhanced crypto keys derivation" {
    var keys = try EnhancedCryptoKeys.init(std.testing.allocator, .aes_128_gcm_sha256);
    defer keys.deinit();

    const master_secret = "test_master_secret_32_bytes_long";
    try keys.deriveFromSecret(master_secret, "test", "");

    // Keys should be properly derived
    try std.testing.expect(keys.key.len == 16); // AES-128
    try std.testing.expect(keys.iv.len == 12);
}

test "RFC 9001 Appendix A.1 Initial key vectors" {
    const destination_connection_id = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try deriveRfc9001InitialKeys(&destination_connection_id);

    const expected_initial_secret = [_]u8{
        0x7d, 0xb5, 0xdf, 0x06, 0xe7, 0xa6, 0x9e, 0x43, 0x24, 0x96, 0xad, 0xed, 0xb0, 0x08, 0x51, 0x92,
        0x35, 0x95, 0x22, 0x15, 0x96, 0xae, 0x2a, 0xe9, 0xfb, 0x81, 0x15, 0xc1, 0xe9, 0xed, 0x0a, 0x44,
    };
    const expected_client_secret = [_]u8{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };
    const expected_server_secret = [_]u8{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    };
    const expected_client_key = [_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d };
    const expected_client_iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
    const expected_client_hp = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    const expected_server_key = [_]u8{ 0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37 };
    const expected_server_iv = [_]u8{ 0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e };
    const expected_server_hp = [_]u8{ 0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };

    try std.testing.expectEqualSlices(u8, &expected_initial_secret, &keys.initial_secret);
    try std.testing.expectEqualSlices(u8, &expected_client_secret, &keys.client.secret);
    try std.testing.expectEqualSlices(u8, &expected_client_key, &keys.client.key);
    try std.testing.expectEqualSlices(u8, &expected_client_iv, &keys.client.iv);
    try std.testing.expectEqualSlices(u8, &expected_client_hp, &keys.client.header_protection_key);
    try std.testing.expectEqualSlices(u8, &expected_server_secret, &keys.server.secret);
    try std.testing.expectEqualSlices(u8, &expected_server_key, &keys.server.key);
    try std.testing.expectEqualSlices(u8, &expected_server_iv, &keys.server.iv);
    try std.testing.expectEqualSlices(u8, &expected_server_hp, &keys.server.header_protection_key);
}

test "aes gcm encryption" {
    const key = "sixteen_byte_key".*;
    const iv = "twelve_bytes".*;
    const plaintext = "Hello, QUIC!";
    const aad = "additional_authenticated_data";

    const ciphertext = try EnhancedAead.encryptAesGcm(&key, &iv, plaintext, aad, std.testing.allocator);
    defer std.testing.allocator.free(ciphertext);

    const decrypted = try EnhancedAead.decryptAesGcm(&key, &iv, ciphertext, aad, std.testing.allocator);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "header protection" {
    const hp_key = "sixteen_byte_key".*;
    const sample = "16_byte_sample!!".*;

    const mask = try EnhancedHeaderProtection.generateAesMask(&hp_key, &sample);
    try std.testing.expect(mask.len == 5);
}
