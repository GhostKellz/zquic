//! QUIC Cryptographic Interface
//!
//! Provides a clean interface for QUIC's cryptographic operations:
//! - AEAD (Authenticated Encryption with Associated Data)
//! - Header Protection (HP)
//! - Key derivation and management
//! - TLS integration
//!
//! Uses zcrypto for the underlying cryptographic implementations.

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const enhanced_tls = @import("../crypto/enhanced_tls.zig");

/// QUIC encryption levels corresponding to TLS record types
pub const EncryptionLevel = enum(u8) {
    /// Initial encryption using well-known keys
    initial = 0,
    /// 0-RTT early data encryption
    early_data = 1,
    /// Handshake encryption for TLS handshake messages
    handshake = 2,
    /// Application data encryption for 1-RTT protected data
    application = 3,

    pub fn toString(self: EncryptionLevel) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .early_data => "EarlyData",
            .handshake => "Handshake",
            .application => "Application",
        };
    }
};

/// QUIC cipher suites
pub const CipherSuite = enum {
    /// AES-128-GCM with SHA-256
    aes_128_gcm_sha256,
    /// AES-256-GCM with SHA-384
    aes_256_gcm_sha384,
    /// ChaCha20-Poly1305 with SHA-256
    chacha20_poly1305_sha256,

    /// Get key length for cipher suite
    pub fn keyLength(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384 => 32,
            .chacha20_poly1305_sha256 => 32,
        };
    }

    /// Get IV length for cipher suite
    pub fn ivLength(self: CipherSuite) usize {
        return switch (self) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 12,
            .chacha20_poly1305_sha256 => 12,
        };
    }

    /// Get authentication tag length
    pub fn tagLength(_: CipherSuite) usize {
        return 16; // All QUIC cipher suites use 16-byte tags
    }

    /// Get hash algorithm for HKDF
    pub fn hashAlgorithm(self: CipherSuite) zcrypto.hash.Algorithm {
        return switch (self) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .sha256,
            .aes_256_gcm_sha384 => .sha384,
        };
    }
};

/// Cryptographic keys for a single direction
pub const DirectionalKeys = struct {
    /// AEAD encryption/decryption key
    aead_key: []const u8,
    /// AEAD initialization vector
    aead_iv: []const u8,
    /// Header protection key
    hp_key: []const u8,
    /// Key update sequence number
    key_phase: u8,

    /// Allocator used for key material
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize directional keys with given cipher suite
    pub fn init(
        allocator: std.mem.Allocator,
        _: CipherSuite,
        aead_key: []const u8,
        aead_iv: []const u8,
        hp_key: []const u8,
    ) !Self {
        return Self{
            .aead_key = try allocator.dupe(u8, aead_key),
            .aead_iv = try allocator.dupe(u8, aead_iv),
            .hp_key = try allocator.dupe(u8, hp_key),
            .key_phase = 0,
            .allocator = allocator,
        };
    }

    /// Clean up key material securely
    pub fn deinit(self: *Self) void {
        // Securely zero key material using constant-time wipe
        // (prevents compiler optimization from removing the wipe)
        std.crypto.secureZero(u8, @constCast(self.aead_key));
        std.crypto.secureZero(u8, @constCast(self.aead_iv));
        std.crypto.secureZero(u8, @constCast(self.hp_key));

        self.allocator.free(self.aead_key);
        self.allocator.free(self.aead_iv);
        self.allocator.free(self.hp_key);
    }
};

/// Key material for both directions
pub const KeyPair = struct {
    /// Keys for outgoing packets (local to remote)
    local: DirectionalKeys,
    /// Keys for incoming packets (remote to local)
    remote: DirectionalKeys,
    /// Cipher suite in use
    cipher_suite: CipherSuite,
    /// Encryption level
    level: EncryptionLevel,

    const Self = @This();

    /// Clean up both directional keys
    pub fn deinit(self: *Self) void {
        self.local.deinit();
        self.remote.deinit();
    }
};

/// AEAD operations interface
pub const AeadOps = struct {
    /// Cipher suite for these operations
    cipher_suite: CipherSuite,

    const Self = @This();

    /// Initialize AEAD operations for cipher suite
    pub fn init(cipher_suite: CipherSuite) Self {
        return Self{ .cipher_suite = cipher_suite };
    }

    /// Encrypt plaintext with AEAD
    pub fn encrypt(
        self: Self,
        key: []const u8,
        iv: []const u8,
        packet_number: u64,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
    ) Error.ZquicError!usize {
        if (iv.len != 12) return Error.ZquicError.CryptoError;
        if (ciphertext.len < plaintext.len + 16) return Error.ZquicError.CryptoError;

        // Construct nonce from IV and packet number
        var nonce: [12]u8 = undefined;
        @memcpy(nonce[0..iv.len], iv);

        // XOR packet number into nonce (big-endian)
        const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
        const offset = nonce.len - 8;
        for (pn_bytes, 0..) |byte, i| {
            nonce[offset + i] ^= byte;
        }

        return switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => blk: {
                // Use std.crypto AES-128-GCM
                if (key.len != 16) return Error.ZquicError.CryptoError;
                const key_array: [16]u8 = key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..16],
                    plaintext,
                    associated_data,
                    nonce,
                    key_array,
                );
                break :blk plaintext.len + 16;
            },
            .aes_256_gcm_sha384 => blk: {
                // Use std.crypto AES-256-GCM
                if (key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..16],
                    plaintext,
                    associated_data,
                    nonce,
                    key_array,
                );
                break :blk plaintext.len + 16;
            },
            .chacha20_poly1305_sha256 => blk: {
                // Use std.crypto ChaCha20-Poly1305
                if (key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..16],
                    plaintext,
                    associated_data,
                    nonce,
                    key_array,
                );
                break :blk plaintext.len + 16;
            },
        };
    }

    /// Decrypt ciphertext with AEAD
    pub fn decrypt(
        self: Self,
        key: []const u8,
        iv: []const u8,
        packet_number: u64,
        associated_data: []const u8,
        ciphertext: []const u8,
        plaintext: []u8,
    ) Error.ZquicError!usize {
        if (ciphertext.len < 16) return Error.ZquicError.CryptoError;
        if (iv.len != 12) return Error.ZquicError.CryptoError;

        // Construct nonce from IV and packet number
        var nonce: [12]u8 = undefined;
        @memcpy(nonce[0..iv.len], iv);

        // XOR packet number into nonce (big-endian)
        const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
        const offset = nonce.len - 8;
        for (pn_bytes, 0..) |byte, i| {
            nonce[offset + i] ^= byte;
        }

        const encrypted_data = ciphertext[0 .. ciphertext.len - 16];
        const tag = ciphertext[ciphertext.len - 16 ..];
        if (plaintext.len < encrypted_data.len) return Error.ZquicError.CryptoError;

        return switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => blk: {
                // Use std.crypto AES-128-GCM
                if (key.len != 16) return Error.ZquicError.CryptoError;
                const key_array: [16]u8 = key[0..16].*;
                const tag_array: [16]u8 = tag[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                    plaintext[0..encrypted_data.len],
                    encrypted_data,
                    tag_array,
                    associated_data,
                    nonce,
                    key_array,
                ) catch return Error.ZquicError.CryptoError;
                break :blk encrypted_data.len;
            },
            .aes_256_gcm_sha384 => blk: {
                // Use std.crypto AES-256-GCM
                if (key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = key[0..32].*;
                const tag_array: [16]u8 = tag[0..16].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                    plaintext[0..encrypted_data.len],
                    encrypted_data,
                    tag_array,
                    associated_data,
                    nonce,
                    key_array,
                ) catch return Error.ZquicError.CryptoError;
                break :blk encrypted_data.len;
            },
            .chacha20_poly1305_sha256 => blk: {
                // Use std.crypto ChaCha20-Poly1305
                if (key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = key[0..32].*;
                const tag_array: [16]u8 = tag[0..16].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                    plaintext[0..encrypted_data.len],
                    encrypted_data,
                    tag_array,
                    associated_data,
                    nonce,
                    key_array,
                ) catch return Error.ZquicError.CryptoError;
                break :blk encrypted_data.len;
            },
        };
    }
};

/// Header Protection operations
pub const HeaderProtection = struct {
    /// Cipher suite for header protection
    cipher_suite: CipherSuite,

    const Self = @This();

    /// Initialize header protection for cipher suite
    pub fn init(cipher_suite: CipherSuite) Self {
        return Self{ .cipher_suite = cipher_suite };
    }

    /// Generate header protection mask
    pub fn generateMask(
        self: Self,
        hp_key: []const u8,
        sample: []const u8,
        mask: []u8,
    ) Error.ZquicError!void {
        if (sample.len != 16) return Error.ZquicError.CryptoError;
        if (mask.len != 5) return Error.ZquicError.CryptoError;

        switch (self.cipher_suite) {
            .aes_128_gcm_sha256 => {
                // Use std.crypto AES-128-ECB to encrypt the sample
                if (hp_key.len != 16) return Error.ZquicError.CryptoError;
                const key_array: [16]u8 = hp_key[0..16].*;
                const sample_array: [16]u8 = sample[0..16].*;
                const aes = std.crypto.core.aes.Aes128.initEnc(key_array);
                var encrypted_sample: [16]u8 = undefined;
                aes.encrypt(&encrypted_sample, &sample_array);
                @memcpy(mask, encrypted_sample[0..5]);
            },
            .aes_256_gcm_sha384 => {
                // Use std.crypto AES-256-ECB to encrypt the sample
                if (hp_key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = hp_key[0..32].*;
                const sample_array: [16]u8 = sample[0..16].*;
                const aes = std.crypto.core.aes.Aes256.initEnc(key_array);
                var encrypted_sample: [16]u8 = undefined;
                aes.encrypt(&encrypted_sample, &sample_array);
                @memcpy(mask, encrypted_sample[0..5]);
            },
            .chacha20_poly1305_sha256 => {
                // Use std.crypto ChaCha20 with counter from sample
                if (hp_key.len != 32) return Error.ZquicError.CryptoError;
                const key_array: [32]u8 = hp_key[0..32].*;
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const nonce_array: [12]u8 = sample[4..16].*;
                var zeros: [5]u8 = std.mem.zeroes([5]u8);
                std.crypto.stream.chacha.ChaCha20IETF.xor(mask, &zeros, counter, key_array, nonce_array);
            },
        }
    }

    /// Apply header protection to packet header
    pub fn protect(
        self: Self,
        hp_key: []const u8,
        header: []u8,
        sample: []const u8,
    ) Error.ZquicError!void {
        if (header.len == 0) return Error.ZquicError.CryptoError;

        var mask: [5]u8 = undefined;
        try self.generateMask(hp_key, sample, &mask);

        // Apply mask to first byte and packet number bytes
        const first_byte_mask: u8 = if (header[0] & 0x80 != 0) 0x0F else 0x1F;
        header[0] ^= mask[0] & first_byte_mask;

        // Determine packet number length and apply mask
        const pn_length = if (header[0] & 0x80 != 0)
            @as(usize, (header[0] & 0x03) + 1) // Long header
        else
            @as(usize, (header[0] & 0x03) + 1); // Short header

        for (0..pn_length) |i| {
            if (1 + i < header.len) {
                header[1 + i] ^= mask[1 + i];
            }
        }
    }

    pub fn protectAtPacketNumberOffset(
        self: Self,
        hp_key: []const u8,
        header: []u8,
        packet_number_offset: usize,
        sample: []const u8,
    ) Error.ZquicError!void {
        if (header.len == 0 or packet_number_offset >= header.len) return Error.ZquicError.CryptoError;

        var mask: [5]u8 = undefined;
        try self.generateMask(hp_key, sample, &mask);

        const first_byte_mask: u8 = if (header[0] & 0x80 != 0) 0x0F else 0x1F;
        const packet_number_len: usize = (header[0] & 0x03) + 1;
        if (packet_number_offset + packet_number_len > header.len) return Error.ZquicError.CryptoError;

        header[0] ^= mask[0] & first_byte_mask;
        for (0..packet_number_len) |i| {
            header[packet_number_offset + i] ^= mask[1 + i];
        }
    }

    pub fn unprotectAtPacketNumberOffset(
        self: Self,
        hp_key: []const u8,
        header: []u8,
        packet_number_offset: usize,
        sample: []const u8,
    ) Error.ZquicError!void {
        if (header.len == 0 or packet_number_offset >= header.len) return Error.ZquicError.CryptoError;

        var mask: [5]u8 = undefined;
        try self.generateMask(hp_key, sample, &mask);

        const first_byte_mask: u8 = if (header[0] & 0x80 != 0) 0x0F else 0x1F;
        header[0] ^= mask[0] & first_byte_mask;

        const packet_number_len: usize = (header[0] & 0x03) + 1;
        if (packet_number_offset + packet_number_len > header.len) return Error.ZquicError.CryptoError;
        for (0..packet_number_len) |i| {
            header[packet_number_offset + i] ^= mask[1 + i];
        }
    }

    /// Remove header protection from packet header
    pub fn unprotect(
        self: Self,
        hp_key: []const u8,
        header: []u8,
        sample: []const u8,
    ) Error.ZquicError!void {
        // Same operation as protect - XOR is its own inverse
        try self.protect(hp_key, header, sample);
    }
};

/// QUIC crypto context managing keys and operations
pub const QuicCrypto = struct {
    /// Current key pairs for each encryption level
    keys: [4]?KeyPair,
    /// AEAD operations
    aead: AeadOps,
    /// Header protection operations
    hp: HeaderProtection,
    /// Memory allocator
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize QUIC crypto context
    pub fn init(allocator: std.mem.Allocator, cipher_suite: CipherSuite) Self {
        return Self{
            .keys = [_]?KeyPair{ null, null, null, null },
            .aead = AeadOps.init(cipher_suite),
            .hp = HeaderProtection.init(cipher_suite),
            .allocator = allocator,
        };
    }

    /// Clean up all key material
    pub fn deinit(self: *Self) void {
        for (&self.keys) |*key_pair| {
            if (key_pair.*) |*kp| {
                kp.deinit();
            }
        }
    }

    /// Install keys for an encryption level
    pub fn installKeys(
        self: *Self,
        level: EncryptionLevel,
        local_keys: DirectionalKeys,
        remote_keys: DirectionalKeys,
    ) void {
        // Clean up existing keys if any
        if (self.keys[@intFromEnum(level)]) |*existing| {
            existing.deinit();
        }

        self.keys[@intFromEnum(level)] = KeyPair{
            .local = local_keys,
            .remote = remote_keys,
            .cipher_suite = self.aead.cipher_suite,
            .level = level,
        };
    }

    /// Get keys for encryption level
    pub fn getKeys(self: *Self, level: EncryptionLevel) ?*KeyPair {
        return if (self.keys[@intFromEnum(level)]) |*kp| kp else null;
    }

    /// Encrypt outgoing packet
    pub fn encryptPacket(
        self: *Self,
        level: EncryptionLevel,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
        output: []u8,
    ) Error.ZquicError!usize {
        const keys = self.getKeys(level) orelse return Error.ZquicError.CryptoError;
        if (output.len < header.len + payload.len + self.aead.cipher_suite.tagLength()) {
            return Error.ZquicError.CryptoError;
        }

        // Encrypt payload
        const ciphertext_len = try self.aead.encrypt(
            keys.local.aead_key,
            keys.local.aead_iv,
            packet_number,
            header,
            payload,
            output[header.len..],
        );

        // Copy header and apply header protection
        @memcpy(output[0..header.len], header);
        const sample_offset = header.len + 4; // Typically 4 bytes into encrypted payload
        if (sample_offset + 16 <= header.len + ciphertext_len) {
            try self.hp.protect(
                keys.local.hp_key,
                output[0..header.len],
                output[sample_offset .. sample_offset + 16],
            );
        }

        return header.len + ciphertext_len;
    }

    /// Decrypt incoming packet
    pub fn decryptPacket(
        self: *Self,
        level: EncryptionLevel,
        packet_number: u64,
        packet: []u8,
        header_len: usize,
        output: []u8,
    ) Error.ZquicError!usize {
        const keys = self.getKeys(level) orelse return Error.ZquicError.CryptoError;
        if (header_len == 0 or header_len > packet.len) return Error.ZquicError.CryptoError;

        // Remove header protection first
        const sample_offset = header_len + 4;
        if (sample_offset + 16 <= packet.len) {
            try self.hp.unprotect(
                keys.remote.hp_key,
                packet[0..header_len],
                packet[sample_offset .. sample_offset + 16],
            );
        }

        // Decrypt payload
        return self.aead.decrypt(
            keys.remote.aead_key,
            keys.remote.aead_iv,
            packet_number,
            packet[0..header_len],
            packet[header_len..],
            output,
        );
    }
};

// Tests
test "cipher suite properties" {
    const aes128 = CipherSuite.aes_128_gcm_sha256;
    try std.testing.expectEqual(@as(usize, 16), aes128.keyLength());
    try std.testing.expectEqual(@as(usize, 12), aes128.ivLength());
    try std.testing.expectEqual(@as(usize, 16), aes128.tagLength());
}

test "encryption level toString" {
    try std.testing.expectEqualStrings("Initial", EncryptionLevel.initial.toString());
    try std.testing.expectEqualStrings("Application", EncryptionLevel.application.toString());
}

test "quic crypto initialization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var crypto = QuicCrypto.init(allocator, .aes_128_gcm_sha256);
    defer crypto.deinit();

    // Initially no keys should be installed
    try std.testing.expect(crypto.getKeys(.initial) == null);
    try std.testing.expect(crypto.getKeys(.application) == null);
}

fn filledBytes(comptime len: usize, value: u8) [len]u8 {
    var bytes = std.mem.zeroes([len]u8);
    @memset(bytes[0..], value);
    return bytes;
}

fn testDirectionalKeys(
    allocator: std.mem.Allocator,
    cipher_suite: CipherSuite,
    key_fill: u8,
    iv_fill: u8,
    hp_fill: u8,
) !DirectionalKeys {
    var key = filledBytes(32, key_fill);
    var iv = filledBytes(12, iv_fill);
    var hp_key = filledBytes(32, hp_fill);
    return DirectionalKeys.init(
        allocator,
        cipher_suite,
        key[0..cipher_suite.keyLength()],
        &iv,
        hp_key[0..cipher_suite.keyLength()],
    );
}

test "aead rejects invalid key iv output and plaintext sizes" {
    const aead = AeadOps.init(.aes_256_gcm_sha384);
    const key = filledBytes(32, 0x42);
    const short_key = filledBytes(31, 0x42);
    const iv = filledBytes(12, 0x11);
    const short_iv = filledBytes(11, 0x11);
    const aad = "quic header";
    const plaintext = "packet payload";

    var ciphertext: [plaintext.len + 16]u8 = undefined;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.encrypt(&short_key, &iv, 7, aad, plaintext, &ciphertext),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.encrypt(&key, &short_iv, 7, aad, plaintext, &ciphertext),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.encrypt(&key, &iv, 7, aad, plaintext, ciphertext[0 .. ciphertext.len - 1]),
    );

    const ciphertext_len = try aead.encrypt(&key, &iv, 7, aad, plaintext, &ciphertext);
    var decrypted: [plaintext.len]u8 = undefined;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &short_iv, 7, aad, ciphertext[0..ciphertext_len], &decrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 7, aad, ciphertext[0..ciphertext_len], decrypted[0 .. decrypted.len - 1]),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 7, aad, ciphertext[0..15], &decrypted),
    );
}

test "aead rejects tampered ciphertext tag aad and packet number" {
    const aead = AeadOps.init(.chacha20_poly1305_sha256);
    const key = filledBytes(32, 0xA5);
    const wrong_key = filledBytes(32, 0xC3);
    const iv = filledBytes(12, 0x5A);
    const aad = "short header";
    const plaintext = "authenticated QUIC packet payload";

    var ciphertext: [plaintext.len + 16]u8 = undefined;
    const ciphertext_len = try aead.encrypt(&key, &iv, 9, aad, plaintext, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    const decrypted_len = try aead.decrypt(&key, &iv, 9, aad, ciphertext[0..ciphertext_len], &decrypted);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..decrypted_len]);

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&wrong_key, &iv, 9, aad, ciphertext[0..ciphertext_len], &decrypted),
    );

    var tampered_ciphertext = ciphertext;
    tampered_ciphertext[0] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 9, aad, tampered_ciphertext[0..ciphertext_len], &decrypted),
    );

    var tampered_tag = ciphertext;
    tampered_tag[ciphertext_len - 1] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 9, aad, tampered_tag[0..ciphertext_len], &decrypted),
    );

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 10, aad, ciphertext[0..ciphertext_len], &decrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 9, "mutated header", ciphertext[0..ciphertext_len], &decrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        aead.decrypt(&key, &iv, 9, aad, ciphertext[0 .. ciphertext_len - 1], &decrypted),
    );
}

test "header protection rejects malformed inputs" {
    const hp = HeaderProtection.init(.aes_256_gcm_sha384);
    const hp_key = filledBytes(32, 0x33);
    const short_hp_key = filledBytes(31, 0x33);
    const sample = filledBytes(16, 0x44);
    const short_sample = filledBytes(15, 0x44);
    var mask: [5]u8 = undefined;
    var short_mask: [4]u8 = undefined;
    var header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01 };
    var empty_header: [0]u8 = .{};

    try hp.generateMask(&hp_key, &sample, &mask);
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        hp.generateMask(&short_hp_key, &sample, &mask),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        hp.generateMask(&hp_key, &short_sample, &mask),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        hp.generateMask(&hp_key, &sample, &short_mask),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        hp.protect(&hp_key, &empty_header, &sample),
    );
    try hp.protect(&hp_key, &header, &sample);
    try hp.unprotect(&hp_key, &header, &sample);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x00, 0x00, 0x00, 0x01 }, &header);
}

fn hexToArray(comptime len: usize, hex: []const u8) ![len]u8 {
    var out: [len]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&out, hex);
    if (bytes.len != len) return error.InvalidLength;
    return out;
}

test "RFC 9001 Appendix A Initial packet header protection vectors" {
    const keys = try enhanced_tls.deriveRfc9001InitialKeys(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const hp = HeaderProtection.init(.aes_128_gcm_sha256);

    const client_sample = try hexToArray(16, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const expected_client_mask = try hexToArray(5, "437b9aec36");
    var client_mask: [5]u8 = undefined;
    try hp.generateMask(&keys.client.header_protection_key, &client_sample, &client_mask);
    try std.testing.expectEqualSlices(u8, &expected_client_mask, &client_mask);

    const client_unprotected = try hexToArray(22, "c300000001088394c8f03e5157080000449e00000002");
    const client_protected = try hexToArray(22, "c000000001088394c8f03e5157080000449e7b9aec34");
    var protected_client_header = client_unprotected;
    try hp.protectAtPacketNumberOffset(&keys.client.header_protection_key, &protected_client_header, 18, &client_sample);
    try std.testing.expectEqualSlices(u8, &client_protected, &protected_client_header);
    try hp.unprotectAtPacketNumberOffset(&keys.client.header_protection_key, &protected_client_header, 18, &client_sample);
    try std.testing.expectEqualSlices(u8, &client_unprotected, &protected_client_header);

    const server_sample = try hexToArray(16, "2cd0991cd25b0aac406a5816b6394100");
    const expected_server_mask = try hexToArray(5, "2ec0d8356a");
    var server_mask: [5]u8 = undefined;
    try hp.generateMask(&keys.server.header_protection_key, &server_sample, &server_mask);
    try std.testing.expectEqualSlices(u8, &expected_server_mask, &server_mask);

    const server_unprotected = try hexToArray(19, "c1000000010008f067a5502a4262b50040750001");
    const server_protected = try hexToArray(19, "cf000000010008f067a5502a4262b5004075c0d9");
    var protected_server_header = server_unprotected;
    try hp.protectAtPacketNumberOffset(&keys.server.header_protection_key, &protected_server_header, 17, &server_sample);
    try std.testing.expectEqualSlices(u8, &server_protected, &protected_server_header);
    try hp.unprotectAtPacketNumberOffset(&keys.server.header_protection_key, &protected_server_header, 17, &server_sample);
    try std.testing.expectEqualSlices(u8, &server_unprotected, &protected_server_header);
}

test "RFC 9001 Appendix A.5 ChaCha20 header protection vector" {
    const hp = HeaderProtection.init(.chacha20_poly1305_sha256);
    const hp_key = try hexToArray(32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
    const sample = try hexToArray(16, "5e5cd55c41f69080575d7999c25a5bfb");
    const expected_mask = try hexToArray(5, "aefefe7d03");
    var mask: [5]u8 = undefined;
    try hp.generateMask(&hp_key, &sample, &mask);
    try std.testing.expectEqualSlices(u8, &expected_mask, &mask);

    const unprotected_header = try hexToArray(4, "4200bff4");
    const protected_header = try hexToArray(4, "4cfe4189");
    var header = unprotected_header;
    try hp.protectAtPacketNumberOffset(&hp_key, &header, 1, &sample);
    try std.testing.expectEqualSlices(u8, &protected_header, &header);
    try hp.unprotectAtPacketNumberOffset(&hp_key, &header, 1, &sample);
    try std.testing.expectEqualSlices(u8, &unprotected_header, &header);
}

test "quic crypto packet roundtrip rejects tampering and undersized buffers" {
    const allocator = std.testing.allocator;
    var crypto = QuicCrypto.init(allocator, .aes_256_gcm_sha384);
    defer crypto.deinit();

    const local = try testDirectionalKeys(allocator, .aes_256_gcm_sha384, 0x10, 0x20, 0x30);
    const remote = try testDirectionalKeys(allocator, .aes_256_gcm_sha384, 0x10, 0x20, 0x30);
    crypto.installKeys(.application, local, remote);

    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x07 };
    const payload = "long enough QUIC application payload for header protection sample";
    var packet: [header.len + payload.len + 16]u8 = undefined;

    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        crypto.encryptPacket(.application, 7, &header, payload, packet[0 .. packet.len - 1]),
    );

    const packet_len = try crypto.encryptPacket(.application, 7, &header, payload, &packet);
    var packet_copy = packet;
    var decrypted: [payload.len]u8 = undefined;
    const decrypted_len = try crypto.decryptPacket(.application, 7, packet_copy[0..packet_len], header.len, &decrypted);
    try std.testing.expectEqualStrings(payload, decrypted[0..decrypted_len]);

    var tampered_packet = packet;
    tampered_packet[packet_len - 1] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        crypto.decryptPacket(.application, 7, tampered_packet[0..packet_len], header.len, &decrypted),
    );

    var tampered_header_packet = packet;
    tampered_header_packet[0] ^= 0x40;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        crypto.decryptPacket(.application, 7, tampered_header_packet[0..packet_len], header.len, &decrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        crypto.decryptPacket(.application, 8, packet[0..packet_len], header.len, &decrypted),
    );
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        crypto.decryptPacket(.application, 7, packet[0..packet_len], packet_len + 1, &decrypted),
    );
}

test "quic crypto rejects old and rolled back keys across packet number continuity" {
    const allocator = std.testing.allocator;
    const header = [_]u8{ 0x40, 0x00, 0x00, 0x00, 0x2a };
    const old_payload = "old key phase packet payload long enough for header protection";
    const new_payload = "new key phase packet payload long enough for header protection";

    var old_crypto = QuicCrypto.init(allocator, .aes_128_gcm_sha256);
    defer old_crypto.deinit();
    const old_local = try testDirectionalKeys(allocator, .aes_128_gcm_sha256, 0x21, 0x31, 0x41);
    const old_remote = try testDirectionalKeys(allocator, .aes_128_gcm_sha256, 0x21, 0x31, 0x41);
    old_crypto.installKeys(.application, old_local, old_remote);

    var old_packet: [header.len + old_payload.len + 16]u8 = undefined;
    const old_packet_len = try old_crypto.encryptPacket(.application, 100, &header, old_payload, &old_packet);
    var old_packet_copy = old_packet;
    var old_decrypted: [old_payload.len]u8 = undefined;
    const old_decrypted_len = try old_crypto.decryptPacket(
        .application,
        100,
        old_packet_copy[0..old_packet_len],
        header.len,
        &old_decrypted,
    );
    try std.testing.expectEqualStrings(old_payload, old_decrypted[0..old_decrypted_len]);

    var new_crypto = QuicCrypto.init(allocator, .aes_128_gcm_sha256);
    defer new_crypto.deinit();
    var new_local = try testDirectionalKeys(allocator, .aes_128_gcm_sha256, 0x52, 0x62, 0x72);
    var new_remote = try testDirectionalKeys(allocator, .aes_128_gcm_sha256, 0x52, 0x62, 0x72);
    new_local.key_phase = 1;
    new_remote.key_phase = 1;
    new_crypto.installKeys(.application, new_local, new_remote);

    var new_packet: [header.len + new_payload.len + 16]u8 = undefined;
    const new_packet_len = try new_crypto.encryptPacket(.application, 101, &header, new_payload, &new_packet);
    var new_packet_copy = new_packet;
    var new_decrypted: [new_payload.len]u8 = undefined;
    const new_decrypted_len = try new_crypto.decryptPacket(
        .application,
        101,
        new_packet_copy[0..new_packet_len],
        header.len,
        &new_decrypted,
    );
    try std.testing.expectEqualStrings(new_payload, new_decrypted[0..new_decrypted_len]);

    var old_under_new = old_packet;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        new_crypto.decryptPacket(.application, 100, old_under_new[0..old_packet_len], header.len, old_decrypted[0..]),
    );

    var new_under_old = new_packet;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        old_crypto.decryptPacket(.application, 101, new_under_old[0..new_packet_len], header.len, new_decrypted[0..]),
    );

    var wrong_packet_number = new_packet;
    try std.testing.expectError(
        Error.ZquicError.CryptoError,
        new_crypto.decryptPacket(.application, 100, wrong_packet_number[0..new_packet_len], header.len, new_decrypted[0..]),
    );
}
