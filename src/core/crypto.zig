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
        // Securely zero key material
        @memset(@constCast(self.aead_key), 0);
        @memset(@constCast(self.aead_iv), 0);
        @memset(@constCast(self.hp_key), 0);

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
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => blk: {
                // Use zcrypto AES-GCM
                const aes_gcm = zcrypto.aead.AesGcm.init(key) catch return Error.ZquicError.CryptoError;
                const result = aes_gcm.encrypt(
                    &nonce,
                    associated_data,
                    plaintext,
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len .. plaintext.len + 16],
                ) catch return Error.ZquicError.CryptoError;
                _ = result;
                break :blk plaintext.len + 16;
            },
            .chacha20_poly1305_sha256 => blk: {
                // Use zcrypto ChaCha20-Poly1305
                const chacha_poly = zcrypto.aead.ChaCha20Poly1305.init(key) catch return Error.ZquicError.CryptoError;
                const result = chacha_poly.encrypt(
                    &nonce,
                    associated_data,
                    plaintext,
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len .. plaintext.len + 16],
                ) catch return Error.ZquicError.CryptoError;
                _ = result;
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

        return switch (self.cipher_suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => blk: {
                // Use zcrypto AES-GCM
                const aes_gcm = zcrypto.aead.AesGcm.init(key) catch return Error.ZquicError.CryptoError;
                const result = aes_gcm.decrypt(
                    &nonce,
                    associated_data,
                    encrypted_data,
                    tag,
                    plaintext,
                ) catch return Error.ZquicError.CryptoError;
                _ = result;
                break :blk encrypted_data.len;
            },
            .chacha20_poly1305_sha256 => blk: {
                // Use zcrypto ChaCha20-Poly1305
                const chacha_poly = zcrypto.aead.ChaCha20Poly1305.init(key) catch return Error.ZquicError.CryptoError;
                const result = chacha_poly.decrypt(
                    &nonce,
                    associated_data,
                    encrypted_data,
                    tag,
                    plaintext,
                ) catch return Error.ZquicError.CryptoError;
                _ = result;
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
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => {
                // Use AES-ECB to encrypt the sample
                const aes = zcrypto.block.Aes.init(hp_key) catch return Error.ZquicError.CryptoError;
                var encrypted_sample: [16]u8 = undefined;
                aes.encryptBlock(sample, &encrypted_sample) catch return Error.ZquicError.CryptoError;
                @memcpy(mask, encrypted_sample[0..5]);
            },
            .chacha20_poly1305_sha256 => {
                // Use ChaCha20 with zero nonce and counter from sample
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const nonce = sample[4..16];
                var zeros: [5]u8 = [_]u8{0} ** 5;

                const chacha20 = zcrypto.stream.ChaCha20.init(hp_key, nonce, counter) catch return Error.ZquicError.CryptoError;
                chacha20.encrypt(&zeros, mask) catch return Error.ZquicError.CryptoError;
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
        var mask: [5]u8 = undefined;
        try self.generateMask(hp_key, sample, &mask);

        // Apply mask to first byte and packet number bytes
        header[0] ^= mask[0] & if (header[0] & 0x80 != 0) 0x0F else 0x1F;

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
            .keys = [_]?KeyPair{null} ** 4,
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
