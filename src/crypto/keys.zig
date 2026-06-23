//! QUIC key management and derivation
//!
//! Handles key updates and key derivation for QUIC

const std = @import("std");
const Error = @import("../utils/error.zig");
const Tls = @import("tls.zig");

/// Key update manager
pub const KeyManager = struct {
    current_keys: Tls.CryptoKeys,
    next_keys: ?Tls.CryptoKeys,
    key_phase: u1, // 0 or 1
    update_pending: bool,

    const Self = @This();

    pub fn init(initial_keys: Tls.CryptoKeys) Self {
        return Self{
            .current_keys = initial_keys,
            .next_keys = null,
            .key_phase = 0,
            .update_pending = false,
        };
    }

    /// Initiate a key update
    pub fn initiateKeyUpdate(self: *Self) Error.ZquicError!void {
        if (self.update_pending) {
            return Error.ZquicError.CryptoError;
        }

        // Derive next generation keys
        const next_secret = self.deriveNextSecret();
        self.next_keys = try Tls.CryptoKeys.deriveFromSecret(&next_secret);
        self.update_pending = true;
    }

    /// Complete a key update (when we've received confirmation)
    pub fn completeKeyUpdate(self: *Self) void {
        if (self.next_keys) |next_keys| {
            self.current_keys = next_keys;
            self.next_keys = null;
            self.key_phase = 1 - self.key_phase; // Toggle between 0 and 1
            self.update_pending = false;
        }
    }

    /// Get current encryption keys
    pub fn getCurrentKeys(self: *const Self) *const Tls.CryptoKeys {
        return &self.current_keys;
    }

    /// Get keys for the specified key phase
    pub fn getKeysForPhase(self: *const Self, phase: u1) ?*const Tls.CryptoKeys {
        if (phase == self.key_phase) {
            return &self.current_keys;
        } else if (self.next_keys != null and phase == (1 - self.key_phase)) {
            return &self.next_keys.?;
        }
        return null;
    }

    /// Check if a key update is pending
    pub fn isUpdatePending(self: *const Self) bool {
        return self.update_pending;
    }

    /// Get current key phase
    pub fn getCurrentKeyPhase(self: *const Self) u1 {
        return self.key_phase;
    }

    /// Derive the next generation secret (simplified)
    fn deriveNextSecret(self: *const Self) [32]u8 {
        var next_secret: [32]u8 = undefined;

        // Simple key derivation (not cryptographically secure)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.current_keys.secret);
        hasher.update("key_update");
        hasher.final(&next_secret);

        return next_secret;
    }
};

/// Packet protection utilities
pub const PacketProtection = struct {
    /// Apply header protection to a packet
    pub fn protectHeader(header: []u8, sample: []const u8, hp_key: []const u8) Error.ZquicError!void {
        if (sample.len < 16 or hp_key.len < 32) {
            return Error.ZquicError.CryptoError;
        }

        // Simplified header protection (not cryptographically secure)
        // In real implementation, would use AES-ECB or ChaCha20
        const mask = generateMask(sample, hp_key);

        // Apply mask to first byte and packet number bytes
        if (header.len > 0) {
            header[0] ^= mask[0] & 0x1f; // Protect flags
        }

        // Protect packet number bytes (simplified - assumes 1 byte PN)
        if (header.len > 1) {
            header[header.len - 1] ^= mask[1];
        }
    }

    /// Remove header protection from a packet
    pub fn unprotectHeader(header: []u8, sample: []const u8, hp_key: []const u8) Error.ZquicError!void {
        // Header protection is symmetric, so we can reuse the same function
        return protectHeader(header, sample, hp_key);
    }

    /// Generate header protection mask
    fn generateMask(sample: []const u8, hp_key: []const u8) [5]u8 {
        _ = hp_key;
        var mask: [5]u8 = undefined;

        // Simplified mask generation
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(sample[0..16]);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        @memcpy(&mask, hash[0..5]);
        return mask;
    }
};

/// QUIC-specific key derivation functions
pub const KeyDerivation = struct {
    pub const retry_integrity_key = [16]u8{
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    };
    pub const retry_integrity_nonce = [12]u8{
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
        0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    };
    pub const max_retry_pseudo_packet_len = 4096;

    /// Derive initial secrets for QUIC
    pub fn deriveInitialSecrets(connection_id: []const u8, version: u32) struct { client: [32]u8, server: [32]u8 } {
        _ = version;

        var client_secret: [32]u8 = undefined;
        var server_secret: [32]u8 = undefined;

        // Simplified derivation (not per QUIC spec)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("client");
        hasher.update(connection_id);
        hasher.final(&client_secret);

        hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("server");
        hasher.update(connection_id);
        hasher.final(&server_secret);

        return .{ .client = client_secret, .server = server_secret };
    }

    /// Derive retry integrity tag
    pub fn deriveRetryIntegrityTag(retry_packet: []const u8, original_dest_conn_id: []const u8) [16]u8 {
        return deriveRetryIntegrityTagRfc9001(retry_packet, original_dest_conn_id) catch std.mem.zeroes([16]u8);
    }

    pub fn deriveRetryIntegrityTagRfc9001(
        retry_packet_without_tag: []const u8,
        original_dest_conn_id: []const u8,
    ) Error.ZquicError![16]u8 {
        if (original_dest_conn_id.len > 20) return Error.ZquicError.InvalidConnectionId;
        if (1 + original_dest_conn_id.len + retry_packet_without_tag.len > max_retry_pseudo_packet_len) {
            return Error.ZquicError.BufferTooSmall;
        }

        var pseudo_packet: [max_retry_pseudo_packet_len]u8 = undefined;
        pseudo_packet[0] = @intCast(original_dest_conn_id.len);
        @memcpy(pseudo_packet[1 .. 1 + original_dest_conn_id.len], original_dest_conn_id);
        @memcpy(
            pseudo_packet[1 + original_dest_conn_id.len ..][0..retry_packet_without_tag.len],
            retry_packet_without_tag,
        );
        const aad = pseudo_packet[0 .. 1 + original_dest_conn_id.len + retry_packet_without_tag.len];

        var tag: [16]u8 = undefined;
        var ciphertext: [0]u8 = .{};
        std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(
            &ciphertext,
            &tag,
            "",
            aad,
            retry_integrity_nonce,
            retry_integrity_key,
        );
        return tag;
    }
};

test "key manager initialization and update" {
    const initial_secret = "initial_secret_for_testing_only";
    const initial_keys = try Tls.CryptoKeys.deriveFromSecret(initial_secret);

    var key_manager = KeyManager.init(initial_keys);

    try std.testing.expect(key_manager.getCurrentKeyPhase() == 0);
    try std.testing.expect(!key_manager.isUpdatePending());

    // Initiate key update
    try key_manager.initiateKeyUpdate();
    try std.testing.expect(key_manager.isUpdatePending());

    // Complete key update
    key_manager.completeKeyUpdate();
    try std.testing.expect(!key_manager.isUpdatePending());
    try std.testing.expect(key_manager.getCurrentKeyPhase() == 1);
}

test "key manager rejects overlapping updates and exposes only pending phase before confirmation" {
    const initial_keys = try Tls.CryptoKeys.deriveFromSecret("initial key update trigger secret");
    var key_manager = KeyManager.init(initial_keys);

    try key_manager.initiateKeyUpdate();
    try std.testing.expect(key_manager.isUpdatePending());
    try std.testing.expectEqual(@as(u1, 0), key_manager.getCurrentKeyPhase());
    try std.testing.expect(key_manager.getKeysForPhase(0) != null);
    try std.testing.expect(key_manager.getKeysForPhase(1) != null);

    try std.testing.expectError(Error.ZquicError.CryptoError, key_manager.initiateKeyUpdate());
}

test "key manager discards old phase and rejects rollback after confirmation" {
    const initial_keys = try Tls.CryptoKeys.deriveFromSecret("old key phase secret");
    const old_secret = initial_keys.secret;
    var key_manager = KeyManager.init(initial_keys);

    try key_manager.initiateKeyUpdate();
    const pending_keys = key_manager.getKeysForPhase(1) orelse return error.TestExpectedEqual;
    const pending_secret = pending_keys.secret;
    try std.testing.expect(!std.mem.eql(u8, &old_secret, &pending_secret));

    key_manager.completeKeyUpdate();
    try std.testing.expectEqual(@as(u1, 1), key_manager.getCurrentKeyPhase());
    try std.testing.expect(!key_manager.isUpdatePending());
    try std.testing.expect(key_manager.getKeysForPhase(0) == null);

    const current_keys = key_manager.getKeysForPhase(1) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &pending_secret, &current_keys.secret);

    key_manager.completeKeyUpdate();
    try std.testing.expectEqual(@as(u1, 1), key_manager.getCurrentKeyPhase());
    try std.testing.expect(key_manager.getKeysForPhase(0) == null);
}

test "packet protection" {
    var header = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    const sample = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const hp_key = blk: {
        var bytes = std.mem.zeroes([32]u8);
        @memset(bytes[0..], 0xaa);
        break :blk bytes;
    };

    const original_header = header;

    // Protect header
    try PacketProtection.protectHeader(&header, &sample, &hp_key);
    try std.testing.expect(!std.mem.eql(u8, &header, &original_header));

    // Unprotect header
    try PacketProtection.unprotectHeader(&header, &sample, &hp_key);
    try std.testing.expectEqualSlices(u8, &original_header, &header);
}

test "initial secrets derivation" {
    const conn_id = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const secrets = KeyDerivation.deriveInitialSecrets(conn_id, 0x00000001);

    // Client and server secrets should be different
    try std.testing.expect(!std.mem.eql(u8, &secrets.client, &secrets.server));
}

test "retry integrity tag uses RFC 9001 AES-GCM binding" {
    const fixture = @embedFile("../../tests/fixtures/interop/retry-integrity.json");
    try std.testing.expect(std.mem.indexOf(u8, fixture, "\"expected_integrity_tag\": \"0dd63360ee9ba7ffae76ab38f3d70dde\"") != null);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_without_tag = [_]u8{
        0xf0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x83, 0x94, 0xc8, 0xf0,
        0x3e, 0x51, 0x57, 0x08, 0x08,
        0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f,
        0x6b, 0x65, 0x6e,
    };

    const tag = try KeyDerivation.deriveRetryIntegrityTagRfc9001(&retry_without_tag, &original_dcid);
    const expected_tag = [_]u8{
        0x0d, 0xd6, 0x33, 0x60, 0xee, 0x9b, 0xa7, 0xff,
        0xae, 0x76, 0xab, 0x38, 0xf3, 0xd7, 0x0d, 0xde,
    };
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    const same_tag = KeyDerivation.deriveRetryIntegrityTag(&retry_without_tag, &original_dcid);
    try std.testing.expectEqualSlices(u8, &tag, &same_tag);

    var changed_dcid = original_dcid;
    changed_dcid[0] ^= 0x01;
    const changed_dcid_tag = try KeyDerivation.deriveRetryIntegrityTagRfc9001(&retry_without_tag, &changed_dcid);
    try std.testing.expect(!std.mem.eql(u8, &tag, &changed_dcid_tag));

    var changed_retry = retry_without_tag;
    changed_retry[changed_retry.len - 1] ^= 0x01;
    const changed_retry_tag = try KeyDerivation.deriveRetryIntegrityTagRfc9001(&changed_retry, &original_dcid);
    try std.testing.expect(!std.mem.eql(u8, &tag, &changed_retry_tag));
}

test "retry integrity tag rejects oversized pseudo packet" {
    const original_dcid = [_]u8{ 0x01, 0x02 };
    const retry: [KeyDerivation.max_retry_pseudo_packet_len]u8 = @splat(0xaa);
    try std.testing.expectError(
        Error.ZquicError.BufferTooSmall,
        KeyDerivation.deriveRetryIntegrityTagRfc9001(&retry, &original_dcid),
    );
}
