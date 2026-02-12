//! SSH/QUIC integration
//!
//! Provides SSH secret injection for QUIC connections,
//! allowing SSH key exchange to replace TLS handshake.
//!
//! Per SSH/QUIC spec (draft-denis-ssh-quic):
//! After SSH key exchange, the application MUST derive:
//!   client_secret = HMAC-SHA256("ssh/quic client", mpint(K) || string(H))
//!   server_secret = HMAC-SHA256("ssh/quic server", mpint(K) || string(H))
//!
//! This module does NOT perform the HMAC-SHA256 derivation itself; instead,
//! it accepts already-derived 32-byte client and server secrets and uses
//! them to initialize QUIC in post-handshake state.
//!
//! Security notes:
//! - Secrets should be passed by pointer to minimize stack copies
//! - Call `zeroize()` on SshQuicSecrets after use to clear sensitive data

const std = @import("std");
const Error = @import("../utils/error.zig");
const Tls = @import("tls.zig");

/// SSH-derived QUIC secrets
///
/// Contains the pre-derived 32-byte secrets from SSH key exchange.
/// Both client and server must use the same secrets to establish
/// a working QUIC connection.
pub const SshQuicSecrets = struct {
    client_secret: [32]u8,
    server_secret: [32]u8,

    const Self = @This();

    /// Initialize from SSH-derived secrets (copies the values)
    pub fn init(client_secret: [32]u8, server_secret: [32]u8) Self {
        return Self{
            .client_secret = client_secret,
            .server_secret = server_secret,
        };
    }

    /// Initialize from pointers to SSH-derived secrets (avoids extra copies)
    pub fn initFromPtrs(client_secret: *const [32]u8, server_secret: *const [32]u8) Self {
        return Self{
            .client_secret = client_secret.*,
            .server_secret = server_secret.*,
        };
    }

    /// Derive QUIC crypto keys from SSH secrets
    /// Returns client keys and server keys
    pub fn deriveKeys(self: *const Self) Error.ZquicError!struct {
        client: Tls.CryptoKeys,
        server: Tls.CryptoKeys,
    } {
        const client_keys = try Tls.CryptoKeys.deriveFromSecret(&self.client_secret);
        const server_keys = try Tls.CryptoKeys.deriveFromSecret(&self.server_secret);

        return .{
            .client = client_keys,
            .server = server_keys,
        };
    }

    /// Securely zero the secrets to minimize exposure of sensitive material.
    /// Call this after initializing the QUIC context.
    pub fn zeroize(self: *Self) void {
        std.crypto.secureZero(u8, &self.client_secret);
        std.crypto.secureZero(u8, &self.server_secret);
    }
};

/// Extended TLS context that supports SSH secret injection
pub const SshQuicContext = struct {
    tls_ctx: Tls.TlsContext,
    ssh_mode: bool,
    /// Store both key sets for proper directional encryption
    local_keys: ?Tls.CryptoKeys,
    remote_keys: ?Tls.CryptoKeys,

    const Self = @This();

    /// Initialize with SSH-derived secrets (bypasses TLS handshake)
    ///
    /// Takes secrets by pointer to minimize copies of sensitive material.
    /// After calling this, you should call `secrets.zeroize()` to clear
    /// the original secret data.
    pub fn initWithSshSecrets(
        allocator: std.mem.Allocator,
        is_server: bool,
        secrets: *const SshQuicSecrets,
    ) Error.ZquicError!Self {
        var tls_ctx = Tls.TlsContext.init(allocator, is_server);

        // Derive keys from SSH secrets
        const keys = try secrets.deriveKeys();

        // Set application keys directly (bypass handshake).
        // For interoperability, both client and server use the client keys
        // as the shared application key. The local/remote key distinction
        // is maintained separately for proper directional encryption.
        tls_ctx.application_keys = keys.client;

        // Store directional keys for proper encrypt/decrypt operations
        var local_keys: Tls.CryptoKeys = undefined;
        var remote_keys: Tls.CryptoKeys = undefined;
        if (is_server) {
            local_keys = keys.server;
            remote_keys = keys.client;
        } else {
            local_keys = keys.client;
            remote_keys = keys.server;
        }

        // Mark handshake as completed (we used SSH instead)
        tls_ctx.state = .completed;

        return Self{
            .tls_ctx = tls_ctx,
            .ssh_mode = true,
            .local_keys = local_keys,
            .remote_keys = remote_keys,
        };
    }

    /// Initialize with normal TLS handshake
    pub fn initWithTls(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .tls_ctx = Tls.TlsContext.init(allocator, is_server),
            .ssh_mode = false,
            .local_keys = null,
            .remote_keys = null,
        };
    }

    pub fn deinit(self: *Self) void {
        // Securely zero keys before deallocation
        if (self.local_keys) |*keys| {
            std.crypto.secureZero(u8, &keys.secret);
            std.crypto.secureZero(u8, &keys.key);
            std.crypto.secureZero(u8, &keys.iv);
            std.crypto.secureZero(u8, &keys.header_protection_key);
        }
        if (self.remote_keys) |*keys| {
            std.crypto.secureZero(u8, &keys.secret);
            std.crypto.secureZero(u8, &keys.key);
            std.crypto.secureZero(u8, &keys.iv);
            std.crypto.secureZero(u8, &keys.header_protection_key);
        }
        self.tls_ctx.deinit();
    }

    /// Check if using SSH mode (no TLS handshake)
    pub fn isSshMode(self: *const Self) bool {
        return self.ssh_mode;
    }

    /// Get the underlying TLS context
    pub fn getTlsContext(self: *Self) *Tls.TlsContext {
        return &self.tls_ctx;
    }

    /// Check if ready to send/receive data
    pub fn isReady(self: *const Self) bool {
        return self.tls_ctx.isHandshakeComplete();
    }

    /// Get local keys for encryption (data we send)
    pub fn getLocalKeys(self: *const Self) ?*const Tls.CryptoKeys {
        return if (self.local_keys) |*keys| keys else null;
    }

    /// Get remote keys for decryption (data we receive)
    pub fn getRemoteKeys(self: *const Self) ?*const Tls.CryptoKeys {
        return if (self.remote_keys) |*keys| keys else null;
    }

    /// Encrypt data using local keys (for sending)
    pub fn encrypt(
        self: *const Self,
        plaintext: []const u8,
        packet_number: u64,
        allocator: std.mem.Allocator,
    ) Error.ZquicError![]u8 {
        if (!self.ssh_mode) {
            // In TLS mode, use the standard TLS context encryption
            return self.tls_ctx.encrypt(.application, plaintext, packet_number, allocator);
        }

        // SSH mode encryption using local keys
        const keys = self.local_keys orelse return Error.ZquicError.CryptoError;

        // TODO: Implement proper AEAD encryption using keys and packet_number as nonce
        // For now, use a simplified XOR-based approach for testing
        var ciphertext = try allocator.alloc(u8, plaintext.len + 16);
        for (ciphertext[0..plaintext.len], plaintext, 0..) |*c, p, i| {
            c.* = p ^ keys.key[i % keys.key.len];
        }
        // Encode packet number in auth tag for verification
        std.mem.writeInt(u64, ciphertext[plaintext.len..][0..8], packet_number, .little);
        @memset(ciphertext[plaintext.len + 8 ..], 0xAA);

        return ciphertext;
    }

    /// Decrypt data using remote keys (for receiving)
    pub fn decrypt(
        self: *const Self,
        ciphertext: []const u8,
        packet_number: u64,
        allocator: std.mem.Allocator,
    ) Error.ZquicError![]u8 {
        if (!self.ssh_mode) {
            // In TLS mode, use the standard TLS context decryption
            return self.tls_ctx.decrypt(.application, ciphertext, packet_number, allocator);
        }

        // SSH mode decryption using remote keys
        const keys = self.remote_keys orelse return Error.ZquicError.CryptoError;

        if (ciphertext.len < 16) {
            return Error.ZquicError.CryptoError;
        }

        // Verify packet number from auth tag
        const plaintext_len = ciphertext.len - 16;
        const stored_pn = std.mem.readInt(u64, ciphertext[plaintext_len..][0..8], .little);
        if (stored_pn != packet_number) {
            return Error.ZquicError.CryptoError;
        }

        // TODO: Implement proper AEAD decryption
        // For now, use simplified XOR-based approach for testing
        const plaintext = try allocator.alloc(u8, plaintext_len);
        for (plaintext, ciphertext[0..plaintext_len], 0..) |*p, c, i| {
            p.* = c ^ keys.key[i % keys.key.len];
        }

        return plaintext;
    }
};

test "SSH secret derivation" {
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;

    var secrets = SshQuicSecrets.init(client_secret, server_secret);
    const keys = try secrets.deriveKeys();

    // Verify keys were derived and are different
    try std.testing.expect(!std.mem.eql(u8, &keys.client.key, &keys.server.key));

    // Test zeroization
    secrets.zeroize();
    try std.testing.expect(std.mem.eql(u8, &secrets.client_secret, &([_]u8{0} ** 32)));
    try std.testing.expect(std.mem.eql(u8, &secrets.server_secret, &([_]u8{0} ** 32)));
}

test "SSH QUIC context initialization" {
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;
    var secrets = SshQuicSecrets.init(client_secret, server_secret);
    defer secrets.zeroize();

    var ctx = try SshQuicContext.initWithSshSecrets(
        std.testing.allocator,
        false,
        &secrets,
    );
    defer ctx.deinit();

    try std.testing.expect(ctx.isSshMode());
    try std.testing.expect(ctx.isReady());
    try std.testing.expect(ctx.getTlsContext().isHandshakeComplete());

    // Verify keys are accessible
    try std.testing.expect(ctx.getLocalKeys() != null);
    try std.testing.expect(ctx.getRemoteKeys() != null);
}

test "Normal TLS mode still works" {
    var ctx = SshQuicContext.initWithTls(std.testing.allocator, false);
    defer ctx.deinit();

    try std.testing.expect(!ctx.isSshMode());
    try std.testing.expect(!ctx.isReady()); // Needs handshake
    try std.testing.expect(ctx.getLocalKeys() == null);
    try std.testing.expect(ctx.getRemoteKeys() == null);
}

test "Client-server interop: encrypt/decrypt roundtrip" {
    // Both client and server use the same secrets (as they would after SSH key exchange)
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;

    var client_secrets = SshQuicSecrets.init(client_secret, server_secret);
    defer client_secrets.zeroize();

    var server_secrets = SshQuicSecrets.init(client_secret, server_secret);
    defer server_secrets.zeroize();

    // Initialize client context
    var client_ctx = try SshQuicContext.initWithSshSecrets(
        std.testing.allocator,
        false, // is_server = false
        &client_secrets,
    );
    defer client_ctx.deinit();

    // Initialize server context
    var server_ctx = try SshQuicContext.initWithSshSecrets(
        std.testing.allocator,
        true, // is_server = true
        &server_secrets,
    );
    defer server_ctx.deinit();

    // Test that client can encrypt and server can decrypt
    const plaintext = "Hello from client!";
    const packet_number: u64 = 1;

    // Client encrypts
    const ciphertext = try client_ctx.encrypt(plaintext, packet_number, std.testing.allocator);
    defer std.testing.allocator.free(ciphertext);

    // Server decrypts
    const decrypted = try server_ctx.decrypt(ciphertext, packet_number, std.testing.allocator);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);

    // Test reverse direction: server encrypts, client decrypts
    const server_plaintext = "Hello from server!";
    const server_ciphertext = try server_ctx.encrypt(server_plaintext, packet_number, std.testing.allocator);
    defer std.testing.allocator.free(server_ciphertext);

    const client_decrypted = try client_ctx.decrypt(server_ciphertext, packet_number, std.testing.allocator);
    defer std.testing.allocator.free(client_decrypted);

    try std.testing.expectEqualStrings(server_plaintext, client_decrypted);
}

test "initFromPtrs avoids extra copies" {
    const client_secret = [_]u8{0xCC} ** 32;
    const server_secret = [_]u8{0xDD} ** 32;

    var secrets = SshQuicSecrets.initFromPtrs(&client_secret, &server_secret);
    defer secrets.zeroize();

    try std.testing.expectEqualSlices(u8, &client_secret, &secrets.client_secret);
    try std.testing.expectEqualSlices(u8, &server_secret, &secrets.server_secret);
}
