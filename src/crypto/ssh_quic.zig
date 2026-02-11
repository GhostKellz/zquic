//! SSH/QUIC integration
//!
//! Provides SSH secret injection for QUIC connections,
//! allowing SSH key exchange to replace TLS handshake.
//!
//! Per SSH/QUIC spec (draft-denis-ssh-quic):
//! After SSH key exchange, derive:
//!   client_secret = HMAC-SHA256("ssh/quic client", mpint(K) || string(H))
//!   server_secret = HMAC-SHA256("ssh/quic server", mpint(K) || string(H))
//!
//! These secrets are used to initialize QUIC in post-handshake state.

const std = @import("std");
const Error = @import("../utils/error.zig");
const Tls = @import("tls.zig");

/// SSH-derived QUIC secrets
pub const SshQuicSecrets = struct {
    client_secret: [32]u8,
    server_secret: [32]u8,

    const Self = @This();

    /// Initialize from SSH-derived secrets
    pub fn init(client_secret: [32]u8, server_secret: [32]u8) Self {
        return Self{
            .client_secret = client_secret,
            .server_secret = server_secret,
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
};

/// Extended TLS context that supports SSH secret injection
pub const SshQuicContext = struct {
    tls_ctx: Tls.TlsContext,
    ssh_mode: bool,

    const Self = @This();

    /// Initialize with SSH-derived secrets (bypasses TLS handshake)
    pub fn initWithSshSecrets(
        allocator: std.mem.Allocator,
        is_server: bool,
        secrets: SshQuicSecrets,
    ) Error.ZquicError!Self {
        var tls_ctx = Tls.TlsContext.init(allocator, is_server);

        // Derive keys from SSH secrets
        const keys = try secrets.deriveKeys();

        // Set application keys directly (bypass handshake)
        if (is_server) {
            tls_ctx.application_keys = keys.server;
        } else {
            tls_ctx.application_keys = keys.client;
        }

        // Mark handshake as completed (we used SSH instead)
        tls_ctx.state = .completed;

        return Self{
            .tls_ctx = tls_ctx,
            .ssh_mode = true,
        };
    }

    /// Initialize with normal TLS handshake
    pub fn initWithTls(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .tls_ctx = Tls.TlsContext.init(allocator, is_server),
            .ssh_mode = false,
        };
    }

    pub fn deinit(self: *Self) void {
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
};

test "SSH secret derivation" {
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;

    const secrets = SshQuicSecrets.init(client_secret, server_secret);
    const keys = try secrets.deriveKeys();

    // Verify keys were derived
    try std.testing.expect(!std.mem.eql(u8, &keys.client.key, &keys.server.key));
}

test "SSH QUIC context initialization" {
    const client_secret = [_]u8{0xAA} ** 32;
    const server_secret = [_]u8{0xBB} ** 32;
    const secrets = SshQuicSecrets.init(client_secret, server_secret);

    var ctx = try SshQuicContext.initWithSshSecrets(
        std.testing.allocator,
        false,
        secrets,
    );
    defer ctx.deinit();

    try std.testing.expect(ctx.isSshMode());
    try std.testing.expect(ctx.isReady());
    try std.testing.expect(ctx.getTlsContext().isHandshakeComplete());
}

test "Normal TLS mode still works" {
    var ctx = SshQuicContext.initWithTls(std.testing.allocator, false);
    defer ctx.deinit();

    try std.testing.expect(!ctx.isSshMode());
    try std.testing.expect(!ctx.isReady()); // Needs handshake
}
