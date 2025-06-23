//! QUIC handshake management
//!
//! Manages the QUIC+TLS handshake process

const std = @import("std");
const Error = @import("../utils/error.zig");
const Tls = @import("tls.zig");

/// Handshake manager that coordinates QUIC and TLS
pub const HandshakeManager = struct {
    tls_context: Tls.TlsContext,
    crypto_buffer: std.ArrayList(u8),
    handshake_complete: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .tls_context = Tls.TlsContext.init(allocator, is_server),
            .crypto_buffer = std.ArrayList(u8).init(allocator),
            .handshake_complete = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tls_context.deinit();
        self.crypto_buffer.deinit();
    }

    /// Start the handshake process
    pub fn startHandshake(self: *Self, connection_id: []const u8) Error.ZquicError!void {
        try self.tls_context.initializeInitialKeys(connection_id);

        // Generate initial CRYPTO frame if client
        if (!self.tls_context.is_server) {
            const crypto_data = try self.tls_context.generateCryptoData(self.crypto_buffer.allocator);
            defer self.crypto_buffer.allocator.free(crypto_data);
            try self.crypto_buffer.appendSlice(crypto_data);
        }
    }

    /// Process incoming CRYPTO frame
    pub fn processCryptoFrame(self: *Self, data: []const u8, offset: u64) Error.ZquicError!void {
        try self.tls_context.processCryptoData(data, offset);

        // Check if we need to generate response
        if (self.tls_context.state == .wait_server_hello and self.tls_context.is_server) {
            const crypto_data = try self.tls_context.generateCryptoData(self.crypto_buffer.allocator);
            defer self.crypto_buffer.allocator.free(crypto_data);
            try self.crypto_buffer.appendSlice(crypto_data);
        }

        if (self.tls_context.isHandshakeComplete()) {
            self.handshake_complete = true;
        }
    }

    /// Get pending CRYPTO data to send
    pub fn getPendingCryptoData(self: *Self) []const u8 {
        return self.crypto_buffer.items;
    }

    /// Clear sent CRYPTO data
    pub fn clearSentCryptoData(self: *Self) void {
        self.crypto_buffer.clearRetainingCapacity();
    }

    /// Check if handshake is complete
    pub fn isComplete(self: *const Self) bool {
        return self.handshake_complete;
    }

    /// Get encryption level for current handshake state
    pub fn getCurrentEncryptionLevel(self: *const Self) Tls.EncryptionLevel {
        return switch (self.tls_context.state) {
            .initial, .wait_client_hello, .wait_server_hello => .initial,
            .wait_finished => .handshake,
            .completed => .application,
            .failed => .initial,
        };
    }
};

test "handshake manager initialization" {
    var manager = HandshakeManager.init(std.testing.allocator, false);
    defer manager.deinit();

    try std.testing.expect(!manager.isComplete());
    try std.testing.expect(manager.getCurrentEncryptionLevel() == .initial);
}

test "handshake flow with manager" {
    var client_manager = HandshakeManager.init(std.testing.allocator, false);
    defer client_manager.deinit();

    var server_manager = HandshakeManager.init(std.testing.allocator, true);
    defer server_manager.deinit();

    const conn_id = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    // Start client handshake
    try client_manager.startHandshake(conn_id);

    // Client should have pending CRYPTO data
    const client_hello = client_manager.getPendingCryptoData();
    try std.testing.expect(client_hello.len > 0);

    // Server processes ClientHello
    try server_manager.processCryptoFrame(client_hello, 0);

    // Server should have pending CRYPTO data
    const server_hello = server_manager.getPendingCryptoData();
    try std.testing.expect(server_hello.len > 0);
}
