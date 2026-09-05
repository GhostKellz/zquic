//! QUIC handshake management
//!
//! Manages the QUIC+TLS handshake process

const std = @import("std");
const Error = @import("../utils/error.zig");
const Tls = @import("tls.zig");
const EnhancedTls = @import("enhanced_tls.zig");
const PacketCryptoMod = @import("../core/packet_crypto.zig");

/// Handshake manager that coordinates QUIC and TLS
pub const HandshakeManager = struct {
    tls_context: Tls.TlsContext,
    crypto_buffer: std.ArrayListUnmanaged(u8),
    handshake_crypto_buffer: std.ArrayListUnmanaged(u8),
    handshake_complete: bool,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, is_server: bool) Self {
        return Self{
            .tls_context = Tls.TlsContext.init(allocator, is_server),
            .crypto_buffer = .empty,
            .handshake_crypto_buffer = .empty,
            .handshake_complete = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tls_context.deinit();
        self.crypto_buffer.deinit(self.allocator);
        self.handshake_crypto_buffer.deinit(self.allocator);
    }

    /// Start the handshake process
    pub fn startHandshake(self: *Self, connection_id: []const u8) Error.ZquicError!void {
        try self.tls_context.initializeInitialKeys(connection_id);

        // Generate initial CRYPTO frame if client
        if (!self.tls_context.is_server) {
            const crypto_data = try self.tls_context.generateCryptoData(self.allocator);
            defer self.allocator.free(crypto_data);
            try self.crypto_buffer.appendSlice(self.allocator, crypto_data);
        }
    }

    /// Process incoming CRYPTO frame
    pub fn processCryptoFrame(self: *Self, data: []const u8, offset: u64) Error.ZquicError!void {
        try self.tls_context.processCryptoData(data, offset);

        // Check if we need to generate response
        if (self.tls_context.state == .wait_server_hello and self.tls_context.is_server) {
            const crypto_data = try self.tls_context.generateCryptoData(self.allocator);
            defer self.allocator.free(crypto_data);
            try self.crypto_buffer.appendSlice(self.allocator, crypto_data);

            // The compatibility TLS engine still models messages rather than
            // encoding a production TLS 1.3 flight. Keep the post-ServerHello
            // bytes in Handshake space so packet scheduling and evidence do
            // not incorrectly collapse both QUIC encryption levels.
            const handshake_flight = "EncryptedExtensions, Certificate, CertificateVerify, Finished";
            try self.handshake_crypto_buffer.appendSlice(self.allocator, handshake_flight);
        } else if (self.tls_context.state == .wait_finished and !self.tls_context.is_server) {
            const crypto_data = try self.tls_context.generateCryptoData(self.allocator);
            defer self.allocator.free(crypto_data);
            // The compatibility TLS engine historically exposes the client's
            // Finished through the generic buffer. Preserve that API while the
            // level-aware accessor below classifies it as Handshake data.
            try self.crypto_buffer.appendSlice(self.allocator, crypto_data);
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

    pub fn getPendingCryptoDataForLevel(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
    ) []const u8 {
        return self.pendingCryptoBufferForLevel(level).items;
    }

    pub fn clearSentCryptoDataForLevel(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
    ) void {
        self.pendingCryptoBufferForLevel(level).clearRetainingCapacity();
    }

    fn pendingCryptoBufferForLevel(
        self: *Self,
        level: PacketCryptoMod.EncryptionLevel,
    ) *std.ArrayListUnmanaged(u8) {
        return switch (level) {
            .handshake => if (self.handshake_crypto_buffer.items.len > 0 or self.tls_context.is_server)
                &self.handshake_crypto_buffer
            else
                &self.crypto_buffer,
            .initial, .early_data, .application => &self.crypto_buffer,
        };
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

    /// Synchronize live handshake progress into packet protection keys.
    ///
    /// The current compatibility handshake is still a synthetic TLS message
    /// flow, but this keeps packet key installation tied to the actual CRYPTO
    /// transcript seen by the manager instead of a caller-owned side channel.
    pub fn syncPacketCrypto(
        self: *Self,
        enhanced_tls_context: *EnhancedTls.EnhancedTlsContext,
        packet_crypto: *PacketCryptoMod.PacketCrypto,
        connection_id: []const u8,
    ) Error.ZquicError!usize {
        try self.deriveEnhancedPacketKeys(enhanced_tls_context, connection_id);
        return packet_crypto.refreshKeysFromTlsContext() catch Error.ZquicError.CryptoError;
    }

    /// Derive Enhanced TLS packet keys available for the current handshake
    /// state from the manager's stored transcript.
    pub fn deriveEnhancedPacketKeys(
        self: *Self,
        enhanced_tls_context: *EnhancedTls.EnhancedTlsContext,
        connection_id: []const u8,
    ) Error.ZquicError!void {
        if (enhanced_tls_context.initial_keys == null) {
            enhanced_tls_context.initializeInitialKeys(connection_id) catch return Error.ZquicError.CryptoError;
        }

        switch (self.tls_context.state) {
            .wait_finished, .completed => {
                if (enhanced_tls_context.handshake_keys == null) {
                    var handshake_secret: [48]u8 = undefined;
                    self.deriveTranscriptSecret(connection_id, "zquic handshake traffic", &handshake_secret);
                    enhanced_tls_context.deriveHandshakeKeys(&handshake_secret) catch return Error.ZquicError.CryptoError;
                }
            },
            else => {},
        }

        if (self.tls_context.state == .completed and enhanced_tls_context.application_keys == null) {
            var application_secret: [48]u8 = undefined;
            self.deriveTranscriptSecret(connection_id, "zquic application traffic", &application_secret);
            enhanced_tls_context.deriveApplicationKeys(&application_secret) catch return Error.ZquicError.CryptoError;
        }
    }

    fn deriveTranscriptSecret(
        self: *const Self,
        connection_id: []const u8,
        label: []const u8,
        out: *[48]u8,
    ) void {
        var hasher = std.crypto.hash.sha2.Sha384.init(.{});
        hasher.update("zquic handshake manager packet key bridge");
        hasher.update(label);
        hasher.update(connection_id);

        if (self.tls_context.client_hello) |data| hasher.update(data);
        if (self.tls_context.server_hello) |data| hasher.update(data);
        if (self.tls_context.finished) |data| hasher.update(data);

        hasher.final(out);
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
