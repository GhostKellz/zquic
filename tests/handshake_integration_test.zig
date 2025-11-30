//! Handshake integration tests exercising client/server flows

const std = @import("std");
const zquic = @import("zquic");

const HandshakeManager = zquic.Handshake.HandshakeManager;

test "integration: client and server complete handshake" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = HandshakeManager.init(allocator, false);
    defer client.deinit();

    var server = HandshakeManager.init(allocator, true);
    defer server.deinit();

    const connection_id = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04 };

    try client.startHandshake(&connection_id);
    try server.startHandshake(&connection_id);

    var safety_counter: usize = 0;
    while ((client.isComplete() == false or server.isComplete() == false) and safety_counter < 16) : (safety_counter += 1) {
        const client_crypto = client.getPendingCryptoData();
        if (client_crypto.len > 0) {
            try server.processCryptoFrame(client_crypto, 0);
            client.clearSentCryptoData();
        }

        const server_crypto = server.getPendingCryptoData();
        if (server_crypto.len > 0) {
            try client.processCryptoFrame(server_crypto, 0);
            server.clearSentCryptoData();
        }
    }

    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
    try std.testing.expect(client.getCurrentEncryptionLevel() == .application);
    try std.testing.expect(server.getCurrentEncryptionLevel() == .application);
}

test "integration: handshake tolerates fragmented crypto frames" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = HandshakeManager.init(allocator, false);
    defer client.deinit();

    var server = HandshakeManager.init(allocator, true);
    defer server.deinit();

    const connection_id = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD };

    try client.startHandshake(&connection_id);
    try server.startHandshake(&connection_id);

    const client_crypto = client.getPendingCryptoData();
    try std.testing.expect(client_crypto.len > 4);

    const split = client_crypto.len / 2;
    try server.processCryptoFrame(client_crypto[0..split], 0);
    try server.processCryptoFrame(client_crypto[split..], split);
    client.clearSentCryptoData();

    const server_crypto = server.getPendingCryptoData();
    try std.testing.expect(server_crypto.len > 0);
    try client.processCryptoFrame(server_crypto, 0);
    server.clearSentCryptoData();

    const server_level = server.getCurrentEncryptionLevel();
    try std.testing.expect(server_level == .handshake or server_level == .application);

    const client_level = client.getCurrentEncryptionLevel();
    try std.testing.expect(client_level == .handshake or client_level == .application);
}
