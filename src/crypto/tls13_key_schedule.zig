//! TLS 1.3 key schedule and RFC 9001 packet-protection key derivation.
//!
//! Scope is deliberately narrow: SHA-256 / AES-128-GCM / X25519 only, and only
//! the portions of the schedule needed for QUIC Handshake and first-generation
//! application (1-RTT) packet keys. Early-data and resumption are not derived
//! here.
//!
//! This module is a leaf: it imports only `std` and the project error set, so it
//! can be used from both the TLS layer and the packet-crypto layer without
//! creating an import cycle.

const std = @import("std");
const Error = @import("../utils/error.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const hash_length = Sha256.digest_length;
pub const aead_key_length = 16;
pub const aead_iv_length = 12;
pub const header_protection_key_length = 16;

/// HKDF-Expand-Label per RFC 8446 Section 7.1, specialised to SHA-256.
///
/// The `HkdfLabel` structure is:
///   uint16 length; opaque label<7..255> = "tls13 " ++ label; opaque context<0..255>;
///
/// Allocation-free: `info` is built on the stack, which bounds `label` and
/// `context` to 64 bytes each. Longer inputs are rejected rather than truncated.
pub fn hkdfExpandLabelSha256(
    secret: *const [hash_length]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) Error.ZquicError!void {
    const tls_prefix = "tls13 ";
    const full_label_len = tls_prefix.len + label.len;
    if (out.len > std.math.maxInt(u16) or full_label_len > std.math.maxInt(u8) or context.len > std.math.maxInt(u8)) {
        return Error.ZquicError.CryptoError;
    }

    var info: [2 + 1 + tls_prefix.len + 64 + 1 + 64]u8 = undefined;
    if (full_label_len > tls_prefix.len + 64 or context.len > 64) {
        return Error.ZquicError.CryptoError;
    }

    var offset: usize = 0;
    std.mem.writeInt(u16, info[offset..][0..2], @intCast(out.len), .big);
    offset += 2;
    info[offset] = @intCast(full_label_len);
    offset += 1;
    @memcpy(info[offset .. offset + tls_prefix.len], tls_prefix);
    offset += tls_prefix.len;
    @memcpy(info[offset .. offset + label.len], label);
    offset += label.len;
    info[offset] = @intCast(context.len);
    offset += 1;
    @memcpy(info[offset .. offset + context.len], context);
    offset += context.len;

    HkdfSha256.expand(out, info[0..offset], secret.*);
}

/// Derive-Secret per RFC 8446 Section 7.1: HKDF-Expand-Label with a transcript
/// hash as the context and a full hash-length output.
pub fn deriveSecret(
    secret: *const [hash_length]u8,
    label: []const u8,
    transcript_hash: *const [hash_length]u8,
    out: *[hash_length]u8,
) Error.ZquicError!void {
    try hkdfExpandLabelSha256(secret, label, transcript_hash, out);
}

/// RFC 9001 Section 5.1 packet-protection keys for one direction.
pub const QuicPacketKeys = struct {
    key: [aead_key_length]u8,
    iv: [aead_iv_length]u8,
    hp: [header_protection_key_length]u8,

    pub fn zeroize(self: *QuicPacketKeys) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
        std.crypto.secureZero(u8, &self.hp);
    }
};

/// Derive the RFC 9001 `quic key` / `quic iv` / `quic hp` triple from a TLS
/// traffic secret.
pub fn deriveQuicPacketKeys(traffic_secret: *const [hash_length]u8) Error.ZquicError!QuicPacketKeys {
    var keys: QuicPacketKeys = undefined;
    try hkdfExpandLabelSha256(traffic_secret, "quic key", &.{}, &keys.key);
    try hkdfExpandLabelSha256(traffic_secret, "quic iv", &.{}, &keys.iv);
    try hkdfExpandLabelSha256(traffic_secret, "quic hp", &.{}, &keys.hp);
    return keys;
}

/// Everything derived at the Handshake boundary, for both directions.
///
/// `client_*` is what the client writes with and the server reads with;
/// `server_*` is what the server writes with and the client reads with.
pub const HandshakeKeySchedule = struct {
    handshake_secret: [hash_length]u8,
    client_traffic_secret: [hash_length]u8,
    server_traffic_secret: [hash_length]u8,
    client_packet_keys: QuicPacketKeys,
    server_packet_keys: QuicPacketKeys,

    pub fn zeroize(self: *HandshakeKeySchedule) void {
        std.crypto.secureZero(u8, &self.handshake_secret);
        std.crypto.secureZero(u8, &self.client_traffic_secret);
        std.crypto.secureZero(u8, &self.server_traffic_secret);
        self.client_packet_keys.zeroize();
        self.server_packet_keys.zeroize();
    }
};

/// Compute TLS 1.3 Finished.verify_data for one Handshake traffic secret.
pub fn computeFinishedVerifyData(
    traffic_secret: *const [hash_length]u8,
    transcript_hash: *const [hash_length]u8,
) Error.ZquicError![hash_length]u8 {
    var finished_key: [hash_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &finished_key);
    try hkdfExpandLabelSha256(traffic_secret, "finished", &.{}, &finished_key);

    var verify_data: [hash_length]u8 = undefined;
    HmacSha256.create(&verify_data, transcript_hash, &finished_key);
    return verify_data;
}

/// TLS 1.3 application traffic secrets and their RFC 9001 packet keys.
/// The transcript hash is through the server Finished message.
pub const ApplicationKeySchedule = struct {
    master_secret: [hash_length]u8,
    client_traffic_secret: [hash_length]u8,
    server_traffic_secret: [hash_length]u8,
    client_packet_keys: QuicPacketKeys,
    server_packet_keys: QuicPacketKeys,

    pub fn zeroize(self: *ApplicationKeySchedule) void {
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.client_traffic_secret);
        std.crypto.secureZero(u8, &self.server_traffic_secret);
        self.client_packet_keys.zeroize();
        self.server_packet_keys.zeroize();
    }
};

/// Advance the no-PSK TLS 1.3 key schedule from the Handshake secret to the
/// first application traffic secrets at H(ClientHello..server Finished).
pub fn deriveApplicationKeySchedule(
    handshake_secret: *const [hash_length]u8,
    transcript_hash: *const [hash_length]u8,
) Error.ZquicError!ApplicationKeySchedule {
    var empty_hash: [hash_length]u8 = undefined;
    Sha256.hash(&.{}, &empty_hash, .{});

    var derived: [hash_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &derived);
    try deriveSecret(handshake_secret, "derived", &empty_hash, &derived);

    const zero_ikm: [hash_length]u8 = @splat(0);
    var schedule: ApplicationKeySchedule = undefined;
    schedule.master_secret = HkdfSha256.extract(&derived, &zero_ikm);
    try deriveSecret(&schedule.master_secret, "c ap traffic", transcript_hash, &schedule.client_traffic_secret);
    try deriveSecret(&schedule.master_secret, "s ap traffic", transcript_hash, &schedule.server_traffic_secret);
    schedule.client_packet_keys = try deriveQuicPacketKeys(&schedule.client_traffic_secret);
    schedule.server_packet_keys = try deriveQuicPacketKeys(&schedule.server_traffic_secret);
    return schedule;
}

/// Run the TLS 1.3 key schedule from an ECDHE shared secret and the
/// ClientHello..ServerHello transcript hash, then derive RFC 9001 packet keys.
///
/// Schedule (RFC 8446 Section 7.1), with no PSK:
///   early_secret     = HKDF-Extract(salt: 0, ikm: 0)
///   derived          = Derive-Secret(early_secret, "derived", "")
///   handshake_secret = HKDF-Extract(salt: derived, ikm: shared_secret)
///   c hs traffic     = Derive-Secret(handshake_secret, "c hs traffic", H(CH..SH))
///   s hs traffic     = Derive-Secret(handshake_secret, "s hs traffic", H(CH..SH))
pub fn deriveHandshakeKeySchedule(
    shared_secret: *const [32]u8,
    transcript_hash: *const [hash_length]u8,
) Error.ZquicError!HandshakeKeySchedule {
    const zero_key: [hash_length]u8 = @splat(0);
    var early_secret = HkdfSha256.extract(&.{}, &zero_key);
    defer std.crypto.secureZero(u8, &early_secret);

    // Derive-Secret(early_secret, "derived", "") uses the hash of the empty string.
    var empty_hash: [hash_length]u8 = undefined;
    Sha256.hash(&.{}, &empty_hash, .{});

    var derived: [hash_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &derived);
    try deriveSecret(&early_secret, "derived", &empty_hash, &derived);

    var schedule: HandshakeKeySchedule = undefined;
    schedule.handshake_secret = HkdfSha256.extract(&derived, shared_secret);

    try deriveSecret(&schedule.handshake_secret, "c hs traffic", transcript_hash, &schedule.client_traffic_secret);
    try deriveSecret(&schedule.handshake_secret, "s hs traffic", transcript_hash, &schedule.server_traffic_secret);

    schedule.client_packet_keys = try deriveQuicPacketKeys(&schedule.client_traffic_secret);
    schedule.server_packet_keys = try deriveQuicPacketKeys(&schedule.server_traffic_secret);

    return schedule;
}

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "hkdfExpandLabelSha256 matches RFC 9001 Appendix A client Initial keys" {
    // RFC 9001 Appendix A.1/A.2 published vectors. This pins the label encoding
    // against a specification-provided answer, independent of this codebase.
    const initial_salt = hexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    const dcid = hexToBytes("8394c8f03e515708");

    const initial_secret = HkdfSha256.extract(&initial_salt, &dcid);

    var client_initial: [hash_length]u8 = undefined;
    try hkdfExpandLabelSha256(&initial_secret, "client in", &.{}, &client_initial);
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        &client_initial,
    );

    const keys = try deriveQuicPacketKeys(&client_initial);
    try testing.expectEqualSlices(u8, &hexToBytes("1f369613dd76d5467730efcbe3b1a22d"), &keys.key);
    try testing.expectEqualSlices(u8, &hexToBytes("fa044b2f42a3fd3b46fb255c"), &keys.iv);
    try testing.expectEqualSlices(u8, &hexToBytes("9f50449e04a0e810283a1e9933adedd2"), &keys.hp);
}

test "hkdfExpandLabelSha256 matches RFC 9001 Appendix A server Initial keys" {
    const initial_salt = hexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    const dcid = hexToBytes("8394c8f03e515708");
    const initial_secret = HkdfSha256.extract(&initial_salt, &dcid);

    var server_initial: [hash_length]u8 = undefined;
    try hkdfExpandLabelSha256(&initial_secret, "server in", &.{}, &server_initial);
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
        &server_initial,
    );

    const keys = try deriveQuicPacketKeys(&server_initial);
    try testing.expectEqualSlices(u8, &hexToBytes("cf3a5331653c364c88f0f379b6067e37"), &keys.key);
    try testing.expectEqualSlices(u8, &hexToBytes("0ac1493ca1905853b0bba03e"), &keys.iv);
    try testing.expectEqualSlices(u8, &hexToBytes("c206b8d9b9f0f37644430b490eeaa314"), &keys.hp);
}

test "deriveHandshakeKeySchedule matches RFC 8448 section 3 handshake secrets" {
    // RFC 8448 "Example Handshake Traces for TLS 1.3", Section 3 ("Simple
    // 1-RTT Handshake"). The shared secret and transcript hash below are the
    // values the RFC prints for the ClientHello..ServerHello boundary.
    const shared_secret = hexToBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    // H(ClientHello || ServerHello) as printed by RFC 8448 Section 3.
    const transcript_hash = hexToBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

    const schedule = try deriveHandshakeKeySchedule(&shared_secret, &transcript_hash);

    try testing.expectEqualSlices(
        u8,
        &hexToBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
        &schedule.handshake_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
        &schedule.client_traffic_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
        &schedule.server_traffic_secret,
    );
}

test "deriveApplicationKeySchedule matches RFC 8448 section 3 secrets" {
    const handshake_secret = hexToBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    const transcript_hash = hexToBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

    var schedule = try deriveApplicationKeySchedule(&handshake_secret, &transcript_hash);
    defer schedule.zeroize();
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
        &schedule.master_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
        &schedule.client_traffic_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &hexToBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
        &schedule.server_traffic_secret,
    );
}

test "Finished verify data is traffic-secret and transcript bound" {
    const secret: [hash_length]u8 = @splat(0x3a);
    const transcript_a: [hash_length]u8 = @splat(0x71);
    var transcript_b = transcript_a;
    transcript_b[0] ^= 1;
    var other_secret = secret;
    other_secret[0] ^= 1;

    const verify_a = try computeFinishedVerifyData(&secret, &transcript_a);
    const verify_b = try computeFinishedVerifyData(&secret, &transcript_b);
    const verify_c = try computeFinishedVerifyData(&other_secret, &transcript_a);
    try testing.expect(!std.mem.eql(u8, &verify_a, &verify_b));
    try testing.expect(!std.mem.eql(u8, &verify_a, &verify_c));
}

test "deriveHandshakeKeySchedule separates the two directions" {
    const shared_secret: [32]u8 = @splat(0x2a);
    const transcript_hash: [hash_length]u8 = @splat(0x5c);

    const schedule = try deriveHandshakeKeySchedule(&shared_secret, &transcript_hash);

    try testing.expect(!std.mem.eql(u8, &schedule.client_traffic_secret, &schedule.server_traffic_secret));
    try testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.key, &schedule.server_packet_keys.key));
    try testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.iv, &schedule.server_packet_keys.iv));
    try testing.expect(!std.mem.eql(u8, &schedule.client_packet_keys.hp, &schedule.server_packet_keys.hp));
}

test "deriveHandshakeKeySchedule is transcript bound" {
    const shared_secret: [32]u8 = @splat(0x2a);
    const transcript_a: [hash_length]u8 = @splat(0x5c);
    var transcript_b = transcript_a;
    transcript_b[0] ^= 0x01;

    const schedule_a = try deriveHandshakeKeySchedule(&shared_secret, &transcript_a);
    const schedule_b = try deriveHandshakeKeySchedule(&shared_secret, &transcript_b);

    // The handshake secret does not depend on the transcript, but every traffic
    // secret and packet key must.
    try testing.expectEqualSlices(u8, &schedule_a.handshake_secret, &schedule_b.handshake_secret);
    try testing.expect(!std.mem.eql(u8, &schedule_a.client_traffic_secret, &schedule_b.client_traffic_secret));
    try testing.expect(!std.mem.eql(u8, &schedule_a.server_traffic_secret, &schedule_b.server_traffic_secret));
}

test "hkdfExpandLabelSha256 rejects oversized label and context" {
    const secret: [hash_length]u8 = @splat(0);
    var out: [16]u8 = undefined;
    const long: [65]u8 = @splat('a');

    try testing.expectError(Error.ZquicError.CryptoError, hkdfExpandLabelSha256(&secret, &long, &.{}, &out));
    try testing.expectError(Error.ZquicError.CryptoError, hkdfExpandLabelSha256(&secret, "quic key", &long, &out));
}

test "zeroize clears schedule material" {
    const shared_secret: [32]u8 = @splat(0x2a);
    const transcript_hash: [hash_length]u8 = @splat(0x5c);
    var schedule = try deriveHandshakeKeySchedule(&shared_secret, &transcript_hash);

    schedule.zeroize();

    const zeros: [hash_length]u8 = @splat(0);
    const zero_key: [aead_key_length]u8 = @splat(0);
    const zero_iv: [aead_iv_length]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zeros, &schedule.handshake_secret);
    try testing.expectEqualSlices(u8, &zeros, &schedule.client_traffic_secret);
    try testing.expectEqualSlices(u8, &zeros, &schedule.server_traffic_secret);
    try testing.expectEqualSlices(u8, &zero_key, &schedule.client_packet_keys.key);
    try testing.expectEqualSlices(u8, &zero_iv, &schedule.server_packet_keys.iv);
}
