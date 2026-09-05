//! Ephemeral Ed25519 and ECDSA P-256 identities for the live QUIC interop probe.
//!
//! The certificate is a minimal self-signed X.509 v3 certificate generated for
//! each process. It is intentionally not a production credential: insecure
//! interop clients may parse it, but no trust claim is made.

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const EphemeralIdentity = struct {
    certificate_der: []u8,
    secret_key: [Ed25519.SecretKey.encoded_length]u8,
    allocator: std.mem.Allocator,

    pub fn generate(allocator: std.mem.Allocator) Error.ZquicError!EphemeralIdentity {
        var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
        zcrypto.rand.fill(&seed);
        defer std.crypto.secureZero(u8, &seed);
        const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch return Error.ZquicError.CryptoError;

        var serial: [16]u8 = undefined;
        zcrypto.rand.fill(&serial);
        serial[0] &= 0x7f;
        if (std.mem.allEqual(u8, &serial, 0)) serial[serial.len - 1] = 1;

        const certificate_der = try buildCertificate(allocator, key_pair, &serial);
        return .{
            .certificate_der = certificate_der,
            .secret_key = key_pair.secret_key.toBytes(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EphemeralIdentity) void {
        std.crypto.secureZero(u8, &self.secret_key);
        self.allocator.free(self.certificate_der);
        self.certificate_der = &.{};
    }

    /// Derive an opaque per-connection server CID without exposing the signing
    /// key. This is domain-separated from Ed25519 use and truncated to the
    /// short-header CID length used by the probe.
    pub fn deriveConnectionId(
        self: *const EphemeralIdentity,
        client_dcid: []const u8,
        client_scid: []const u8,
        now_us: i64,
    ) [8]u8 {
        var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.secret_key);
        mac.update("zquic interop server cid v1");
        mac.update(client_dcid);
        mac.update(client_scid);
        var time_bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &time_bytes, now_us, .big);
        mac.update(&time_bytes);
        var digest: [32]u8 = undefined;
        mac.final(&digest);
        defer std.crypto.secureZero(u8, &digest);
        return digest[0..8].*;
    }
};

pub const EphemeralP256Identity = struct {
    certificate_der: []u8,
    secret_key: [EcdsaP256.SecretKey.encoded_length]u8,
    allocator: std.mem.Allocator,

    pub fn generate(allocator: std.mem.Allocator) Error.ZquicError!EphemeralP256Identity {
        var seed: [EcdsaP256.KeyPair.seed_length]u8 = undefined;
        zcrypto.rand.fill(&seed);
        defer std.crypto.secureZero(u8, &seed);
        const key_pair = EcdsaP256.KeyPair.generateDeterministic(seed) catch return Error.ZquicError.CryptoError;

        var serial: [16]u8 = undefined;
        zcrypto.rand.fill(&serial);
        serial[0] &= 0x7f;
        if (std.mem.allEqual(u8, &serial, 0)) serial[serial.len - 1] = 1;

        const certificate_der = try buildP256Certificate(allocator, key_pair, &serial);
        return .{
            .certificate_der = certificate_der,
            .secret_key = key_pair.secret_key.toBytes(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EphemeralP256Identity) void {
        std.crypto.secureZero(u8, &self.secret_key);
        self.allocator.free(self.certificate_der);
        self.certificate_der = &.{};
    }
};

fn appendLength(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, len: usize) Error.ZquicError!void {
    if (len < 128) {
        out.append(allocator, @intCast(len)) catch return Error.ZquicError.OutOfMemory;
    } else if (len <= std.math.maxInt(u8)) {
        out.appendSlice(allocator, &.{ 0x81, @intCast(len) }) catch return Error.ZquicError.OutOfMemory;
    } else if (len <= std.math.maxInt(u16)) {
        out.appendSlice(allocator, &.{ 0x82, @truncate(len >> 8), @truncate(len) }) catch return Error.ZquicError.OutOfMemory;
    } else {
        return Error.ZquicError.PacketTooLarge;
    }
}

fn appendTlv(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    tag: u8,
    value: []const u8,
) Error.ZquicError!void {
    out.append(allocator, tag) catch return Error.ZquicError.OutOfMemory;
    try appendLength(out, allocator, value.len);
    out.appendSlice(allocator, value) catch return Error.ZquicError.OutOfMemory;
}

fn wrapOwned(
    allocator: std.mem.Allocator,
    tag: u8,
    value: []const u8,
) Error.ZquicError![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendTlv(&out, allocator, tag, value);
    return out.toOwnedSlice(allocator) catch Error.ZquicError.OutOfMemory;
}

fn buildName(allocator: std.mem.Allocator) Error.ZquicError![]u8 {
    var attribute: std.ArrayListUnmanaged(u8) = .empty;
    defer attribute.deinit(allocator);
    try appendTlv(&attribute, allocator, 0x06, &.{ 0x55, 0x04, 0x03 });
    try appendTlv(&attribute, allocator, 0x0c, "zquic interop");

    const sequence = try wrapOwned(allocator, 0x30, attribute.items);
    defer allocator.free(sequence);
    const set = try wrapOwned(allocator, 0x31, sequence);
    defer allocator.free(set);
    return wrapOwned(allocator, 0x30, set);
}

fn buildSubjectPublicKeyInfo(
    allocator: std.mem.Allocator,
    public_key: *const [Ed25519.PublicKey.encoded_length]u8,
) Error.ZquicError![]u8 {
    const algorithm_identifier = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    var content: std.ArrayListUnmanaged(u8) = .empty;
    defer content.deinit(allocator);
    content.appendSlice(allocator, &algorithm_identifier) catch return Error.ZquicError.OutOfMemory;

    var bit_string: [1 + Ed25519.PublicKey.encoded_length]u8 = undefined;
    bit_string[0] = 0;
    @memcpy(bit_string[1..], public_key);
    try appendTlv(&content, allocator, 0x03, &bit_string);
    return wrapOwned(allocator, 0x30, content.items);
}

fn buildP256SubjectPublicKeyInfo(
    allocator: std.mem.Allocator,
    public_key: EcdsaP256.PublicKey,
) Error.ZquicError![]u8 {
    // id-ecPublicKey with the prime256v1 named-curve parameter.
    const algorithm_identifier = [_]u8{
        0x30, 0x13,
        0x06, 0x07,
        0x2a, 0x86,
        0x48, 0xce,
        0x3d, 0x02,
        0x01, 0x06,
        0x08, 0x2a,
        0x86, 0x48,
        0xce, 0x3d,
        0x03, 0x01,
        0x07,
    };
    var content: std.ArrayListUnmanaged(u8) = .empty;
    defer content.deinit(allocator);
    content.appendSlice(allocator, &algorithm_identifier) catch return Error.ZquicError.OutOfMemory;

    const sec1 = public_key.toUncompressedSec1();
    var bit_string: [1 + EcdsaP256.PublicKey.uncompressed_sec1_encoded_length]u8 = undefined;
    bit_string[0] = 0;
    @memcpy(bit_string[1..], &sec1);
    try appendTlv(&content, allocator, 0x03, &bit_string);
    return wrapOwned(allocator, 0x30, content.items);
}

fn buildCertificate(
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    serial: *const [16]u8,
) Error.ZquicError![]u8 {
    const algorithm_identifier = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    const version_v3 = [_]u8{ 0xa0, 0x03, 0x02, 0x01, 0x02 };
    const validity = [_]u8{
        0x30, 0x1e,
        0x17, 0x0d,
        '2',  '4',
        '0',  '1',
        '0',  '1',
        '0',  '0',
        '0',  '0',
        '0',  '0',
        'Z',  0x17,
        0x0d, '4',
        '9',  '1',
        '2',  '3',
        '1',  '2',
        '3',  '5',
        '9',  '5',
        '9',  'Z',
    };

    const name = try buildName(allocator);
    defer allocator.free(name);
    const public_key = key_pair.public_key.toBytes();
    const spki = try buildSubjectPublicKeyInfo(allocator, &public_key);
    defer allocator.free(spki);

    var tbs_content: std.ArrayListUnmanaged(u8) = .empty;
    defer tbs_content.deinit(allocator);
    tbs_content.appendSlice(allocator, &version_v3) catch return Error.ZquicError.OutOfMemory;
    try appendTlv(&tbs_content, allocator, 0x02, serial);
    tbs_content.appendSlice(allocator, &algorithm_identifier) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, name) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, &validity) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, name) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, spki) catch return Error.ZquicError.OutOfMemory;

    const tbs = try wrapOwned(allocator, 0x30, tbs_content.items);
    defer allocator.free(tbs);
    const signature = key_pair.sign(tbs, null) catch return Error.ZquicError.CryptoError;
    const signature_bytes = signature.toBytes();

    var certificate_content: std.ArrayListUnmanaged(u8) = .empty;
    defer certificate_content.deinit(allocator);
    certificate_content.appendSlice(allocator, tbs) catch return Error.ZquicError.OutOfMemory;
    certificate_content.appendSlice(allocator, &algorithm_identifier) catch return Error.ZquicError.OutOfMemory;
    var signature_bit_string: [1 + Ed25519.Signature.encoded_length]u8 = undefined;
    signature_bit_string[0] = 0;
    @memcpy(signature_bit_string[1..], &signature_bytes);
    try appendTlv(&certificate_content, allocator, 0x03, &signature_bit_string);
    return wrapOwned(allocator, 0x30, certificate_content.items);
}

fn buildP256Certificate(
    allocator: std.mem.Allocator,
    key_pair: EcdsaP256.KeyPair,
    serial: *const [16]u8,
) Error.ZquicError![]u8 {
    // ecdsa-with-SHA256; RFC 5480 requires absent AlgorithmIdentifier params.
    const signature_algorithm = [_]u8{ 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
    const version_v3 = [_]u8{ 0xa0, 0x03, 0x02, 0x01, 0x02 };
    const validity = [_]u8{
        0x30, 0x1e,
        0x17, 0x0d,
        '2',  '4',
        '0',  '1',
        '0',  '1',
        '0',  '0',
        '0',  '0',
        '0',  '0',
        'Z',  0x17,
        0x0d, '4',
        '9',  '1',
        '2',  '3',
        '1',  '2',
        '3',  '5',
        '9',  '5',
        '9',  'Z',
    };

    const name = try buildName(allocator);
    defer allocator.free(name);
    const spki = try buildP256SubjectPublicKeyInfo(allocator, key_pair.public_key);
    defer allocator.free(spki);

    var tbs_content: std.ArrayListUnmanaged(u8) = .empty;
    defer tbs_content.deinit(allocator);
    tbs_content.appendSlice(allocator, &version_v3) catch return Error.ZquicError.OutOfMemory;
    try appendTlv(&tbs_content, allocator, 0x02, serial);
    tbs_content.appendSlice(allocator, &signature_algorithm) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, name) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, &validity) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, name) catch return Error.ZquicError.OutOfMemory;
    tbs_content.appendSlice(allocator, spki) catch return Error.ZquicError.OutOfMemory;

    const tbs = try wrapOwned(allocator, 0x30, tbs_content.items);
    defer allocator.free(tbs);
    var noise: [EcdsaP256.noise_length]u8 = undefined;
    zcrypto.rand.fill(&noise);
    defer std.crypto.secureZero(u8, &noise);
    const signature = key_pair.sign(tbs, noise) catch return Error.ZquicError.CryptoError;
    var signature_der_storage: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const signature_der = signature.toDer(&signature_der_storage);

    var certificate_content: std.ArrayListUnmanaged(u8) = .empty;
    defer certificate_content.deinit(allocator);
    certificate_content.appendSlice(allocator, tbs) catch return Error.ZquicError.OutOfMemory;
    certificate_content.appendSlice(allocator, &signature_algorithm) catch return Error.ZquicError.OutOfMemory;
    var signature_bit_string: [1 + EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    signature_bit_string[0] = 0;
    @memcpy(signature_bit_string[1..][0..signature_der.len], signature_der);
    try appendTlv(&certificate_content, allocator, 0x03, signature_bit_string[0 .. 1 + signature_der.len]);
    return wrapOwned(allocator, 0x30, certificate_content.items);
}

test "ephemeral Ed25519 certificate parses and verifies" {
    var identity = try EphemeralIdentity.generate(std.testing.allocator);
    defer identity.deinit();

    const parsed = try std.crypto.Certificate.parse(.{ .buffer = identity.certificate_der, .index = 0 });
    try std.testing.expectEqual(std.crypto.Certificate.Algorithm.curveEd25519, parsed.signature_algorithm);
    try std.testing.expect(parsed.validity.not_after > parsed.validity.not_before);
}

test "ephemeral ECDSA P-256 certificate parses and verifies" {
    var identity = try EphemeralP256Identity.generate(std.testing.allocator);
    defer identity.deinit();

    const certificate: std.crypto.Certificate = .{ .buffer = identity.certificate_der, .index = 0 };
    const parsed = try std.crypto.Certificate.parse(certificate);
    try std.testing.expectEqual(std.crypto.Certificate.Algorithm.ecdsa_with_SHA256, parsed.signature_algorithm);
    try std.crypto.Certificate.verify(certificate, certificate, 1_735_689_600);
}

fn generateAndDestroy(allocator: std.mem.Allocator) !void {
    var identity = try EphemeralIdentity.generate(allocator);
    defer identity.deinit();
}

test "ephemeral identity cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, generateAndDestroy, .{});
}

fn generateAndDestroyP256(allocator: std.mem.Allocator) !void {
    var identity = try EphemeralP256Identity.generate(allocator);
    defer identity.deinit();
}

test "ephemeral P-256 identity cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, generateAndDestroyP256, .{});
}
