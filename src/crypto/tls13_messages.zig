//! Strict TLS 1.3 ClientHello parsing and ServerHello construction for QUIC.
//!
//! Scope is deliberately narrow, matching the single supported profile:
//! TLS 1.3, `TLS_AES_128_GCM_SHA256`, X25519 key share, and a mandatory
//! `quic_transport_parameters` extension. Anything else is rejected rather than
//! coerced, so a peer that negotiates something we cannot actually do fails
//! loudly at parse time instead of silently later.
//!
//! This module is a leaf: it imports only `std` and the project error set.
//!
//! Both functions operate on the handshake message *body* — the caller has
//! already stripped the 4-byte `msg_type` + `uint24 length` handshake header.

const std = @import("std");
const Error = @import("../utils/error.zig");

pub const legacy_version_tls12: u16 = 0x0303;
pub const version_tls13: u16 = 0x0304;

pub const cipher_suite_aes_128_gcm_sha256: u16 = 0x1301;
pub const named_group_x25519: u16 = 0x001d;
pub const signature_scheme_ecdsa_secp256r1_sha256: u16 = 0x0403;
pub const signature_scheme_ed25519: u16 = 0x0807;

pub const ext_server_name: u16 = 0;
pub const ext_supported_groups: u16 = 10;
pub const ext_signature_algorithms: u16 = 13;
pub const ext_alpn: u16 = 16;
pub const ext_supported_versions: u16 = 43;
pub const ext_key_share: u16 = 51;
pub const ext_quic_transport_parameters: u16 = 0x0039;

pub const random_length = 32;
pub const x25519_key_length = 32;
pub const max_legacy_session_id_length = 32;

/// Upper bound on a `buildServerHello` body: every field this builder emits is
/// fixed-size except the echoed session id, which `buildServerHello` itself caps
/// at `max_legacy_session_id_length`. Callers size stack buffers from this.
pub const max_server_hello_body_len =
    2 + // legacy_version
    random_length +
    1 + max_legacy_session_id_length +
    2 + // cipher_suite
    1 + // legacy_compression_method
    2 + // extensions length
    (2 + 2 + 2) + // supported_versions
    (2 + 2 + 2 + 2 + x25519_key_length); // key_share

/// Big-endian cursor over a peer-controlled buffer.
///
/// Every read is bounds-checked and returns `ProtocolViolation` on truncation,
/// so no caller needs to pre-validate lengths.
const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Cursor) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *Cursor, len: usize) Error.ZquicError![]const u8 {
        if (self.remaining() < len) return Error.ZquicError.ProtocolViolation;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }

    fn readU8(self: *Cursor) Error.ZquicError!u8 {
        const b = try self.take(1);
        return b[0];
    }

    fn readU16(self: *Cursor) Error.ZquicError!u16 {
        const b = try self.take(2);
        return std.mem.readInt(u16, b[0..2], .big);
    }

    /// Read an `opaque<0..255>` vector.
    fn readVec8(self: *Cursor) Error.ZquicError![]const u8 {
        const len = try self.readU8();
        return self.take(len);
    }

    /// Read an `opaque<0..65535>` vector.
    fn readVec16(self: *Cursor) Error.ZquicError![]const u8 {
        const len = try self.readU16();
        return self.take(len);
    }

    fn expectEnd(self: *const Cursor) Error.ZquicError!void {
        if (self.remaining() != 0) return Error.ZquicError.ProtocolViolation;
    }
};

/// Allocation-free duplicate detection for TLS 16-bit identifiers.
const IdentifierSet = struct {
    words: [std.math.maxInt(u16) / 64 + 1]u64 = @splat(0),

    fn mark(self: *IdentifierSet, identifier: u16) Error.ZquicError!void {
        const word_index: usize = @as(usize, identifier) / 64;
        const bit_index: u6 = @intCast(identifier % 64);
        const mask = @as(u64, 1) << bit_index;
        if (self.words[word_index] & mask != 0) return Error.ZquicError.ProtocolViolation;
        self.words[word_index] |= mask;
    }
};

fn validateKeyShareGroups(
    supported_groups: []const u8,
    key_share_entries: []const u8,
) Error.ZquicError!void {
    var groups = Cursor{ .bytes = supported_groups };
    var shares = Cursor{ .bytes = key_share_entries };
    while (shares.remaining() > 0) {
        const share_group = try shares.readU16();
        const key_exchange = try shares.readVec16();
        if (key_exchange.len == 0) return Error.ZquicError.ProtocolViolation;

        var found = false;
        while (groups.remaining() > 0) {
            if (try groups.readU16() == share_group) {
                found = true;
                break;
            }
        }
        if (!found) return Error.ZquicError.ProtocolViolation;
    }
}

/// The subset of a ClientHello this implementation acts on.
///
/// HARD RULE: `legacy_session_id`, `quic_transport_parameters`, `alpn_list`, and
/// `server_name` are **borrowed** from the caller's message buffer. In the TLS
/// context that buffer is `quic_crypto_buffer.items`, which is compacted as soon
/// as the message is consumed. A `ParsedClientHello` must never be stored on a
/// long-lived struct — copy out anything that needs to outlive the call.
pub const ParsedClientHello = struct {
    random: [random_length]u8,
    legacy_session_id: []const u8,
    x25519_key_share: [x25519_key_length]u8,
    quic_transport_parameters: []const u8,
    /// Raw `ProtocolNameList` body (the inner list, without its 2-byte length).
    alpn_list: ?[]const u8,
    server_name: ?[]const u8,
    offers_ecdsa_secp256r1_sha256: bool,
    offers_ed25519: bool,

    /// Pick the first server preference the client also offered.
    ///
    /// Returns a slice borrowed from the same message buffer as `alpn_list`.
    pub fn selectAlpn(self: *const ParsedClientHello, preferences: []const []const u8) ?[]const u8 {
        const list = self.alpn_list orelse return null;
        for (preferences) |preference| {
            var cursor = Cursor{ .bytes = list };
            while (cursor.remaining() > 0) {
                const name = cursor.readVec8() catch return null;
                if (std.mem.eql(u8, name, preference)) return name;
            }
        }
        return null;
    }
};

pub const ClientHelloStage = enum {
    structure,
    cipher_suite,
    supported_versions,
    supported_groups,
    signature_algorithms,
    key_share,
    transport_parameters,
    key_share_consistency,
    alpn,
    transport_decode,
    transport_validate,
    accepted,
};

/// Parse and validate a ClientHello body against the single supported profile.
///
/// Rejects: truncation, trailing bytes at any vector boundary, duplicate
/// extensions, a compression method other than `null`, absence of TLS 1.3 in
/// `supported_versions`, absence of `TLS_AES_128_GCM_SHA256`, a missing or
/// malformed X25519 key share, and a missing `quic_transport_parameters`.
///
/// Nothing is allocated and nothing is mutated; the result borrows from `body`.
pub fn parseClientHello(body: []const u8) Error.ZquicError!ParsedClientHello {
    var stage: ClientHelloStage = .structure;
    return parseClientHelloWithStage(body, &stage);
}

pub fn parseClientHelloWithStage(body: []const u8, stage: *ClientHelloStage) Error.ZquicError!ParsedClientHello {
    stage.* = .structure;
    var cursor = Cursor{ .bytes = body };

    // legacy_version is required to be TLS 1.2 on the wire; real version
    // negotiation happens in supported_versions.
    if (try cursor.readU16() != legacy_version_tls12) return Error.ZquicError.ProtocolViolation;

    const random = try cursor.take(random_length);

    const legacy_session_id = try cursor.readVec8();
    if (legacy_session_id.len > max_legacy_session_id_length) return Error.ZquicError.ProtocolViolation;

    stage.* = .cipher_suite;
    const cipher_suites = try cursor.readVec16();
    if (cipher_suites.len == 0 or cipher_suites.len % 2 != 0) return Error.ZquicError.ProtocolViolation;
    var offers_supported_suite = false;
    var suite_index: usize = 0;
    while (suite_index < cipher_suites.len) : (suite_index += 2) {
        const suite = std.mem.readInt(u16, cipher_suites[suite_index..][0..2], .big);
        if (suite == cipher_suite_aes_128_gcm_sha256) offers_supported_suite = true;
    }
    if (!offers_supported_suite) return Error.ZquicError.ProtocolViolation;

    stage.* = .structure;
    const compression_methods = try cursor.readVec8();
    if (compression_methods.len != 1 or compression_methods[0] != 0) return Error.ZquicError.ProtocolViolation;

    // RFC 8446: a TLS 1.3 ClientHello always carries extensions.
    const extensions = try cursor.readVec16();
    try cursor.expectEnd();

    var seen_extensions = IdentifierSet{};
    var seen_supported_versions = false;
    var seen_supported_groups = false;
    var seen_signature_algorithms = false;
    var seen_key_share = false;
    var seen_quic_transport_parameters = false;

    var offers_tls13 = false;
    var offers_x25519 = false;
    var offers_ed25519 = false;
    var offers_ecdsa_secp256r1_sha256 = false;
    var supported_groups: ?[]const u8 = null;
    var key_share_entries: ?[]const u8 = null;
    var x25519_key_share: ?[x25519_key_length]u8 = null;
    var quic_transport_parameters: ?[]const u8 = null;
    var alpn_list: ?[]const u8 = null;
    var server_name: ?[]const u8 = null;

    var ext_cursor = Cursor{ .bytes = extensions };
    while (ext_cursor.remaining() > 0) {
        const ext_type = try ext_cursor.readU16();
        const ext_data = try ext_cursor.readVec16();
        try seen_extensions.mark(ext_type);

        switch (ext_type) {
            ext_supported_versions => {
                stage.* = .supported_versions;
                seen_supported_versions = true;

                var inner = Cursor{ .bytes = ext_data };
                const versions = try inner.readVec8();
                try inner.expectEnd();
                if (versions.len == 0 or versions.len % 2 != 0) return Error.ZquicError.ProtocolViolation;
                var version_index: usize = 0;
                while (version_index < versions.len) : (version_index += 2) {
                    if (std.mem.readInt(u16, versions[version_index..][0..2], .big) == version_tls13) {
                        offers_tls13 = true;
                    }
                }
            },
            ext_supported_groups => {
                stage.* = .supported_groups;
                seen_supported_groups = true;

                var inner = Cursor{ .bytes = ext_data };
                const groups = try inner.readVec16();
                try inner.expectEnd();
                if (groups.len == 0 or groups.len % 2 != 0) return Error.ZquicError.ProtocolViolation;

                var seen_groups = IdentifierSet{};
                var group_cursor = Cursor{ .bytes = groups };
                while (group_cursor.remaining() > 0) {
                    const group = try group_cursor.readU16();
                    try seen_groups.mark(group);
                    if (group == named_group_x25519) offers_x25519 = true;
                }
                supported_groups = groups;
            },
            ext_signature_algorithms => {
                stage.* = .signature_algorithms;
                seen_signature_algorithms = true;

                var inner = Cursor{ .bytes = ext_data };
                const schemes = try inner.readVec16();
                try inner.expectEnd();
                if (schemes.len == 0 or schemes.len % 2 != 0) return Error.ZquicError.ProtocolViolation;

                var scheme_cursor = Cursor{ .bytes = schemes };
                while (scheme_cursor.remaining() > 0) {
                    switch (try scheme_cursor.readU16()) {
                        signature_scheme_ecdsa_secp256r1_sha256 => offers_ecdsa_secp256r1_sha256 = true,
                        signature_scheme_ed25519 => offers_ed25519 = true,
                        else => {},
                    }
                }
            },
            ext_key_share => {
                stage.* = .key_share;
                seen_key_share = true;

                var inner = Cursor{ .bytes = ext_data };
                const shares = try inner.readVec16();
                try inner.expectEnd();
                key_share_entries = shares;

                var seen_share_groups = IdentifierSet{};
                var share_cursor = Cursor{ .bytes = shares };
                while (share_cursor.remaining() > 0) {
                    const group = try share_cursor.readU16();
                    const key_exchange = try share_cursor.readVec16();
                    try seen_share_groups.mark(group);
                    if (key_exchange.len == 0) return Error.ZquicError.ProtocolViolation;
                    if (group != named_group_x25519) continue;
                    if (key_exchange.len != x25519_key_length) return Error.ZquicError.ProtocolViolation;
                    x25519_key_share = key_exchange[0..x25519_key_length].*;
                }
            },
            ext_quic_transport_parameters => {
                stage.* = .transport_parameters;
                seen_quic_transport_parameters = true;
                quic_transport_parameters = ext_data;
            },
            ext_alpn => {
                var inner = Cursor{ .bytes = ext_data };
                const list = try inner.readVec16();
                try inner.expectEnd();
                if (list.len == 0) return Error.ZquicError.ProtocolViolation;

                // Validate the whole list up front so `selectAlpn` cannot walk
                // off a malformed entry later.
                var name_cursor = Cursor{ .bytes = list };
                while (name_cursor.remaining() > 0) {
                    const name = try name_cursor.readVec8();
                    if (name.len == 0) return Error.ZquicError.ProtocolViolation;
                }
                alpn_list = list;
            },
            ext_server_name => {
                var inner = Cursor{ .bytes = ext_data };
                const list = try inner.readVec16();
                try inner.expectEnd();
                if (list.len == 0) return Error.ZquicError.ProtocolViolation;

                var name_cursor = Cursor{ .bytes = list };
                while (name_cursor.remaining() > 0) {
                    const name_type = try name_cursor.readU8();
                    const name = try name_cursor.readVec16();
                    if (name.len == 0) return Error.ZquicError.ProtocolViolation;
                    if (name_type == 0) {
                        if (server_name != null) return Error.ZquicError.ProtocolViolation;
                        server_name = name;
                    }
                }
            },
            else => {},
        }
        stage.* = .structure;
    }

    stage.* = .supported_versions;
    if (!seen_supported_versions or !offers_tls13) return Error.ZquicError.ProtocolViolation;
    stage.* = .supported_groups;
    if (!seen_supported_groups or !offers_x25519) return Error.ZquicError.ProtocolViolation;
    stage.* = .signature_algorithms;
    if (!seen_signature_algorithms or !(offers_ed25519 or offers_ecdsa_secp256r1_sha256)) {
        return Error.ZquicError.ProtocolViolation;
    }
    stage.* = .key_share;
    if (!seen_key_share) return Error.ZquicError.ProtocolViolation;
    stage.* = .transport_parameters;
    if (!seen_quic_transport_parameters) return Error.ZquicError.ProtocolViolation;
    stage.* = .key_share_consistency;
    try validateKeyShareGroups(supported_groups.?, key_share_entries.?);

    stage.* = .accepted;
    return ParsedClientHello{
        .random = random[0..random_length].*,
        .legacy_session_id = legacy_session_id,
        .x25519_key_share = x25519_key_share orelse return Error.ZquicError.ProtocolViolation,
        .quic_transport_parameters = quic_transport_parameters.?,
        .alpn_list = alpn_list,
        .server_name = server_name,
        .offers_ecdsa_secp256r1_sha256 = offers_ecdsa_secp256r1_sha256,
        .offers_ed25519 = offers_ed25519,
    };
}

/// Serialise a ServerHello body into `out`, returning the written slice.
///
/// The caller supplies the server random and X25519 public key so this stays
/// deterministic and unit-testable; it never touches an RNG itself.
pub fn buildServerHello(
    out: []u8,
    server_random: *const [random_length]u8,
    legacy_session_id_echo: []const u8,
    server_x25519_public: *const [x25519_key_length]u8,
) Error.ZquicError![]u8 {
    if (legacy_session_id_echo.len > max_legacy_session_id_length) return Error.ZquicError.ProtocolViolation;

    const extensions_len =
        2 + 2 + 2 + // supported_versions: type, length, selected_version
        2 + 2 + 2 + 2 + x25519_key_length; // key_share: type, length, group, key length, key
    const total =
        2 + // legacy_version
        random_length +
        1 + legacy_session_id_echo.len +
        2 + // cipher_suite
        1 + // legacy_compression_method
        2 + extensions_len;

    if (out.len < total) return Error.ZquicError.PacketTooLarge;

    var pos: usize = 0;

    std.mem.writeInt(u16, out[pos..][0..2], legacy_version_tls12, .big);
    pos += 2;

    @memcpy(out[pos..][0..random_length], server_random);
    pos += random_length;

    out[pos] = @intCast(legacy_session_id_echo.len);
    pos += 1;
    @memcpy(out[pos..][0..legacy_session_id_echo.len], legacy_session_id_echo);
    pos += legacy_session_id_echo.len;

    std.mem.writeInt(u16, out[pos..][0..2], cipher_suite_aes_128_gcm_sha256, .big);
    pos += 2;

    out[pos] = 0; // legacy_compression_method = null
    pos += 1;

    std.mem.writeInt(u16, out[pos..][0..2], @intCast(extensions_len), .big);
    pos += 2;

    // supported_versions (ServerHello form carries the selected version only).
    std.mem.writeInt(u16, out[pos..][0..2], ext_supported_versions, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], 2, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], version_tls13, .big);
    pos += 2;

    // key_share (ServerHello form carries a single KeyShareEntry).
    std.mem.writeInt(u16, out[pos..][0..2], ext_key_share, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], 2 + 2 + x25519_key_length, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], named_group_x25519, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], x25519_key_length, .big);
    pos += 2;
    @memcpy(out[pos..][0..x25519_key_length], server_x25519_public);
    pos += x25519_key_length;

    std.debug.assert(pos == total);
    return out[0..total];
}

/// Knobs for `buildTestClientHello`.
///
/// Defaults produce a ClientHello this parser accepts; each field exists so a
/// rejection test can break exactly one thing.
pub const TestClientHelloOptions = struct {
    legacy_version: u16 = legacy_version_tls12,
    random: [random_length]u8 = @splat(0xa1),
    legacy_session_id_len: u8 = 32,
    cipher_suites: []const u16 = &.{cipher_suite_aes_128_gcm_sha256},
    compression_methods: []const u8 = &.{0},
    include_supported_versions: bool = true,
    supported_versions: []const u16 = &.{version_tls13},
    duplicate_supported_versions: bool = false,
    include_supported_groups: bool = true,
    supported_groups: []const u16 = &.{named_group_x25519},
    duplicate_supported_groups: bool = false,
    include_signature_algorithms: bool = true,
    signature_algorithms: []const u16 = &.{signature_scheme_ed25519},
    include_key_share: bool = true,
    key_share_group: u16 = named_group_x25519,
    key_share_len: u16 = x25519_key_length,
    /// Exact key-share bytes to emit. When null the share is filled with a
    /// recognisable constant, which is enough for parser tests. End-to-end
    /// tests supply a real X25519 public key so the exchange can be completed.
    key_share_bytes: ?[]const u8 = null,
    duplicate_key_share: bool = false,
    include_quic_transport_parameters: bool = true,
    /// max_idle_timeout (id 0x01), length 1, varint 30. Minimal but decodable;
    /// every other transport parameter falls back to its default, which passes
    /// `TransportParameters.validate()`.
    quic_transport_parameters: []const u8 = &.{ 0x01, 0x01, 0x1e },
    duplicate_quic_transport_parameters: bool = false,
    alpn_protocols: ?[]const []const u8 = null,
    duplicate_unknown_extension: bool = false,
    trailing_bytes: usize = 0,
};

/// Build a ClientHello body into `out` for tests.
///
/// This lives beside the parser (rather than in a test file) so every call site
/// that needs a well-formed ClientHello shares one definition of "well formed".
pub fn buildTestClientHello(out: []u8, opts: TestClientHelloOptions) Error.ZquicError![]u8 {
    var pos: usize = 0;

    const put = struct {
        fn u8v(buf: []u8, p: *usize, value: u8) Error.ZquicError!void {
            if (buf.len < p.* + 1) return Error.ZquicError.PacketTooLarge;
            buf[p.*] = value;
            p.* += 1;
        }
        fn u16v(buf: []u8, p: *usize, value: u16) Error.ZquicError!void {
            if (buf.len < p.* + 2) return Error.ZquicError.PacketTooLarge;
            std.mem.writeInt(u16, buf[p.*..][0..2], value, .big);
            p.* += 2;
        }
        fn bytes(buf: []u8, p: *usize, value: []const u8) Error.ZquicError!void {
            if (buf.len < p.* + value.len) return Error.ZquicError.PacketTooLarge;
            @memcpy(buf[p.*..][0..value.len], value);
            p.* += value.len;
        }
    };

    try put.u16v(out, &pos, opts.legacy_version);
    try put.bytes(out, &pos, &opts.random);

    try put.u8v(out, &pos, opts.legacy_session_id_len);
    var session_index: usize = 0;
    while (session_index < opts.legacy_session_id_len) : (session_index += 1) {
        try put.u8v(out, &pos, @intCast(session_index));
    }

    try put.u16v(out, &pos, @intCast(opts.cipher_suites.len * 2));
    for (opts.cipher_suites) |suite| try put.u16v(out, &pos, suite);

    try put.u8v(out, &pos, @intCast(opts.compression_methods.len));
    try put.bytes(out, &pos, opts.compression_methods);

    // Reserve the extensions-block length and backfill once the body is known.
    const extensions_len_pos = pos;
    try put.u16v(out, &pos, 0);
    const extensions_start = pos;

    const writeSupportedVersions = struct {
        fn call(buf: []u8, p: *usize, versions: []const u16) Error.ZquicError!void {
            try put.u16v(buf, p, ext_supported_versions);
            try put.u16v(buf, p, @intCast(1 + versions.len * 2));
            try put.u8v(buf, p, @intCast(versions.len * 2));
            for (versions) |version| try put.u16v(buf, p, version);
        }
    };

    const writeKeyShare = struct {
        fn call(buf: []u8, p: *usize, group: u16, key_len: u16, key_bytes: ?[]const u8) Error.ZquicError!void {
            if (key_bytes) |bytes| {
                if (bytes.len != key_len) return Error.ZquicError.InvalidArgument;
            }
            try put.u16v(buf, p, ext_key_share);
            try put.u16v(buf, p, @intCast(2 + 2 + 2 + key_len));
            try put.u16v(buf, p, @intCast(2 + 2 + key_len));
            try put.u16v(buf, p, group);
            try put.u16v(buf, p, key_len);
            if (key_bytes) |bytes| {
                try put.bytes(buf, p, bytes);
            } else {
                var key_index: u16 = 0;
                while (key_index < key_len) : (key_index += 1) try put.u8v(buf, p, 0x42);
            }
        }
    };

    const writeSupportedGroups = struct {
        fn call(buf: []u8, p: *usize, groups: []const u16) Error.ZquicError!void {
            try put.u16v(buf, p, ext_supported_groups);
            try put.u16v(buf, p, @intCast(2 + groups.len * 2));
            try put.u16v(buf, p, @intCast(groups.len * 2));
            for (groups) |group| try put.u16v(buf, p, group);
        }
    };

    const writeSignatureAlgorithms = struct {
        fn call(buf: []u8, p: *usize, schemes: []const u16) Error.ZquicError!void {
            try put.u16v(buf, p, ext_signature_algorithms);
            try put.u16v(buf, p, @intCast(2 + schemes.len * 2));
            try put.u16v(buf, p, @intCast(schemes.len * 2));
            for (schemes) |scheme| try put.u16v(buf, p, scheme);
        }
    };

    const writeTransportParameters = struct {
        fn call(buf: []u8, p: *usize, params: []const u8) Error.ZquicError!void {
            try put.u16v(buf, p, ext_quic_transport_parameters);
            try put.u16v(buf, p, @intCast(params.len));
            try put.bytes(buf, p, params);
        }
    };

    if (opts.include_supported_versions) {
        try writeSupportedVersions.call(out, &pos, opts.supported_versions);
        if (opts.duplicate_supported_versions) try writeSupportedVersions.call(out, &pos, opts.supported_versions);
    }

    if (opts.include_supported_groups) {
        try writeSupportedGroups.call(out, &pos, opts.supported_groups);
        if (opts.duplicate_supported_groups) try writeSupportedGroups.call(out, &pos, opts.supported_groups);
    }

    if (opts.include_signature_algorithms) {
        try writeSignatureAlgorithms.call(out, &pos, opts.signature_algorithms);
    }

    if (opts.include_key_share) {
        try writeKeyShare.call(out, &pos, opts.key_share_group, opts.key_share_len, opts.key_share_bytes);
        if (opts.duplicate_key_share) {
            try writeKeyShare.call(out, &pos, opts.key_share_group, opts.key_share_len, opts.key_share_bytes);
        }
    }

    if (opts.alpn_protocols) |protocols| {
        var list_len: usize = 0;
        for (protocols) |protocol| list_len += 1 + protocol.len;
        try put.u16v(out, &pos, ext_alpn);
        try put.u16v(out, &pos, @intCast(2 + list_len));
        try put.u16v(out, &pos, @intCast(list_len));
        for (protocols) |protocol| {
            try put.u8v(out, &pos, @intCast(protocol.len));
            try put.bytes(out, &pos, protocol);
        }
    }

    if (opts.include_quic_transport_parameters) {
        try writeTransportParameters.call(out, &pos, opts.quic_transport_parameters);
        if (opts.duplicate_quic_transport_parameters) {
            try writeTransportParameters.call(out, &pos, opts.quic_transport_parameters);
        }
    }

    if (opts.duplicate_unknown_extension) {
        try put.u16v(out, &pos, 0xfafa);
        try put.u16v(out, &pos, 0);
        try put.u16v(out, &pos, 0xfafa);
        try put.u16v(out, &pos, 0);
    }

    std.mem.writeInt(u16, out[extensions_len_pos..][0..2], @intCast(pos - extensions_start), .big);

    var trailing_index: usize = 0;
    while (trailing_index < opts.trailing_bytes) : (trailing_index += 1) {
        try put.u8v(out, &pos, 0xff);
    }

    return out[0..pos];
}

const testing = std.testing;

/// Independent ServerHello reader used only by tests, so round-trip coverage
/// does not simply replay `buildServerHello`'s own field order.
pub const TestServerHello = struct {
    legacy_version: u16,
    random: [random_length]u8,
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    selected_version: u16,
    key_share_group: u16,
    key_share: []const u8,
};

pub fn parseServerHelloForTest(body: []const u8) Error.ZquicError!TestServerHello {
    var cursor = Cursor{ .bytes = body };
    const legacy_version = try cursor.readU16();
    const random = try cursor.take(random_length);
    const session_id = try cursor.readVec8();
    const cipher_suite = try cursor.readU16();
    if (try cursor.readU8() != 0) return Error.ZquicError.ProtocolViolation;
    const extensions = try cursor.readVec16();
    try cursor.expectEnd();

    var selected_version: ?u16 = null;
    var key_share_group: ?u16 = null;
    var key_share: ?[]const u8 = null;

    var ext_cursor = Cursor{ .bytes = extensions };
    while (ext_cursor.remaining() > 0) {
        const ext_type = try ext_cursor.readU16();
        const ext_data = try ext_cursor.readVec16();
        switch (ext_type) {
            ext_supported_versions => {
                if (ext_data.len != 2) return Error.ZquicError.ProtocolViolation;
                selected_version = std.mem.readInt(u16, ext_data[0..2], .big);
            },
            ext_key_share => {
                var inner = Cursor{ .bytes = ext_data };
                key_share_group = try inner.readU16();
                key_share = try inner.readVec16();
                try inner.expectEnd();
            },
            else => return Error.ZquicError.ProtocolViolation,
        }
    }

    return TestServerHello{
        .legacy_version = legacy_version,
        .random = random[0..random_length].*,
        .legacy_session_id_echo = session_id,
        .cipher_suite = cipher_suite,
        .selected_version = selected_version orelse return Error.ZquicError.ProtocolViolation,
        .key_share_group = key_share_group orelse return Error.ZquicError.ProtocolViolation,
        .key_share = key_share orelse return Error.ZquicError.ProtocolViolation,
    };
}

test "parseClientHello accepts the supported profile" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{});

    const parsed = try parseClientHello(hello);
    const expected_share: [x25519_key_length]u8 = @splat(0x42);
    try testing.expectEqual(@as(usize, 32), parsed.legacy_session_id.len);
    try testing.expectEqualSlices(u8, &expected_share, &parsed.x25519_key_share);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 0x1e }, parsed.quic_transport_parameters);
    try testing.expect(parsed.alpn_list == null);
}

test "parseClientHello selects ALPN by server preference" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .alpn_protocols = &.{ "hq-interop", "h3" } });

    const parsed = try parseClientHello(hello);
    const selected = parsed.selectAlpn(&.{ "h3", "hq-interop" });
    try testing.expectEqualStrings("h3", selected.?);
    try testing.expect(parsed.selectAlpn(&.{"nope"}) == null);
}

test "parseClientHello rejects a non-TLS1.2 legacy version" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .legacy_version = 0x0304 });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects an oversized legacy session id" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .legacy_session_id_len = 33 });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects an unsupported cipher suite list" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .cipher_suites = &.{ 0x1302, 0x1303 } });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects an empty cipher suite list" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .cipher_suites = &.{} });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects a non-null compression method" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .compression_methods = &.{1} });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects trailing bytes after the extensions block" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .trailing_bytes = 3 });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "parseClientHello rejects truncation at every prefix" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{});

    var truncate_at: usize = 0;
    while (truncate_at < hello.len) : (truncate_at += 1) {
        try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello[0..truncate_at]));
    }
}

test "parseClientHello requires supported_versions advertising TLS 1.3" {
    var buf: [512]u8 = undefined;

    const missing = try buildTestClientHello(&buf, .{ .include_supported_versions = false });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(missing));

    var buf2: [512]u8 = undefined;
    const wrong = try buildTestClientHello(&buf2, .{ .supported_versions = &.{0x0303} });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(wrong));
}

test "parseClientHello rejects duplicate singleton extensions" {
    var buf: [512]u8 = undefined;

    const dup_versions = try buildTestClientHello(&buf, .{ .duplicate_supported_versions = true });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(dup_versions));

    var buf2: [512]u8 = undefined;
    const dup_key_share = try buildTestClientHello(&buf2, .{ .duplicate_key_share = true });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(dup_key_share));

    var buf3: [512]u8 = undefined;
    const dup_params = try buildTestClientHello(&buf3, .{ .duplicate_quic_transport_parameters = true });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(dup_params));

    var buf4: [512]u8 = undefined;
    const dup_groups = try buildTestClientHello(&buf4, .{ .duplicate_supported_groups = true });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(dup_groups));

    var buf5: [512]u8 = undefined;
    const dup_unknown = try buildTestClientHello(&buf5, .{ .duplicate_unknown_extension = true });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(dup_unknown));
}

test "parseClientHello requires X25519 in supported_groups" {
    var missing_buf: [512]u8 = undefined;
    const missing = try buildTestClientHello(&missing_buf, .{ .include_supported_groups = false });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(missing));

    var wrong_buf: [512]u8 = undefined;
    const wrong = try buildTestClientHello(&wrong_buf, .{ .supported_groups = &.{0x0017} });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(wrong));

    var unlisted_buf: [512]u8 = undefined;
    const unlisted = try buildTestClientHello(&unlisted_buf, .{
        .supported_groups = &.{named_group_x25519},
        .key_share_group = 0x0017,
    });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(unlisted));
}

test "parseClientHello requires a supported signature algorithm" {
    var missing_buf: [512]u8 = undefined;
    const missing = try buildTestClientHello(&missing_buf, .{ .include_signature_algorithms = false });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(missing));

    var wrong_buf: [512]u8 = undefined;
    const wrong = try buildTestClientHello(&wrong_buf, .{ .signature_algorithms = &.{0x0804} });
    var stage: ClientHelloStage = .structure;
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHelloWithStage(wrong, &stage));
    try testing.expectEqual(ClientHelloStage.signature_algorithms, stage);

    var p256_buf: [512]u8 = undefined;
    const p256 = try parseClientHello(try buildTestClientHello(&p256_buf, .{
        .signature_algorithms = &.{signature_scheme_ecdsa_secp256r1_sha256},
    }));
    try testing.expect(p256.offers_ecdsa_secp256r1_sha256);
    try testing.expect(!p256.offers_ed25519);
}

test "parseClientHello requires an X25519 key share of the right length" {
    var buf: [512]u8 = undefined;

    const missing = try buildTestClientHello(&buf, .{ .include_key_share = false });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(missing));

    var buf2: [512]u8 = undefined;
    const wrong_group = try buildTestClientHello(&buf2, .{ .key_share_group = 0x0017 });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(wrong_group));

    var buf3: [512]u8 = undefined;
    const wrong_len = try buildTestClientHello(&buf3, .{ .key_share_len = 31 });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(wrong_len));
}

test "parseClientHello requires quic_transport_parameters" {
    var buf: [512]u8 = undefined;
    const hello = try buildTestClientHello(&buf, .{ .include_quic_transport_parameters = false });
    try testing.expectError(Error.ZquicError.ProtocolViolation, parseClientHello(hello));
}

test "buildServerHello round-trips through an independent parser" {
    const server_random: [random_length]u8 = @splat(0x7e);
    const server_public: [x25519_key_length]u8 = @splat(0x33);
    const session_id = [_]u8{ 1, 2, 3, 4 };

    var buf: [256]u8 = undefined;
    const server_hello = try buildServerHello(&buf, &server_random, &session_id, &server_public);

    const parsed = try parseServerHelloForTest(server_hello);
    try testing.expectEqual(legacy_version_tls12, parsed.legacy_version);
    try testing.expectEqualSlices(u8, &server_random, &parsed.random);
    try testing.expectEqualSlices(u8, &session_id, parsed.legacy_session_id_echo);
    try testing.expectEqual(cipher_suite_aes_128_gcm_sha256, parsed.cipher_suite);
    try testing.expectEqual(version_tls13, parsed.selected_version);
    try testing.expectEqual(named_group_x25519, parsed.key_share_group);
    try testing.expectEqualSlices(u8, &server_public, parsed.key_share);
}

test "buildServerHello rejects an undersized output buffer" {
    const server_random: [random_length]u8 = @splat(0x7e);
    const server_public: [x25519_key_length]u8 = @splat(0x33);
    var buf: [16]u8 = undefined;
    try testing.expectError(
        Error.ZquicError.PacketTooLarge,
        buildServerHello(&buf, &server_random, &.{}, &server_public),
    );
}

test "buildServerHello rejects an oversized session id echo" {
    const server_random: [random_length]u8 = @splat(0x7e);
    const server_public: [x25519_key_length]u8 = @splat(0x33);
    const too_long: [33]u8 = @splat(0);
    var buf: [256]u8 = undefined;
    try testing.expectError(
        Error.ZquicError.ProtocolViolation,
        buildServerHello(&buf, &server_random, &too_long, &server_public),
    );
}
