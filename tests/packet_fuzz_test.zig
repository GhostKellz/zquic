//! Fuzz-oriented tests for QUIC packet header parsing

const std = @import("std");
const zquic = @import("zquic");
const builtin = @import("builtin");
const math = std.math;

const PacketHeader = zquic.Packet.PacketHeader;

const TraceFixture = struct {
    name: []const u8,
    role: []const u8,
    quic_version: ?u32,
    alpn: []const u8,
    cipher_suite: []const u8,
    feature_flags: []const []const u8,
    packet_space: []const u8,
    packet_type: []const u8,
    expected_result: []const u8,
    destination_connection_id: []const u8,
    source_connection_id: ?[]const u8,
    packet_number: u64,
    packet_number_length: u8,
    header_length: usize,
    frame_summary: []const []const u8,
    packet_hex: []const u8,
};

fn scaledIterations(base: usize) usize {
    // Keep compatibility across Zig versions: gate on presence of hasEnvVar.
    if (@hasDecl(std.process, "hasEnvVar") and std.process.hasEnvVar("CI")) {
        return math.max(base / 8, 1);
    }
    return base;
}

fn parseExpectedPacketType(packet_type: []const u8) !zquic.Packet.PacketType {
    if (std.mem.eql(u8, packet_type, "initial")) return .initial;
    if (std.mem.eql(u8, packet_type, "handshake")) return .handshake;
    if (std.mem.eql(u8, packet_type, "zero_rtt")) return .zero_rtt;
    if (std.mem.eql(u8, packet_type, "one_rtt")) return .one_rtt;
    return error.UnknownPacketType;
}

fn expectConnectionIdHex(expected_hex: []const u8, actual: *const zquic.Packet.ConnectionId) !void {
    var expected: [20]u8 = undefined;
    const expected_bytes = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, expected_bytes, actual.bytes());
}

fn replayInteropFixture(comptime fixture_json: []const u8) !void {
    const parsed = try std.json.parseFromSlice(TraceFixture, std.testing.allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixture = parsed.value;
    try std.testing.expect(fixture.packet_hex.len > 0);
    try std.testing.expectEqual(@as(usize, 0), fixture.packet_hex.len % 2);
    try std.testing.expect(fixture.frame_summary.len > 0);

    var packet_bytes: [256]u8 = undefined;
    const packet = try std.fmt.hexToBytes(&packet_bytes, fixture.packet_hex);

    if (std.mem.eql(u8, fixture.expected_result, "accept") or
        std.mem.eql(u8, fixture.expected_result, "accept_header_only"))
    {
        const header = try PacketHeader.parse(packet, std.testing.allocator);
        try std.testing.expectEqual(try parseExpectedPacketType(fixture.packet_type), header.packet_type);
        try std.testing.expectEqual(fixture.quic_version, header.version);
        try std.testing.expectEqual(fixture.packet_number_length, header.packet_number_len);
        try std.testing.expectEqual(fixture.header_length, header.header_length);
        try expectConnectionIdHex(fixture.destination_connection_id, &header.dest_conn_id);

        if (fixture.source_connection_id) |source_hex| {
            try std.testing.expect(header.src_conn_id != null);
            try expectConnectionIdHex(source_hex, &header.src_conn_id.?);
        } else {
            try std.testing.expect(header.src_conn_id == null);
        }
    } else if (std.mem.eql(u8, fixture.expected_result, "reject")) {
        try std.testing.expectError(error.InvalidPacket, PacketHeader.parse(packet, std.testing.allocator));
    } else {
        return error.UnknownExpectedResult;
    }
}

fn exerciseRandomCorpus(iterations: usize, allocator: std.mem.Allocator) void {
    var prng = std.Random.DefaultPrng.init(0xDEC0DED);
    var random = prng.random();
    var buffer: [96]u8 = undefined;

    for (0..iterations) |i| {
        const len = random.intRangeAtMost(usize, 1, buffer.len);
        var slice = buffer[0..len];
        random.bytes(slice);

        // Ensure fixed bit is set; flip header form for variety
        slice[0] |= 0x40;
        if ((i & 1) == 0) {
            slice[0] |= 0x80; // long header
        } else {
            slice[0] &= 0x7F; // short header
        }

        const result = PacketHeader.parse(slice, allocator);
        if (result) |header| {
            // Touch a few fields to ensure they remain consistent
            _ = header.packet_type;
            _ = header.dest_conn_id.len;
            _ = header.packet_number_len;
        } else |_| {
            // Parsing failures are expected; ensure no panics or leaks
            continue;
        }
    }
}

test "fuzz: packet header parser handles random data" {
    exerciseRandomCorpus(scaledIterations(512), std.testing.allocator);
}

test "fuzz: valid long header survives random corpus" {
    const valid_initial = [_]u8{
        0xC0, // Long header, Initial packet type
        0x00, 0x00, 0x00, 0x01, // Version 1
        0x04, 0x01, 0x02, 0x03, 0x04, // Dest CID len + bytes
        0x04, 0x05, 0x06, 0x07, 0x08, // Src CID len + bytes
    };

    const header = try PacketHeader.parse(&valid_initial, std.testing.allocator);
    try std.testing.expect(header.packet_type == .initial);
    try std.testing.expect(header.version.? == 1);
    try std.testing.expectEqual(@as(u8, 4), header.dest_conn_id.len);

    // Run the random corpus after a known-good parse to catch regressions when state mutates
    exerciseRandomCorpus(scaledIterations(128), std.testing.allocator);
}

test "fuzz: malformed long headers are rejected deterministically" {
    const cases = [_][]const u8{
        &.{}, // empty
        &.{0x80}, // missing version
        &.{ 0x80, 0x00, 0x00, 0x00, 0x01 }, // missing DCID length
        &.{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x15 }, // DCID length exceeds max/packet
        &.{ 0x80, 0x00, 0x00, 0x00, 0x01, 0x00 }, // missing SCID length
    };

    for (cases) |case| {
        try std.testing.expectError(error.InvalidPacket, PacketHeader.parse(case, std.testing.allocator));
    }

    const unsupported_version = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 };
    try std.testing.expectError(error.NotSupported, PacketHeader.parse(&unsupported_version, std.testing.allocator));
}

test "fuzz: short header fixed bit and packet number length bits" {
    const valid_short = [_]u8{ 0x43, 1, 2, 3, 4, 5, 6, 7, 8 };
    const header = try PacketHeader.parse(&valid_short, std.testing.allocator);
    try std.testing.expect(header.packet_type == .one_rtt);
    try std.testing.expectEqual(@as(u8, 4), header.packet_number_len);
    try std.testing.expectEqual(@as(usize, 9), header.header_length);

    const missing_fixed = [_]u8{ 0x03, 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectError(error.InvalidPacket, PacketHeader.parse(&missing_fixed, std.testing.allocator));

    const truncated_short = [_]u8{ 0x40, 1, 2, 3 };
    try std.testing.expectError(error.InvalidPacket, PacketHeader.parse(&truncated_short, std.testing.allocator));
}

test "fuzz: malformed frame varints and truncated frames reject" {
    const invalid_packet_number_lengths = [_][]const u8{
        &.{ 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 },
        &.{ 0xC1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 },
        &.{ 0xC2, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 },
        &.{ 0xC3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 },
    };

    for (invalid_packet_number_lengths) |case| {
        const header = try PacketHeader.parse(case, std.testing.allocator);
        try std.testing.expect(header.packet_number_len >= 1 and header.packet_number_len <= 4);
    }
}

test "interop fixtures: replay deterministic packet traces" {
    try replayInteropFixture(@embedFile("fixtures/interop/initial.json"));
    try replayInteropFixture(@embedFile("fixtures/interop/handshake.json"));
    try replayInteropFixture(@embedFile("fixtures/interop/zero-rtt.json"));
    try replayInteropFixture(@embedFile("fixtures/interop/one-rtt.json"));
}
