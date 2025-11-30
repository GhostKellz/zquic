//! Fuzz-oriented tests for QUIC packet header parsing

const std = @import("std");
const zquic = @import("zquic");

const PacketHeader = zquic.Packet.PacketHeader;

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
    exerciseRandomCorpus(512, std.testing.allocator);
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
    exerciseRandomCorpus(128, std.testing.allocator);
}
