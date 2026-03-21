//! DNS-over-QUIC integration tests

const std = @import("std");
const zquic = @import("zquic");

const DoQ = zquic.DoQ;
const Error = zquic.Error;

fn writeTempCertFiles(allocator: std.mem.Allocator) !struct { cert: [:0]const u8, key: [:0]const u8, tmp: std.testing.TmpDir } {
    const io = std.testing.io;
    var tmp_dir = std.testing.tmpDir(.{});
    try tmp_dir.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = "dummy-cert" });
    try tmp_dir.dir.writeFile(io, .{ .sub_path = "key.pem", .data = "dummy-key" });

    const cert_path = try tmp_dir.dir.realPathFileAlloc(io, "cert.pem", allocator);
    const key_path = try tmp_dir.dir.realPathFileAlloc(io, "key.pem", allocator);

    return .{ .cert = cert_path, .key = key_path, .tmp = tmp_dir };
}

test "doq server initializes and exposes stats" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var temp = try writeTempCertFiles(allocator);
    defer {
        allocator.free(temp.cert);
        allocator.free(temp.key);
        temp.tmp.cleanup();
    }

    const handler = struct {
        fn echo(query: *DoQ.DnsMessage, arena: std.mem.Allocator) !DoQ.DnsMessage {
            var response = DoQ.DnsMessage.init(arena);
            response.header = query.header;
            if (query.questions.len > 0) {
                response.questions = try arena.alloc(DoQ.DnsQuestion, 1);
                response.questions[0] = DoQ.DnsQuestion{
                    .name = try arena.dupe(u8, query.questions[0].name),
                    .qtype = query.questions[0].qtype,
                    .qclass = query.questions[0].qclass,
                };
            }
            return response;
        }
    }.echo;

    var server = try DoQ.DoqServer.init(allocator, .{
        .address = "127.0.0.1",
        .port = 853,
        .cert_path = temp.cert,
        .key_path = temp.key,
        .handler = handler,
    });
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expect(stats.queries_processed == 0);
    try std.testing.expect(stats.active_connections == 0);
}

test "doq dns message serialize roundtrip" {
    const allocator = std.testing.allocator;

    var message = DoQ.DnsMessage.init(allocator);
    defer message.deinit();

    message.header = DoQ.DnsHeader{
        .id = 0xCAFE,
        .flags = 0x0100,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    message.questions = try allocator.alloc(DoQ.DnsQuestion, 1);
    message.questions[0] = DoQ.DnsQuestion{
        .name = try allocator.dupe(u8, "zquic.dev"),
        .qtype = @intFromEnum(DoQ.DnsRecordType.AAAA),
        .qclass = 1,
    };

    message.answers = try allocator.alloc(DoQ.DnsResourceRecord, 1);
    const ipv6_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    message.answers[0] = DoQ.DnsResourceRecord{
        .name = try allocator.dupe(u8, "zquic.dev"),
        .rtype = @intFromEnum(DoQ.DnsRecordType.AAAA),
        .rclass = 1,
        .ttl = 60,
        .rdlength = ipv6_bytes.len,
        .rdata = try allocator.dupe(u8, &ipv6_bytes),
    };

    const serialized = try message.serializeToStream(allocator);
    defer allocator.free(serialized);

    var parsed = try DoQ.DnsMessage.parseFromStream(allocator, serialized);
    defer parsed.deinit();

    try std.testing.expect(parsed.header.id == 0xCAFE);
    try std.testing.expect(parsed.questions.len == 1);
    try std.testing.expectEqualStrings("zquic.dev", parsed.questions[0].name);
    try std.testing.expect(parsed.answers.len == 1);
    try std.testing.expect(parsed.answers[0].rdlength == ipv6_bytes.len);
}
