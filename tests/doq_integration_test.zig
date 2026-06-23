//! DNS-over-QUIC integration tests

const std = @import("std");
const zquic = @import("zquic");

const DoQ = zquic.DoQ;
const Error = zquic.Error;

const DoqFixture = struct {
    name: []const u8,
    description: []const u8,
    expected_result: []const u8,
    stream_hex: []const u8,
    expected_message_ids: []const u16 = &.{},
    expected_question_names: []const []const u8 = &.{},
    expected_rcode: ?u8 = null,
    timeout_started_seconds: ?i64 = null,
    timeout_now_seconds: ?i64 = null,
    timeout_ms: ?u32 = null,
    expected_timeout: ?bool = null,
};

fn makeQuery(allocator: std.mem.Allocator, id: u16, name: []const u8, qtype: DoQ.DnsRecordType) !DoQ.DnsMessage {
    var message = DoQ.DnsMessage.init(allocator);
    message.header = DoQ.DnsHeader{
        .id = id,
        .flags = 0x0100,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
    message.questions = try allocator.alloc(DoQ.DnsQuestion, 1);
    message.questions[0] = DoQ.DnsQuestion{
        .name = try allocator.dupe(u8, name),
        .qtype = @intFromEnum(qtype),
        .qclass = 1,
    };
    return message;
}

fn replayDoqFixture(comptime fixture_json: []const u8) !void {
    const parsed = try std.json.parseFromSlice(DoqFixture, std.testing.allocator, fixture_json, .{});
    defer parsed.deinit();
    const fixture = parsed.value;

    if (std.mem.eql(u8, fixture.expected_result, "timeout")) {
        const timed_out = DoQ.queryTimedOut(
            fixture.timeout_started_seconds.?,
            fixture.timeout_now_seconds.?,
            fixture.timeout_ms.?,
        );
        try std.testing.expectEqual(fixture.expected_timeout.?, timed_out);
        return;
    }

    try std.testing.expectEqual(@as(usize, 0), fixture.stream_hex.len % 2);
    var stream_buffer: [512]u8 = undefined;
    const stream_bytes = try std.fmt.hexToBytes(&stream_buffer, fixture.stream_hex);

    const stream_messages = try DoQ.parseLengthPrefixedMessages(std.testing.allocator, stream_bytes);
    defer std.testing.allocator.free(stream_messages);

    try std.testing.expectEqual(fixture.expected_message_ids.len, stream_messages.len);

    for (stream_messages, 0..) |stream_message, index| {
        var message = try DoQ.DnsMessage.parseFromStream(std.testing.allocator, stream_message.payload);
        defer message.deinit();

        try std.testing.expectEqual(fixture.expected_message_ids[index], message.header.id);
        try std.testing.expect(message.questions.len > 0);
        try std.testing.expectEqualStrings(fixture.expected_question_names[index], message.questions[0].name);

        if (std.mem.eql(u8, fixture.expected_result, "rcode")) {
            try std.testing.expect(fixture.expected_rcode != null);
            try std.testing.expectEqual(@as(u8, fixture.expected_rcode.?), @as(u8, @intFromEnum(message.responseCode())));
        }
    }
}

fn writeTempCertFiles(allocator: std.mem.Allocator) !struct { cert: [:0]const u8, key: [:0]const u8, tmp: std.testing.TmpDir } {
    const io = std.testing.io;
    var tmp_dir = std.testing.tmpDir(.{});
    try tmp_dir.dir.writeFile(io, .{ .sub_path = "cert.pem", .data = "dummy-cert" });
    try tmp_dir.dir.writeFile(io, .{ .sub_path = "key.pem", .data = "dummy-key" });

    const cert_path = try tmp_dir.dir.realPathFileAlloc(io, "cert.pem", allocator);
    const key_path = try tmp_dir.dir.realPathFileAlloc(io, "key.pem", allocator);

    return .{ .cert = cert_path, .key = key_path, .tmp = tmp_dir };
}

test "doq parses compressed answer names" {
    const allocator = std.testing.allocator;

    const wire = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00,
        0x04, 127,  0,    0,    1,
    };

    var parsed = try DoQ.DnsMessage.parseFromStream(allocator, &wire);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u16, 0x1234), parsed.header.id);
    try std.testing.expectEqualStrings("example.com", parsed.questions[0].name);
    try std.testing.expectEqualStrings("example.com", parsed.answers[0].name);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, parsed.answers[0].rdata);
}

test "doq rejects malformed compression pointer" {
    const allocator = std.testing.allocator;

    const wire = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xC0, 0xFF, 0x00, 0x01,
        0x00, 0x01,
    };

    try std.testing.expectError(Error.ZquicError.InvalidArgument, DoQ.DnsMessage.parseFromStream(allocator, &wire));
}

test "doq parses multiple concurrent query messages independently" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{ "alpha.zquic.dev", "beta.zquic.dev", "gamma.zquic.dev" };
    var serialized: [names.len][]u8 = undefined;

    for (names, 0..) |name, i| {
        var query = try makeQuery(allocator, @intCast(0x2000 + i), name, .A);
        defer query.deinit();
        serialized[i] = try query.serializeToStream(allocator);
    }
    defer {
        for (serialized) |bytes| allocator.free(bytes);
    }

    for (serialized, 0..) |bytes, i| {
        var parsed = try DoQ.DnsMessage.parseFromStream(allocator, bytes);
        defer parsed.deinit();

        try std.testing.expectEqual(@as(u16, @intCast(0x2000 + i)), parsed.header.id);
        try std.testing.expectEqualStrings(names[i], parsed.questions[0].name);
    }
}

test "doq maps NXDOMAIN and SERVFAIL responses" {
    const allocator = std.testing.allocator;

    var query = try makeQuery(allocator, 0xBEEF, "missing.zquic.dev", .AAAA);
    defer query.deinit();

    var nxdomain = try DoQ.createResponseForQuery(allocator, &query, .NXDomain);
    defer nxdomain.deinit();
    try std.testing.expectEqual(DoQ.DnsResponseCode.NXDomain, nxdomain.responseCode());
    try std.testing.expectEqual(@as(u16, 0xBEEF), nxdomain.header.id);
    try std.testing.expectEqualStrings("missing.zquic.dev", nxdomain.questions[0].name);

    var servfail = try DoQ.createResponseForQuery(allocator, &query, .ServFail);
    defer servfail.deinit();
    try std.testing.expectEqual(DoQ.DnsResponseCode.ServFail, servfail.responseCode());
}

test "doq rejects oversized and over-counted messages" {
    const allocator = std.testing.allocator;

    const oversized = try allocator.alloc(u8, DoQ.Message.max_dns_message_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 0);
    try std.testing.expectError(Error.ZquicError.InvalidArgument, DoQ.DnsMessage.parseFromStream(allocator, oversized));

    const too_many_questions = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(Error.ZquicError.InvalidArgument, DoQ.DnsMessage.parseFromStream(allocator, &too_many_questions));
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

test "doq server cancels and times out pending queries" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var temp = try writeTempCertFiles(allocator);
    defer {
        allocator.free(temp.cert);
        allocator.free(temp.key);
        temp.tmp.cleanup();
    }

    const callback = struct {
        fn ignore(_: []u8) void {}
    }.ignore;

    var server = try DoQ.DoqServer.init(allocator, .{
        .address = "127.0.0.1",
        .port = 853,
        .cert_path = temp.cert,
        .key_path = temp.key,
        .query_timeout_ms = 5000,
    });
    defer server.deinit();

    try server.queuePendingQuery(1, "cancel-me", callback, 10);
    try std.testing.expect(server.cancelPendingQuery(1));
    try std.testing.expect(!server.cancelPendingQuery(1));
    try std.testing.expectEqual(@as(usize, 0), server.pending_queries.items.len);
    try std.testing.expectEqual(@as(u64, 1), server.stats.queries_failed);

    try server.queuePendingQuery(2, "still-live", callback, 15);
    try server.queuePendingQuery(3, "expired", callback, 10);
    server.cleanupTimedOutQueries(16);

    try std.testing.expectEqual(@as(usize, 1), server.pending_queries.items.len);
    try std.testing.expectEqual(@as(u16, 2), server.pending_queries.items[0].query_id);
    try std.testing.expectEqual(@as(u64, 2), server.stats.queries_failed);
}

test "doq server deinit releases oversized pending message cleanup" {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    const allocator = debug_allocator.allocator();

    var temp = try writeTempCertFiles(allocator);

    const callback = struct {
        fn ignore(_: []u8) void {}
    }.ignore;

    var server = try DoQ.DoqServer.init(allocator, .{
        .address = "127.0.0.1",
        .port = 853,
        .cert_path = temp.cert,
        .key_path = temp.key,
    });

    const oversized = try allocator.alloc(u8, DoQ.Message.max_dns_message_size);
    @memset(oversized, 0xaa);
    try server.queuePendingQuery(99, oversized, callback, 10);
    server.deinit();
    allocator.free(oversized);
    allocator.free(temp.cert);
    allocator.free(temp.key);
    temp.tmp.cleanup();

    try std.testing.expectEqual(.ok, debug_allocator.deinit());
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

test "interop: doq length-prefixed stream fixtures replay" {
    try replayDoqFixture(@embedFile("fixtures/doq/length-framed-query.json"));
    try replayDoqFixture(@embedFile("fixtures/doq/pipelined-queries.json"));
    try replayDoqFixture(@embedFile("fixtures/doq/nxdomain-response.json"));
    try replayDoqFixture(@embedFile("fixtures/doq/servfail-response.json"));
    try replayDoqFixture(@embedFile("fixtures/doq/timeout-policy.json"));
}

test "interop: doq rejects malformed length-prefixed streams" {
    const truncated_length = [_]u8{0x00};
    try std.testing.expectError(Error.ZquicError.InvalidData, DoQ.parseLengthPrefixedMessages(std.testing.allocator, &truncated_length));

    const truncated_payload = [_]u8{ 0x00, 0x0c, 0x12, 0x34 };
    try std.testing.expectError(Error.ZquicError.InvalidData, DoQ.parseLengthPrefixedMessages(std.testing.allocator, &truncated_payload));

    const too_short_dns_message = [_]u8{ 0x00, 0x01, 0x00 };
    try std.testing.expectError(Error.ZquicError.InvalidArgument, DoQ.parseLengthPrefixedMessages(std.testing.allocator, &too_short_dns_message));
}
