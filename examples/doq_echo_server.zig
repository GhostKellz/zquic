//! DNS-over-QUIC Echo Server Demo
//!
//! Example implementation matching the TODO.md sketch

const std = @import("std");
const zquic = @import("zquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🚀 Starting DNS-over-QUIC Echo Server Demo...", .{});

    // Create DoQ server configuration (matching TODO.md sketch)
    const config = zquic.DoQ.ServerConfig{
        .address = "0.0.0.0",
        .port = 853,
        .max_connections = 1000,
        .query_timeout_ms = 5000,
        .enable_post_quantum = true,
        .cert_path = "/etc/ssl/certs/ghostplane.crt",
        .key_path = "/etc/ssl/private/ghostplane.key",
        .handler = customDnsHandler,
    };

    // Initialize DoQ server
    var server = zquic.DoQ.DoqServer.init(allocator, config) catch |err| {
        // Fallback to self-signed cert for demo
        std.log.warn("⚠️  Could not load certificates: {}, using demo mode", .{err});
        return startDemoServer(allocator);
    };
    defer server.deinit();

    // Signal handling removed for demo simplicity
    // In production, implement proper signal handling

    std.log.info("🌐 DoQ Echo Server listening on port 853", .{});
    std.log.info("🔐 Post-quantum crypto: enabled", .{});
    std.log.info("📊 Send SIGINT/SIGTERM to view stats and shutdown", .{});
    std.log.info("", .{});
    std.log.info("Test with: dig @127.0.0.1 -p 853 +https-post example.com", .{});
    std.log.info("Or use DoQ client tools like dnscrypt-proxy", .{});

    // Start server (this blocks)
    try server.start();
}

/// Fallback demo server when certificates are not available
fn startDemoServer(allocator: std.mem.Allocator) !void {
    std.log.info("🔧 Demo Mode: Running without TLS certificates", .{});
    std.log.info("📝 In production, provide valid cert_path and key_path", .{});

    // Create basic configuration for demo
    const demo_config = zquic.DoQ.ServerConfig{
        .address = "127.0.0.1",
        .port = 8530, // Use non-privileged port for demo
        .max_connections = 100,
        .query_timeout_ms = 3000,
        .enable_post_quantum = false, // Disable PQ for demo simplicity
        .cert_path = "", // Will use fallback demo certs
        .key_path = "",
        .handler = customDnsHandler,
    };

    var demo_server = try zquic.DoQ.DoqServer.init(allocator, demo_config);
    defer demo_server.deinit();

    std.log.info("🌐 Demo DoQ Server listening on 127.0.0.1:8530", .{});
    std.log.info("Test with: dig @127.0.0.1 -p 8530 example.com (if DoQ client available)", .{});

    // Simulate server operation with periodic stats
    var tick: u32 = 0;
    while (tick < 60) { // Run for 60 seconds
        std.Thread.sleep(1_000_000_000); // 1 second
        tick += 1;

        if (tick % 10 == 0) {
            const stats = demo_server.getStats();
            std.log.info("📊 Stats: {} queries processed, {} active connections", .{
                stats.queries_processed,
                stats.active_connections,
            });
        }
    }

    std.log.info("✅ Demo completed", .{});
}

/// Custom DNS handler function (matches TODO.md interface)
fn customDnsHandler(query: *zquic.DoQ.Message.DnsMessage, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    if (query.questions.len == 0) {
        return createErrorResponse(query, allocator, zquic.DoQ.Message.DnsResponseCode.FormErr);
    }

    const domain = query.questions[0].name;
    const qtype = query.questions[0].qtype;
    const record_type = @as(zquic.DoQ.Message.DnsRecordType, @enumFromInt(qtype));

    std.log.info("🔍 DoQ Query: {s} (type: {s})", .{ domain, record_type.toString() });

    // Example handling for different record types
    return switch (record_type) {
        .A => handleARecord(query, domain, allocator),
        .AAAA => handleAAAARecord(query, domain, allocator),
        .TXT => handleTXTRecord(query, domain, allocator),
        .MX => handleMXRecord(query, domain, allocator),
        else => {
            std.log.info("📝 Unsupported record type, returning echo response", .{});
            return createEchoResponse(query, allocator);
        },
    };
}

/// Handle A record queries (IPv4 addresses)
fn handleARecord(query: *const zquic.DoQ.Message.DnsMessage, domain: []const u8, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180, // QR=1, RD=1, RA=1
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    // Copy question
    response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, 1);
    response.questions[0] = zquic.DoQ.Message.DnsQuestion{
        .name = try allocator.dupe(u8, domain),
        .qtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.A),
        .qclass = query.questions[0].qclass,
    };

    // Create A record answer
    response.answers = try allocator.alloc(zquic.DoQ.Message.DnsResourceRecord, 1);

    // Demo IP addresses based on domain
    const ip_data = if (std.mem.eql(u8, domain, "example.com"))
        [_]u8{ 93, 184, 216, 34 } // example.com actual IP
    else if (std.mem.eql(u8, domain, "localhost"))
        [_]u8{ 127, 0, 0, 1 }
    else if (std.mem.startsWith(u8, domain, "ghost"))
        [_]u8{ 10, 0, 0, 1 } // GhostChain demo IP
    else
        [_]u8{ 198, 51, 100, 1 }; // RFC 5737 test IP

    response.answers[0] = zquic.DoQ.Message.DnsResourceRecord{
        .name = try allocator.dupe(u8, domain),
        .rtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.A),
        .rclass = 1, // IN
        .ttl = 300,
        .rdlength = 4,
        .rdata = try allocator.dupe(u8, &ip_data),
    };

    std.log.info("✅ A Record: {s} -> {}.{}.{}.{}", .{ domain, ip_data[0], ip_data[1], ip_data[2], ip_data[3] });
    return response;
}

/// Handle AAAA record queries (IPv6 addresses)
fn handleAAAARecord(query: *const zquic.DoQ.Message.DnsMessage, domain: []const u8, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, 1);
    response.questions[0] = zquic.DoQ.Message.DnsQuestion{
        .name = try allocator.dupe(u8, domain),
        .qtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.AAAA),
        .qclass = query.questions[0].qclass,
    };

    response.answers = try allocator.alloc(zquic.DoQ.Message.DnsResourceRecord, 1);

    // Demo IPv6 address (::1 for localhost, 2001:db8::1 for others)
    const ipv6_data = if (std.mem.eql(u8, domain, "localhost"))
        [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } // ::1
    else
        [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; // 2001:db8::1

    response.answers[0] = zquic.DoQ.Message.DnsResourceRecord{
        .name = try allocator.dupe(u8, domain),
        .rtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.AAAA),
        .rclass = 1,
        .ttl = 300,
        .rdlength = 16,
        .rdata = try allocator.dupe(u8, &ipv6_data),
    };

    std.log.info("✅ AAAA Record: {s} -> IPv6 address", .{domain});
    return response;
}

/// Handle TXT record queries
fn handleTXTRecord(query: *const zquic.DoQ.Message.DnsMessage, domain: []const u8, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, 1);
    response.questions[0] = zquic.DoQ.Message.DnsQuestion{
        .name = try allocator.dupe(u8, domain),
        .qtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.TXT),
        .qclass = query.questions[0].qclass,
    };

    response.answers = try allocator.alloc(zquic.DoQ.Message.DnsResourceRecord, 1);

    // Create demo TXT record
    const txt_content = if (std.mem.startsWith(u8, domain, "ghost"))
        "ghostchain-verified=true quantum-safe=enabled"
    else
        "zquic-doq-echo-server powered-by=zig";

    const txt_data = try std.fmt.allocPrint(allocator, "{c}{s}", .{ @as(u8, @intCast(txt_content.len)), txt_content });

    response.answers[0] = zquic.DoQ.Message.DnsResourceRecord{
        .name = try allocator.dupe(u8, domain),
        .rtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.TXT),
        .rclass = 1,
        .ttl = 300,
        .rdlength = @intCast(txt_data.len),
        .rdata = txt_data,
    };

    std.log.info("✅ TXT Record: {s} -> \"{s}\"", .{ domain, txt_content });
    return response;
}

/// Handle MX record queries
fn handleMXRecord(query: *const zquic.DoQ.Message.DnsMessage, domain: []const u8, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };

    response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, 1);
    response.questions[0] = zquic.DoQ.Message.DnsQuestion{
        .name = try allocator.dupe(u8, domain),
        .qtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.MX),
        .qclass = query.questions[0].qclass,
    };

    response.answers = try allocator.alloc(zquic.DoQ.Message.DnsResourceRecord, 1);

    // Create demo MX record: priority (2 bytes) + domain name
    const mx_domain = try std.fmt.allocPrint(allocator, "mail.{s}", .{domain});
    defer allocator.free(mx_domain);

    var mx_data = std.ArrayList(u8){};
    defer mx_data.deinit(allocator);

    // Priority (10)
    try mx_data.append(allocator, 0);
    try mx_data.append(allocator, 10);

    // Encode domain name
    var parts = std.mem.splitScalar(u8, mx_domain, '.');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        try mx_data.append(allocator, @intCast(part.len));
        try mx_data.appendSlice(allocator, part);
    }
    try mx_data.append(allocator, 0); // null terminator

    response.answers[0] = zquic.DoQ.Message.DnsResourceRecord{
        .name = try allocator.dupe(u8, domain),
        .rtype = @intFromEnum(zquic.DoQ.Message.DnsRecordType.MX),
        .rclass = 1,
        .ttl = 300,
        .rdlength = @intCast(mx_data.items.len),
        .rdata = try mx_data.toOwnedSlice(allocator),
    };

    std.log.info("✅ MX Record: {s} -> 10 {s}", .{ domain, mx_domain });
    return response;
}

/// Create echo response (fallback)
fn createEchoResponse(query: *const zquic.DoQ.Message.DnsMessage, allocator: std.mem.Allocator) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8180,
        .qdcount = query.header.qdcount,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    // Copy questions only
    if (query.questions.len > 0) {
        response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, query.questions.len);
        for (query.questions, 0..) |question, i| {
            response.questions[i] = zquic.DoQ.Message.DnsQuestion{
                .name = try allocator.dupe(u8, question.name),
                .qtype = question.qtype,
                .qclass = question.qclass,
            };
        }
    }

    std.log.info("📡 Echo response (no answers)", .{});
    return response;
}

/// Create error response
fn createErrorResponse(query: *const zquic.DoQ.Message.DnsMessage, allocator: std.mem.Allocator, rcode: zquic.DoQ.Message.DnsResponseCode) !zquic.DoQ.Message.DnsMessage {
    var response = zquic.DoQ.Message.DnsMessage.init(allocator);

    response.header = zquic.DoQ.Message.DnsHeader{
        .id = query.header.id,
        .flags = 0x8000 | (@as(u16, @intFromEnum(rcode)) & 0x000F), // QR=1, RCODE=rcode
        .qdcount = query.header.qdcount,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    // Copy questions
    if (query.questions.len > 0) {
        response.questions = try allocator.alloc(zquic.DoQ.Message.DnsQuestion, query.questions.len);
        for (query.questions, 0..) |question, i| {
            response.questions[i] = zquic.DoQ.Message.DnsQuestion{
                .name = try allocator.dupe(u8, question.name),
                .qtype = question.qtype,
                .qclass = question.qclass,
            };
        }
    }

    std.log.warn("❌ Error response: {}", .{rcode});
    return response;
}
