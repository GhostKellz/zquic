//! DNS-over-QUIC Message Parser (RFC 9250)
//!
//! Implements DoQ message parsing and serialization for stream 0

const std = @import("std");
const Io = std.Io;
const Error = @import("../utils/error.zig");

pub const max_dns_message_size: usize = 65535;
pub const max_dns_record_count: u16 = 4096;

pub const StreamMessage = struct {
    payload: []const u8,
};

/// DNS message header structure (RFC 1035)
pub const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16, // Number of questions
    ancount: u16, // Number of answers
    nscount: u16, // Number of authority records
    arcount: u16, // Number of additional records

    pub fn encode(self: *const DnsHeader, writer: anytype) !void {
        try writer.writeInt(u16, self.id, .big);
        try writer.writeInt(u16, self.flags, .big);
        try writer.writeInt(u16, self.qdcount, .big);
        try writer.writeInt(u16, self.ancount, .big);
        try writer.writeInt(u16, self.nscount, .big);
        try writer.writeInt(u16, self.arcount, .big);
    }

    pub fn decode(reader: anytype) !DnsHeader {
        return DnsHeader{
            .id = try reader.takeInt(u16, .big),
            .flags = try reader.takeInt(u16, .big),
            .qdcount = try reader.takeInt(u16, .big),
            .ancount = try reader.takeInt(u16, .big),
            .nscount = try reader.takeInt(u16, .big),
            .arcount = try reader.takeInt(u16, .big),
        };
    }
};

/// DNS question structure
pub const DnsQuestion = struct {
    name: []const u8,
    qtype: u16,
    qclass: u16,

    pub fn encode(self: *const DnsQuestion, allocator: std.mem.Allocator, writer: anytype) !void {
        // Encode domain name in wire format
        try encodeDomainName(self.name, allocator, writer);
        try writer.writeInt(u16, self.qtype, .big);
        try writer.writeInt(u16, self.qclass, .big);
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype, message_data: []const u8) !DnsQuestion {
        const name = try decodeDomainName(allocator, reader, message_data);
        const qtype = try reader.takeInt(u16, .big);
        const qclass = try reader.takeInt(u16, .big);

        return DnsQuestion{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }
};

/// DNS resource record structure
pub const DnsResourceRecord = struct {
    name: []const u8,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []const u8,

    pub fn encode(self: *const DnsResourceRecord, allocator: std.mem.Allocator, writer: anytype) !void {
        try encodeDomainName(self.name, allocator, writer);
        try writer.writeInt(u16, self.rtype, .big);
        try writer.writeInt(u16, self.rclass, .big);
        try writer.writeInt(u32, self.ttl, .big);
        try writer.writeInt(u16, self.rdlength, .big);
        try writer.writeAll(self.rdata);
    }

    pub fn decode(allocator: std.mem.Allocator, reader: anytype, message_data: []const u8) !DnsResourceRecord {
        const name = try decodeDomainName(allocator, reader, message_data);
        const rtype = try reader.takeInt(u16, .big);
        const rclass = try reader.takeInt(u16, .big);
        const ttl = try reader.takeInt(u32, .big);
        const rdlength = try reader.takeInt(u16, .big);

        const rdata = try allocator.alloc(u8, rdlength);
        try reader.readSliceAll(rdata);

        return DnsResourceRecord{
            .name = name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = rdata,
        };
    }
};

/// Complete DNS message structure
pub const DnsMessage = struct {
    header: DnsHeader,
    questions: []DnsQuestion,
    answers: []DnsResourceRecord,
    authority: []DnsResourceRecord,
    additional: []DnsResourceRecord,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DnsMessage {
        return DnsMessage{
            .header = std.mem.zeroes(DnsHeader),
            .questions = &[_]DnsQuestion{},
            .answers = &[_]DnsResourceRecord{},
            .authority = &[_]DnsResourceRecord{},
            .additional = &[_]DnsResourceRecord{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DnsMessage) void {
        for (self.questions) |question| {
            self.allocator.free(question.name);
        }
        for (self.answers) |answer| {
            self.allocator.free(answer.name);
            self.allocator.free(answer.rdata);
        }
        for (self.authority) |auth| {
            self.allocator.free(auth.name);
            self.allocator.free(auth.rdata);
        }
        for (self.additional) |add| {
            self.allocator.free(add.name);
            self.allocator.free(add.rdata);
        }

        if (self.questions.len > 0) self.allocator.free(self.questions);
        if (self.answers.len > 0) self.allocator.free(self.answers);
        if (self.authority.len > 0) self.allocator.free(self.authority);
        if (self.additional.len > 0) self.allocator.free(self.additional);
    }

    /// Parse DoQ message from QUIC stream 0 (RFC 9250)
    /// Supports DNS compression pointers per RFC 1035 Section 4.1.4
    pub fn parseFromStream(allocator: std.mem.Allocator, data: []const u8) !DnsMessage {
        if (data.len < 12 or data.len > max_dns_message_size) {
            return Error.ZquicError.InvalidArgument;
        }

        var reader = Io.Reader.fixed(data);

        // Parse DNS header
        const header = try DnsHeader.decode(&reader);
        try validateRecordCounts(header);

        var message = DnsMessage.init(allocator);
        message.header = header;
        errdefer message.deinit();

        // Parse questions (passing data for compression pointer resolution)
        if (header.qdcount > 0) {
            const questions = try allocator.alloc(DnsQuestion, header.qdcount);
            var decoded: usize = 0;
            errdefer {
                for (questions[0..decoded]) |question| {
                    allocator.free(question.name);
                }
                allocator.free(questions);
            }
            for (0..header.qdcount) |i| {
                questions[i] = try DnsQuestion.decode(allocator, &reader, data);
                decoded += 1;
            }
            message.questions = questions;
        }

        // Parse answers
        if (header.ancount > 0) {
            const answers = try allocator.alloc(DnsResourceRecord, header.ancount);
            var decoded: usize = 0;
            errdefer {
                for (answers[0..decoded]) |answer| {
                    allocator.free(answer.name);
                    allocator.free(answer.rdata);
                }
                allocator.free(answers);
            }
            for (0..header.ancount) |i| {
                answers[i] = try DnsResourceRecord.decode(allocator, &reader, data);
                decoded += 1;
            }
            message.answers = answers;
        }

        // Parse authority records
        if (header.nscount > 0) {
            const authority = try allocator.alloc(DnsResourceRecord, header.nscount);
            var decoded: usize = 0;
            errdefer {
                for (authority[0..decoded]) |auth| {
                    allocator.free(auth.name);
                    allocator.free(auth.rdata);
                }
                allocator.free(authority);
            }
            for (0..header.nscount) |i| {
                authority[i] = try DnsResourceRecord.decode(allocator, &reader, data);
                decoded += 1;
            }
            message.authority = authority;
        }

        // Parse additional records
        if (header.arcount > 0) {
            const additional = try allocator.alloc(DnsResourceRecord, header.arcount);
            var decoded: usize = 0;
            errdefer {
                for (additional[0..decoded]) |add| {
                    allocator.free(add.name);
                    allocator.free(add.rdata);
                }
                allocator.free(additional);
            }
            for (0..header.arcount) |i| {
                additional[i] = try DnsResourceRecord.decode(allocator, &reader, data);
                decoded += 1;
            }
            message.additional = additional;
        }

        return message;
    }

    /// Serialize DoQ message for QUIC stream 0 (RFC 9250)
    pub fn serializeToStream(self: *const DnsMessage, allocator: std.mem.Allocator) ![]u8 {
        try validateRecordCounts(self.header);

        // DNS messages are typically small, use a reasonable fixed buffer
        var buffer: [max_dns_message_size]u8 = undefined;
        var writer = Io.Writer.fixed(&buffer);

        // Write header
        try self.header.encode(&writer);

        // Write questions
        for (self.questions) |question| {
            try question.encode(allocator, &writer);
        }

        // Write answers
        for (self.answers) |answer| {
            try answer.encode(allocator, &writer);
        }

        // Write authority records
        for (self.authority) |auth| {
            try auth.encode(allocator, &writer);
        }

        // Write additional records
        for (self.additional) |add| {
            try add.encode(allocator, &writer);
        }

        // Return a copy of the serialized data
        const written = Io.Writer.buffered(&writer);
        if (written.len > max_dns_message_size) {
            return Error.ZquicError.InvalidArgument;
        }
        return try allocator.dupe(u8, written);
    }

    pub fn responseCode(self: *const DnsMessage) DnsResponseCode {
        return @fromBackingInt(@intCast(@as(u4, @intCast(self.header.flags & 0x000F))));
    }
};

pub fn createResponseForQuery(allocator: std.mem.Allocator, query: *const DnsMessage, rcode: DnsResponseCode) !DnsMessage {
    var response = DnsMessage.init(allocator);
    response.header = DnsHeader{
        .id = query.header.id,
        .flags = 0x8000 | (@as(u16, @backingInt(rcode)) & 0x000F),
        .qdcount = query.header.qdcount,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    if (query.questions.len > 0) {
        response.questions = try allocator.alloc(DnsQuestion, query.questions.len);
        for (query.questions, 0..) |question, i| {
            response.questions[i] = DnsQuestion{
                .name = try allocator.dupe(u8, question.name),
                .qtype = question.qtype,
                .qclass = question.qclass,
            };
        }
    }

    return response;
}

/// Encode one RFC 9250 DNS message with the two-octet stream length prefix.
pub fn encodeLengthPrefixedMessage(allocator: std.mem.Allocator, dns_message: []const u8) ![]u8 {
    if (dns_message.len < 12 or dns_message.len > max_dns_message_size) {
        return Error.ZquicError.InvalidArgument;
    }

    const framed = try allocator.alloc(u8, dns_message.len + 2);
    const len: u16 = @intCast(dns_message.len);
    framed[0] = @intCast(len >> 8);
    framed[1] = @intCast(len & 0xff);
    @memcpy(framed[2..], dns_message);
    return framed;
}

/// Parse one or more RFC 9250 length-prefixed DNS messages from a QUIC stream.
pub fn parseLengthPrefixedMessages(allocator: std.mem.Allocator, stream_data: []const u8) ![]StreamMessage {
    var messages: std.ArrayListUnmanaged(StreamMessage) = .empty;
    errdefer messages.deinit(allocator);

    var offset: usize = 0;
    while (offset < stream_data.len) {
        if (stream_data.len - offset < 2) return Error.ZquicError.InvalidData;
        const len = (@as(usize, stream_data[offset]) << 8) | stream_data[offset + 1];
        offset += 2;

        if (len < 12 or len > max_dns_message_size) return Error.ZquicError.InvalidArgument;
        if (offset + len > stream_data.len) return Error.ZquicError.InvalidData;

        try messages.append(allocator, .{ .payload = stream_data[offset .. offset + len] });
        offset += len;
    }

    return messages.toOwnedSlice(allocator);
}

fn validateRecordCounts(header: DnsHeader) !void {
    if (header.qdcount > max_dns_record_count or
        header.ancount > max_dns_record_count or
        header.nscount > max_dns_record_count or
        header.arcount > max_dns_record_count)
    {
        return Error.ZquicError.InvalidArgument;
    }
}

/// Encode domain name in DNS wire format
fn encodeDomainName(name: []const u8, _: std.mem.Allocator, writer: anytype) !void {
    var parts = std.mem.splitScalar(u8, name, '.');

    while (parts.next()) |part| {
        if (part.len == 0) continue;
        if (part.len > 63) return Error.ZquicError.InvalidArgument;

        try writer.writeByte(@intCast(part.len));
        try writer.writeAll(part);
    }

    // Null terminator
    try writer.writeByte(0);
}

/// Decode domain name from DNS wire format with compression pointer support (RFC 1035)
/// message_data is the complete DNS message for resolving compression pointers
fn decodeDomainName(allocator: std.mem.Allocator, reader: anytype, message_data: []const u8) ![]u8 {
    var parts: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        // Free any remaining parts on error/cleanup
        for (parts.items) |part| {
            allocator.free(part);
        }
        parts.deinit(allocator);
    }

    // Track pointers followed to detect loops (max 128 levels)
    var pointer_count: u8 = 0;
    const max_pointers: u8 = 128;

    // We may need to follow compression pointers
    var current_reader = reader;
    var pointer_reader: ?Io.Reader = null;

    while (true) {
        const length = current_reader.takeByte() catch |err| {
            if (err == error.EndOfStream) break;
            return err;
        };
        if (length == 0) break;

        // Check for compression pointer (RFC 1035 Section 4.1.4)
        // If top 2 bits are 11, this is a pointer
        if ((length & 0xC0) == 0xC0) {
            if (pointer_count >= max_pointers) {
                // Prevent infinite loops
                return Error.ZquicError.InvalidArgument;
            }
            pointer_count += 1;

            // Read second byte of pointer
            const second_byte = try current_reader.takeByte();
            const offset: u16 = (@as(u16, length & 0x3F) << 8) | second_byte;

            // Validate offset is within message bounds
            if (offset >= message_data.len) {
                return Error.ZquicError.InvalidArgument;
            }

            // Create a reader at the pointed-to location
            pointer_reader = Io.Reader.fixed(message_data[offset..]);
            current_reader = &pointer_reader.?;
            continue;
        }

        // Normal label: length must be 0-63
        if (length > 63) return Error.ZquicError.InvalidArgument;

        const part = try allocator.alloc(u8, length);
        current_reader.readSliceAll(part) catch |err| {
            allocator.free(part);
            return err;
        };
        try parts.append(allocator, part);
    }

    if (parts.items.len == 0) {
        return try allocator.dupe(u8, ".");
    }

    // Join parts with dots
    var total_len: usize = 0;
    for (parts.items) |part| {
        total_len += part.len + 1; // +1 for dot
    }

    const result = try allocator.alloc(u8, total_len - 1); // -1 for trailing dot
    var pos: usize = 0;

    for (parts.items, 0..) |part, i| {
        @memcpy(result[pos .. pos + part.len], part);
        pos += part.len;

        if (i < parts.items.len - 1) {
            result[pos] = '.';
            pos += 1;
        }

        allocator.free(part);
    }

    // Clear parts since we freed them in the loop
    parts.clearRetainingCapacity();

    return result;
}

/// Common DNS record types
pub const DnsRecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    OPT = 41,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    CAA = 257,

    pub fn toString(self: DnsRecordType) []const u8 {
        return switch (self) {
            .A => "A",
            .NS => "NS",
            .CNAME => "CNAME",
            .SOA => "SOA",
            .PTR => "PTR",
            .MX => "MX",
            .TXT => "TXT",
            .AAAA => "AAAA",
            .SRV => "SRV",
            .NAPTR => "NAPTR",
            .OPT => "OPT",
            .DS => "DS",
            .RRSIG => "RRSIG",
            .NSEC => "NSEC",
            .DNSKEY => "DNSKEY",
            .NSEC3 => "NSEC3",
            .NSEC3PARAM => "NSEC3PARAM",
            .CAA => "CAA",
        };
    }
};

/// DNS response codes
pub const DnsResponseCode = enum(u4) {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
};

test "DNS message parsing" {
    const allocator = std.testing.allocator;

    // Create a simple DNS query
    var message = DnsMessage.init(allocator);
    defer message.deinit();

    message.header = DnsHeader{
        .id = 0x1234,
        .flags = 0x0100, // Standard query
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    // Add question for "example.com A"
    message.questions = try allocator.alloc(DnsQuestion, 1);
    message.questions[0] = DnsQuestion{
        .name = try allocator.dupe(u8, "example.com"),
        .qtype = @backingInt(DnsRecordType.A),
        .qclass = 1, // IN
    };

    // Serialize and parse back
    const serialized = try message.serializeToStream(allocator);
    defer allocator.free(serialized);

    var parsed = try DnsMessage.parseFromStream(allocator, serialized);
    defer parsed.deinit();

    try std.testing.expect(parsed.header.id == 0x1234);
    try std.testing.expect(parsed.questions.len == 1);
    try std.testing.expectEqualStrings("example.com", parsed.questions[0].name);
}

test "domain name encode/decode roundtrip" {
    const allocator = std.testing.allocator;
    var buffer: [256]u8 = undefined;
    var writer = Io.Writer.fixed(&buffer);

    try encodeDomainName("sub.example.com", allocator, &writer);

    const written = Io.Writer.buffered(&writer);
    var reader = Io.Reader.fixed(written);
    // Pass the written buffer for compression pointer support
    const decoded = try decodeDomainName(allocator, &reader, written);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("sub.example.com", decoded);
}
