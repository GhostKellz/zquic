//! DNS-over-QUIC Message Parser (RFC 9250)
//!
//! Implements DoQ message parsing and serialization for stream 0

const std = @import("std");
const Error = @import("../utils/error.zig");

/// DNS message header structure (RFC 1035)
pub const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,  // Number of questions
    ancount: u16,  // Number of answers
    nscount: u16,  // Number of authority records
    arcount: u16,  // Number of additional records

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
            .id = try reader.readInt(u16, .big),
            .flags = try reader.readInt(u16, .flags),
            .qdcount = try reader.readInt(u16, .big),
            .ancount = try reader.readInt(u16, .big),
            .nscount = try reader.readInt(u16, .big),
            .arcount = try reader.readInt(u16, .big),
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

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !DnsQuestion {
        const name = try decodeDomainName(allocator, reader);
        const qtype = try reader.readInt(u16, .big);
        const qclass = try reader.readInt(u16, .big);
        
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

    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !DnsResourceRecord {
        const name = try decodeDomainName(allocator, reader);
        const rtype = try reader.readInt(u16, .big);
        const rclass = try reader.readInt(u16, .big);
        const ttl = try reader.readInt(u32, .big);
        const rdlength = try reader.readInt(u16, .big);
        
        const rdata = try allocator.alloc(u8, rdlength);
        _ = try reader.readAll(rdata);
        
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
    pub fn parseFromStream(allocator: std.mem.Allocator, data: []const u8) !DnsMessage {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        // Parse DNS header
        const header = try DnsHeader.decode(reader);
        
        var message = DnsMessage.init(allocator);
        message.header = header;

        // Parse questions
        if (header.qdcount > 0) {
            message.questions = try allocator.alloc(DnsQuestion, header.qdcount);
            for (0..header.qdcount) |i| {
                message.questions[i] = try DnsQuestion.decode(allocator, reader);
            }
        }

        // Parse answers
        if (header.ancount > 0) {
            message.answers = try allocator.alloc(DnsResourceRecord, header.ancount);
            for (0..header.ancount) |i| {
                message.answers[i] = try DnsResourceRecord.decode(allocator, reader);
            }
        }

        // Parse authority records
        if (header.nscount > 0) {
            message.authority = try allocator.alloc(DnsResourceRecord, header.nscount);
            for (0..header.nscount) |i| {
                message.authority[i] = try DnsResourceRecord.decode(allocator, reader);
            }
        }

        // Parse additional records
        if (header.arcount > 0) {
            message.additional = try allocator.alloc(DnsResourceRecord, header.arcount);
            for (0..header.arcount) |i| {
                message.additional[i] = try DnsResourceRecord.decode(allocator, reader);
            }
        }

        return message;
    }

    /// Serialize DoQ message for QUIC stream 0 (RFC 9250)
    pub fn serializeToStream(self: *const DnsMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        
        const writer = buffer.writer();

        // Write header
        try self.header.encode(writer);

        // Write questions
        for (self.questions) |question| {
            try question.encode(allocator, writer);
        }

        // Write answers
        for (self.answers) |answer| {
            try answer.encode(allocator, writer);
        }

        // Write authority records
        for (self.authority) |auth| {
            try auth.encode(allocator, writer);
        }

        // Write additional records
        for (self.additional) |add| {
            try add.encode(allocator, writer);
        }

        return try buffer.toOwnedSlice();
    }
};

/// Encode domain name in DNS wire format
fn encodeDomainName(name: []const u8, _: std.mem.Allocator, writer: anytype) !void {
    var parts = std.mem.splitScalar(u8, name, '.');
    
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        if (part.len > 63) return Error.ZquicError.InvalidDomainName;
        
        try writer.writeByte(@intCast(part.len));
        try writer.writeAll(part);
    }
    
    // Null terminator
    try writer.writeByte(0);
}

/// Decode domain name from DNS wire format
fn decodeDomainName(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var parts = std.ArrayList([]const u8).init(allocator);
    defer parts.deinit();
    
    while (true) {
        const length = try reader.readByte();
        if (length == 0) break;
        
        if (length > 63) return Error.ZquicError.InvalidDomainName;
        
        const part = try allocator.alloc(u8, length);
        _ = try reader.readAll(part);
        try parts.append(part);
    }
    
    if (parts.items.len == 0) {
        return try allocator.dupe(u8, ".");
    }
    
    // Join parts with dots
    var total_len: usize = 0;
    for (parts.items) |part| {
        total_len += part.len + 1; // +1 for dot
    }
    
    var result = try allocator.alloc(u8, total_len - 1); // -1 for trailing dot
    var pos: usize = 0;
    
    for (parts.items, 0..) |part, i| {
        std.mem.copyForwards(u8, result[pos..pos + part.len], part);
        pos += part.len;
        
        if (i < parts.items.len - 1) {
            result[pos] = '.';
            pos += 1;
        }
        
        allocator.free(part);
    }
    
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
        .qtype = @intFromEnum(DnsRecordType.A),
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