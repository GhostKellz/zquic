//! Zero-RTT Connection Resumption for QUIC
//!
//! Implements 0-RTT session resumption with anti-replay protection
//! Critical for high-frequency crypto trading and DeFi applications

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");

/// Session ticket for 0-RTT resumption
pub const SessionTicket = struct {
    ticket_id: [16]u8,
    creation_time: i64,
    expiry_time: i64,
    resumption_secret: [32]u8,
    early_data_cipher: u8,
    max_early_data: u32,
    
    const Self = @This();
    
    pub fn isValid(self: *const Self) bool {
        const now = std.time.timestamp();
        return now >= self.creation_time and now <= self.expiry_time;
    }
    
    pub fn isExpired(self: *const Self) bool {
        return std.time.timestamp() > self.expiry_time;
    }
};

/// Anti-replay protection using sliding window
pub const AntiReplayWindow = struct {
    window_size: u32,
    window_start: u64,
    received_packets: std.DynamicBitSet,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    const DEFAULT_WINDOW_SIZE = 1024;
    
    pub fn init(allocator: std.mem.Allocator, window_size: u32) !Self {
        return Self{
            .window_size = window_size,
            .window_start = 0,
            .received_packets = try std.DynamicBitSet.initEmpty(allocator, window_size),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.received_packets.deinit();
    }
    
    /// Check if packet number is duplicate and update window
    pub fn checkAndUpdate(self: *Self, packet_number: u64) bool {
        // Check if packet is too old
        if (packet_number < self.window_start) {
            return false; // Duplicate/replay
        }
        
        // Check if packet is within current window
        if (packet_number < self.window_start + self.window_size) {
            const bit_index = @as(u32, @intCast(packet_number - self.window_start));
            if (self.received_packets.isSet(bit_index)) {
                return false; // Duplicate
            }
            self.received_packets.set(bit_index);
            return true; // Valid new packet
        }
        
        // Packet is beyond current window - slide window forward
        const slide_amount = packet_number - (self.window_start + self.window_size - 1);
        self.slideWindow(slide_amount);
        
        // Set bit for new packet
        const bit_index = @as(u32, @intCast(packet_number - self.window_start));
        self.received_packets.set(bit_index);
        return true;
    }
    
    fn slideWindow(self: *Self, slide_amount: u64) void {
        if (slide_amount >= self.window_size) {
            // Slide entire window
            self.window_start += slide_amount;
            self.received_packets.setRangeValue(.{ .start = 0, .end = self.window_size }, false);
        } else {
            // Slide partial window
            const slide_u32 = @as(u32, @intCast(slide_amount));
            self.window_start += slide_amount;
            
            // Shift bits left
            var i: u32 = 0;
            while (i < self.window_size - slide_u32) : (i += 1) {
                const old_bit = self.received_packets.isSet(i + slide_u32);
                self.received_packets.setValue(i, old_bit);
            }
            
            // Clear the new bits
            self.received_packets.setRangeValue(.{ .start = self.window_size - slide_u32, .end = self.window_size }, false);
        }
    }
};

/// Zero-RTT session manager
pub const ZeroRttSessionManager = struct {
    sessions: std.HashMap([16]u8, SessionTicket, ArrayHashContext, std.hash_map.default_max_load_percentage),
    anti_replay: AntiReplayWindow,
    max_sessions: u32,
    ticket_lifetime: i64, // seconds
    allocator: std.mem.Allocator,
    
    const Self = @This();
    const ArrayHashContext = struct {
        pub fn hash(self: @This(), key: [16]u8) u64 {
            _ = self;
            return std.hash_map.hashString(std.mem.asBytes(&key));
        }
        
        pub fn eql(self: @This(), a: [16]u8, b: [16]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .sessions = std.HashMap([16]u8, SessionTicket, ArrayHashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .anti_replay = try AntiReplayWindow.init(allocator, AntiReplayWindow.DEFAULT_WINDOW_SIZE),
            .max_sessions = 10000, // High limit for crypto trading
            .ticket_lifetime = 86400, // 24 hours
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.sessions.deinit();
        self.anti_replay.deinit();
    }
    
    /// Create new session ticket for resumption
    pub fn createSessionTicket(self: *Self, resumption_secret: [32]u8) !SessionTicket {
        var ticket = SessionTicket{
            .ticket_id = undefined,
            .creation_time = std.time.timestamp(),
            .expiry_time = std.time.timestamp() + self.ticket_lifetime,
            .resumption_secret = resumption_secret,
            .early_data_cipher = 1, // AES-128-GCM
            .max_early_data = 16384, // 16KB for trading data
        };
        
        // Generate secure random ticket ID
        try zcrypto.rand.bytes(&ticket.ticket_id);
        
        // Store session if we have space
        if (self.sessions.count() < self.max_sessions) {
            try self.sessions.put(ticket.ticket_id, ticket);
        } else {
            // Cleanup expired sessions first
            try self.cleanupExpiredSessions();
            if (self.sessions.count() < self.max_sessions) {
                try self.sessions.put(ticket.ticket_id, ticket);
            }
        }
        
        return ticket;
    }
    
    /// Validate session ticket for 0-RTT
    pub fn validateSessionTicket(self: *Self, ticket_id: [16]u8, packet_number: u64) ?SessionTicket {
        const session = self.sessions.get(ticket_id) orelse return null;
        
        // Check if session is valid
        if (!session.isValid()) {
            _ = self.sessions.remove(ticket_id);
            return null;
        }
        
        // Check anti-replay
        if (!self.anti_replay.checkAndUpdate(packet_number)) {
            std.log.warn("0-RTT packet replay detected: ticket={x}, pn={}", .{ ticket_id, packet_number });
            return null;
        }
        
        return session;
    }
    
    /// Cleanup expired sessions
    pub fn cleanupExpiredSessions(self: *Self) !void {
        var expired_tickets = std.ArrayList([16]u8).init(self.allocator);
        defer expired_tickets.deinit();
        
        var iterator = self.sessions.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                try expired_tickets.append(entry.key_ptr.*);
            }
        }
        
        for (expired_tickets.items) |ticket_id| {
            _ = self.sessions.remove(ticket_id);
        }
        
        std.log.info("Cleaned up {} expired 0-RTT sessions", .{expired_tickets.items.len});
    }
    
    /// Get session statistics
    pub fn getStats(self: *const Self) struct { active_sessions: u32, window_start: u64 } {
        return .{
            .active_sessions = @as(u32, @intCast(self.sessions.count())),
            .window_start = self.anti_replay.window_start,
        };
    }
};

/// Zero-RTT context for connections
pub const ZeroRttContext = struct {
    is_early_data: bool,
    early_data_accepted: bool,
    early_data_rejected: bool,
    session_ticket: ?SessionTicket,
    early_data_buffer: std.ArrayList(u8),
    max_early_data: u32,
    early_data_sent: u32,
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .is_early_data = false,
            .early_data_accepted = false,
            .early_data_rejected = false,
            .session_ticket = null,
            .early_data_buffer = std.ArrayList(u8).init(allocator),
            .max_early_data = 16384,
            .early_data_sent = 0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.early_data_buffer.deinit();
        if (self.session_ticket) |*ticket| {
            secureZero(std.mem.asBytes(&ticket.resumption_secret));
        }
    }
    
    /// Start 0-RTT with session ticket
    pub fn startEarlyData(self: *Self, ticket: SessionTicket) !void {
        self.session_ticket = ticket;
        self.is_early_data = true;
        self.max_early_data = ticket.max_early_data;
        
        std.log.info("Starting 0-RTT early data (max: {} bytes)", .{self.max_early_data});
    }
    
    /// Write early data
    pub fn writeEarlyData(self: *Self, data: []const u8) !bool {
        if (!self.is_early_data or self.early_data_rejected) {
            return false;
        }
        
        if (self.early_data_sent + data.len > self.max_early_data) {
            return false; // Would exceed limit
        }
        
        try self.early_data_buffer.appendSlice(data);
        self.early_data_sent += @as(u32, @intCast(data.len));
        
        return true;
    }
    
    /// Accept early data (server side)
    pub fn acceptEarlyData(self: *Self) void {
        self.early_data_accepted = true;
        std.log.info("Server accepted 0-RTT early data ({} bytes)", .{self.early_data_sent});
    }
    
    /// Reject early data (server side)
    pub fn rejectEarlyData(self: *Self) void {
        self.early_data_rejected = true;
        self.early_data_buffer.clearRetainingCapacity();
        std.log.warn("Server rejected 0-RTT early data");
    }
    
    /// Get early data buffer
    pub fn getEarlyData(self: *const Self) []const u8 {
        return self.early_data_buffer.items;
    }
    
    /// Check if 0-RTT is available
    pub fn canUseEarlyData(self: *const Self) bool {
        return self.session_ticket != null and 
               self.session_ticket.?.isValid() and 
               !self.early_data_rejected;
    }
};

/// Utility function for secure memory zeroing
fn secureZero(data: []u8) void {
    @memset(data, 0);
    asm volatile ("" : : [data] "m" (data) : "memory");
}

/// Test 0-RTT functionality
pub fn testZeroRtt() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create session manager
    var session_mgr = try ZeroRttSessionManager.init(allocator);
    defer session_mgr.deinit();
    
    // Create resumption secret
    var resumption_secret: [32]u8 = undefined;
    try zcrypto.rand.bytes(&resumption_secret);
    
    // Create session ticket
    const ticket = try session_mgr.createSessionTicket(resumption_secret);
    
    // Create 0-RTT context
    var zero_rtt = ZeroRttContext.init(allocator);
    defer zero_rtt.deinit();
    
    // Start early data
    try zero_rtt.startEarlyData(ticket);
    
    // Write some early data (simulating trading order)
    const trading_data = "BUY,ETH,100,@3500";
    const success = try zero_rtt.writeEarlyData(trading_data);
    
    if (!success) {
        return Error.ZquicError.InvalidState;
    }
    
    // Validate ticket
    const validated_ticket = session_mgr.validateSessionTicket(ticket.ticket_id, 12345);
    if (validated_ticket == null) {
        return Error.ZquicError.CryptoError;
    }
    
    // Accept early data
    zero_rtt.acceptEarlyData();
    
    const stats = session_mgr.getStats();
    std.log.info("0-RTT test passed! Active sessions: {}, Early data: {s}", .{ stats.active_sessions, zero_rtt.getEarlyData() });
}