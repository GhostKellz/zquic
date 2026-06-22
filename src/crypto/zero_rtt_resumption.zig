//! Zero-RTT Connection Resumption for QUIC
//!
//! Implements 0-RTT session resumption with anti-replay protection
//! Critical for high-frequency crypto trading and DeFi applications

const std = @import("std");
const zcrypto = @import("zcrypto");
const Error = @import("../utils/error.zig");
const Time = @import("../utils/time.zig");

/// Explicit resumption posture for session tickets.
pub const ResumptionPolicy = enum(u8) {
    classical_zero_rtt,
    hybrid_pq_no_early_data,
    hybrid_pq_early_data,

    pub fn allowsEarlyData(self: ResumptionPolicy) bool {
        return switch (self) {
            .classical_zero_rtt, .hybrid_pq_early_data => true,
            .hybrid_pq_no_early_data => false,
        };
    }

    pub fn isPostQuantum(self: ResumptionPolicy) bool {
        return switch (self) {
            .classical_zero_rtt => false,
            .hybrid_pq_no_early_data, .hybrid_pq_early_data => true,
        };
    }
};

/// Local session-ticket issuer used to authenticate resumption tickets.
///
/// Production deployments should persist and rotate this key material. The
/// in-memory default is appropriate for process-local tickets and tests.
pub const TicketIssuer = struct {
    key_id: [8]u8,
    mac_key: [32]u8,

    pub fn initRandom() TicketIssuer {
        var issuer = TicketIssuer{
            .key_id = undefined,
            .mac_key = undefined,
        };
        zcrypto.rand.fill(&issuer.key_id);
        zcrypto.rand.fill(&issuer.mac_key);
        return issuer;
    }

    pub fn initFixed(key_id: [8]u8, mac_key: [32]u8) TicketIssuer {
        return .{
            .key_id = key_id,
            .mac_key = mac_key,
        };
    }

    pub fn deinit(self: *TicketIssuer) void {
        secureZero(&self.mac_key);
    }

    pub fn sign(self: *const TicketIssuer, ticket: *const SessionTicket) [32]u8 {
        var input: [110]u8 = undefined;
        defer secureZero(&input);

        var offset: usize = 0;
        @memcpy(input[offset..][0..8], &self.key_id);
        offset += 8;
        @memcpy(input[offset..][0..16], &ticket.ticket_id);
        offset += 16;
        std.mem.writeInt(i64, input[offset..][0..8], ticket.creation_time, .big);
        offset += 8;
        std.mem.writeInt(i64, input[offset..][0..8], ticket.expiry_time, .big);
        offset += 8;
        @memcpy(input[offset..][0..32], &ticket.resumption_secret);
        offset += 32;
        input[offset] = @intFromEnum(ticket.resumption_policy);
        offset += 1;
        @memcpy(input[offset..][0..32], &ticket.pq_binder);
        offset += 32;
        input[offset] = ticket.early_data_cipher;
        offset += 1;
        std.mem.writeInt(u32, input[offset..][0..4], ticket.max_early_data, .big);
        offset += 4;

        var mac: [32]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.mac_key);
        hmac.update(input[0..offset]);
        hmac.final(&mac);
        return mac;
    }

    pub fn verify(self: *const TicketIssuer, ticket: *const SessionTicket) bool {
        if (!std.mem.eql(u8, &ticket.issuer_key_id, &self.key_id)) return false;
        const expected = self.sign(ticket);
        return std.crypto.timing_safe.eql([32]u8, expected, ticket.ticket_mac);
    }
};

/// Persistable issuer material for deployments that need tickets to survive
/// process restarts or a planned one-key rotation window.
pub const TicketIssuerMaterial = struct {
    key_id: [8]u8,
    mac_key: [32]u8,

    pub fn init(key_id: [8]u8, mac_key: [32]u8) TicketIssuerMaterial {
        return .{
            .key_id = key_id,
            .mac_key = mac_key,
        };
    }
};

/// Active plus optional previous ticket issuer.
///
/// New tickets are always signed by `active`; validation accepts `active` and
/// `previous` so operators can rotate keys without invalidating every live
/// ticket immediately. Keep `previous` only for the maximum ticket lifetime.
pub const TicketIssuerRing = struct {
    active: TicketIssuer,
    previous: ?TicketIssuer = null,

    pub fn initRandom() TicketIssuerRing {
        return .{
            .active = TicketIssuer.initRandom(),
            .previous = null,
        };
    }

    pub fn initFromMaterial(active: TicketIssuerMaterial, previous: ?TicketIssuerMaterial) TicketIssuerRing {
        return .{
            .active = TicketIssuer.initFixed(active.key_id, active.mac_key),
            .previous = if (previous) |material| TicketIssuer.initFixed(material.key_id, material.mac_key) else null,
        };
    }

    pub fn deinit(self: *TicketIssuerRing) void {
        self.active.deinit();
        if (self.previous) |*issuer| issuer.deinit();
    }

    pub fn signer(self: *const TicketIssuerRing) *const TicketIssuer {
        return &self.active;
    }

    pub fn verify(self: *const TicketIssuerRing, ticket: *const SessionTicket) bool {
        if (self.active.verify(ticket)) return true;
        if (self.previous) |issuer| return issuer.verify(ticket);
        return false;
    }
};

/// Session ticket for 0-RTT resumption
pub const SessionTicket = struct {
    ticket_id: [16]u8,
    issuer_key_id: [8]u8,
    creation_time: i64,
    expiry_time: i64,
    resumption_secret: [32]u8,
    resumption_policy: ResumptionPolicy,
    pq_binder: [32]u8,
    early_data_cipher: u8,
    max_early_data: u32,
    ticket_mac: [32]u8,

    const Self = @This();

    pub fn create(
        issuer: *const TicketIssuer,
        resumption_secret: [32]u8,
        lifetime_seconds: i64,
        policy: ResumptionPolicy,
        pq_binder: [32]u8,
        max_early_data: u32,
    ) Self {
        const now = Time.nowSeconds();
        var ticket = Self{
            .ticket_id = undefined,
            .issuer_key_id = issuer.key_id,
            .creation_time = now,
            .expiry_time = now + lifetime_seconds,
            .resumption_secret = resumption_secret,
            .resumption_policy = policy,
            .pq_binder = pq_binder,
            .early_data_cipher = 1, // AES-128-GCM
            .max_early_data = if (policy.allowsEarlyData()) max_early_data else 0,
            .ticket_mac = std.mem.zeroes([32]u8),
        };
        zcrypto.rand.fill(&ticket.ticket_id);
        ticket.ticket_mac = issuer.sign(&ticket);
        return ticket;
    }

    pub fn createPostQuantum(issuer: *const TicketIssuer, hybrid_secret: [64]u8, pq_binder: [32]u8, lifetime_seconds: i64, allow_early_data: bool) Self {
        var input: [96]u8 = undefined;
        @memcpy(input[0..64], &hybrid_secret);
        @memcpy(input[64..96], &pq_binder);
        defer secureZero(&input);

        const resumption_secret = zcrypto.hash.sha256(&input);
        return create(
            issuer,
            resumption_secret,
            lifetime_seconds,
            if (allow_early_data) .hybrid_pq_early_data else .hybrid_pq_no_early_data,
            pq_binder,
            if (allow_early_data) 16_384 else 0,
        );
    }

    pub fn isValid(self: *const Self) bool {
        const now = Time.nowSeconds();
        return now >= self.creation_time and now <= self.expiry_time;
    }

    pub fn isExpired(self: *const Self) bool {
        return Time.nowSeconds() > self.expiry_time;
    }

    pub fn matchesPolicy(self: *const Self, policy: ResumptionPolicy) bool {
        return self.resumption_policy == policy;
    }

    pub fn matchesPostQuantumBinder(self: *const Self, binder: [32]u8) bool {
        if (!self.resumption_policy.isPostQuantum()) return false;
        return std.mem.eql(u8, &self.pq_binder, &binder);
    }

    pub fn isAuthentic(self: *const Self, issuer: *const TicketIssuer) bool {
        return issuer.verify(self);
    }

    pub fn isAuthenticInRing(self: *const Self, issuers: *const TicketIssuerRing) bool {
        return issuers.verify(self);
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
        _ = self.allocator;
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
    sessions: std.AutoArrayHashMapUnmanaged([16]u8, SessionTicket),
    anti_replay: AntiReplayWindow,
    ticket_issuers: TicketIssuerRing,
    max_sessions: u32,
    ticket_lifetime: i64, // seconds
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .sessions = .empty,
            .anti_replay = try AntiReplayWindow.init(allocator, AntiReplayWindow.DEFAULT_WINDOW_SIZE),
            .ticket_issuers = TicketIssuerRing.initRandom(),
            .max_sessions = 10000, // High limit for crypto trading
            .ticket_lifetime = 86400, // 24 hours
            .allocator = allocator,
        };
    }

    pub fn initWithTicketIssuers(allocator: std.mem.Allocator, active: TicketIssuerMaterial, previous: ?TicketIssuerMaterial) !Self {
        return Self{
            .sessions = .empty,
            .anti_replay = try AntiReplayWindow.init(allocator, AntiReplayWindow.DEFAULT_WINDOW_SIZE),
            .ticket_issuers = TicketIssuerRing.initFromMaterial(active, previous),
            .max_sessions = 10000,
            .ticket_lifetime = 86400,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.sessions.deinit(self.allocator);
        self.anti_replay.deinit();
        self.ticket_issuers.deinit();
    }

    /// Create new session ticket for resumption
    pub fn createSessionTicket(self: *Self, resumption_secret: [32]u8) !SessionTicket {
        const ticket = SessionTicket.create(
            self.ticket_issuers.signer(),
            resumption_secret,
            self.ticket_lifetime,
            .classical_zero_rtt,
            std.mem.zeroes([32]u8),
            16_384,
        );
        try self.storeSessionTicket(ticket);

        return ticket;
    }

    pub fn createPostQuantumSessionTicket(self: *Self, hybrid_secret: [64]u8, pq_binder: [32]u8, allow_early_data: bool) !SessionTicket {
        const ticket = SessionTicket.createPostQuantum(self.ticket_issuers.signer(), hybrid_secret, pq_binder, self.ticket_lifetime, allow_early_data);
        try self.storeSessionTicket(ticket);
        return ticket;
    }

    fn storeSessionTicket(self: *Self, ticket: SessionTicket) !void {
        if (self.sessions.count() >= self.max_sessions) {
            try self.cleanupExpiredSessions();
        }
        if (self.sessions.count() < self.max_sessions) {
            try self.sessions.put(self.allocator, ticket.ticket_id, ticket);
        }
    }

    /// Validate session ticket for 0-RTT
    pub fn validateSessionTicket(self: *Self, ticket_id: [16]u8, packet_number: u64) ?SessionTicket {
        const session = self.sessions.get(ticket_id) orelse return null;

        // Check if session is valid
        if (!session.isValid() or !session.isAuthenticInRing(&self.ticket_issuers)) {
            _ = self.sessions.swapRemove(ticket_id);
            return null;
        }

        // Check anti-replay
        if (!self.anti_replay.checkAndUpdate(packet_number)) {
            std.log.warn("0-RTT packet replay detected: ticket={x}, pn={}", .{ ticket_id, packet_number });
            return null;
        }

        return session;
    }

    pub fn validatePostQuantumSessionTicket(self: *Self, ticket_id: [16]u8, packet_number: u64, expected_binder: [32]u8, allow_early_data: bool) ?SessionTicket {
        const expected_policy: ResumptionPolicy = if (allow_early_data) .hybrid_pq_early_data else .hybrid_pq_no_early_data;
        const session = self.validateSessionTicket(ticket_id, packet_number) orelse return null;
        if (!session.matchesPolicy(expected_policy)) return null;
        if (!session.matchesPostQuantumBinder(expected_binder)) return null;
        return session;
    }

    /// Cleanup expired sessions
    pub fn cleanupExpiredSessions(self: *Self) !void {
        var expired_tickets: std.ArrayListUnmanaged([16]u8) = .empty;
        defer expired_tickets.deinit(self.allocator);

        var iterator = self.sessions.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                try expired_tickets.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (expired_tickets.items) |ticket_id| {
            _ = self.sessions.swapRemove(ticket_id);
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
    early_data_buffer: std.ArrayListUnmanaged(u8),
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
            .early_data_buffer = .empty,
            .max_early_data = 16384,
            .early_data_sent = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.early_data_buffer.deinit(self.allocator);
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

        try self.early_data_buffer.appendSlice(self.allocator, data);
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

/// Utility function for secure memory zeroing - uses std.crypto.secureZero
fn secureZero(data: []u8) void {
    std.crypto.secureZero(u8, data);
}

/// Test 0-RTT functionality
pub fn testZeroRtt() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    // Create session manager
    var session_mgr = try ZeroRttSessionManager.init(allocator);
    defer session_mgr.deinit();

    // Create resumption secret
    var resumption_secret: [32]u8 = undefined;
    zcrypto.rand.fill(&resumption_secret);

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

test "PQ resumption ticket disables early data by default and binds PQ material" {
    const allocator = std.testing.allocator;
    var session_mgr = try ZeroRttSessionManager.init(allocator);
    defer session_mgr.deinit();

    var hybrid_secret: [64]u8 = undefined;
    @memset(&hybrid_secret, 0xA5);
    var pq_binder: [32]u8 = undefined;
    @memset(&pq_binder, 0x5A);

    const ticket = try session_mgr.createPostQuantumSessionTicket(hybrid_secret, pq_binder, false);

    try std.testing.expect(ticket.resumption_policy == .hybrid_pq_no_early_data);
    try std.testing.expectEqual(@as(u32, 0), ticket.max_early_data);
    try std.testing.expect(ticket.matchesPostQuantumBinder(pq_binder));
    try std.testing.expect(ticket.isAuthenticInRing(&session_mgr.ticket_issuers));

    const accepted = session_mgr.validatePostQuantumSessionTicket(ticket.ticket_id, 10, pq_binder, false);
    try std.testing.expect(accepted != null);

    var wrong_binder = pq_binder;
    wrong_binder[0] ^= 0xFF;
    try std.testing.expect(session_mgr.validatePostQuantumSessionTicket(ticket.ticket_id, 11, wrong_binder, false) == null);
}

test "PQ resumption ticket rejects tampering and wrong issuer" {
    const allocator = std.testing.allocator;
    var session_mgr = try ZeroRttSessionManager.init(allocator);
    defer session_mgr.deinit();

    var hybrid_secret: [64]u8 = undefined;
    @memset(&hybrid_secret, 0x33);
    var pq_binder: [32]u8 = undefined;
    @memset(&pq_binder, 0x44);

    var ticket = try session_mgr.createPostQuantumSessionTicket(hybrid_secret, pq_binder, false);
    try std.testing.expect(ticket.isAuthenticInRing(&session_mgr.ticket_issuers));

    var tampered_secret = ticket;
    tampered_secret.resumption_secret[0] ^= 0x80;
    try std.testing.expect(!tampered_secret.isAuthenticInRing(&session_mgr.ticket_issuers));

    var tampered_policy = ticket;
    tampered_policy.resumption_policy = .hybrid_pq_early_data;
    try std.testing.expect(!tampered_policy.isAuthenticInRing(&session_mgr.ticket_issuers));

    var wrong_issuers = TicketIssuerRing.initRandom();
    defer wrong_issuers.deinit();
    try std.testing.expect(!ticket.isAuthenticInRing(&wrong_issuers));

    ticket.ticket_mac[0] ^= 0x01;
    try std.testing.expect(!ticket.isAuthenticInRing(&session_mgr.ticket_issuers));
}

test "PQ resumption ticket accepts previous issuer during rotation window" {
    const allocator = std.testing.allocator;
    const old_key_id: [8]u8 = @splat(0x10);
    const old_mac_key: [32]u8 = @splat(0x20);
    const new_key_id: [8]u8 = @splat(0x30);
    const new_mac_key: [32]u8 = @splat(0x40);
    const old_material = TicketIssuerMaterial.init(old_key_id, old_mac_key);
    const new_material = TicketIssuerMaterial.init(new_key_id, new_mac_key);

    var old_mgr = try ZeroRttSessionManager.initWithTicketIssuers(allocator, old_material, null);
    defer old_mgr.deinit();

    var hybrid_secret: [64]u8 = undefined;
    @memset(&hybrid_secret, 0x55);
    var pq_binder: [32]u8 = undefined;
    @memset(&pq_binder, 0x66);

    const old_ticket = try old_mgr.createPostQuantumSessionTicket(hybrid_secret, pq_binder, false);

    var rotated_mgr = try ZeroRttSessionManager.initWithTicketIssuers(allocator, new_material, old_material);
    defer rotated_mgr.deinit();
    try rotated_mgr.storeSessionTicket(old_ticket);

    try std.testing.expect(rotated_mgr.validatePostQuantumSessionTicket(old_ticket.ticket_id, 30, pq_binder, false) != null);

    const new_ticket = try rotated_mgr.createPostQuantumSessionTicket(hybrid_secret, pq_binder, false);
    try std.testing.expect(std.mem.eql(u8, &new_ticket.issuer_key_id, &new_material.key_id));
}

test "PQ resumption ticket policy rejects early-data mismatch" {
    const allocator = std.testing.allocator;
    var session_mgr = try ZeroRttSessionManager.init(allocator);
    defer session_mgr.deinit();

    var hybrid_secret: [64]u8 = undefined;
    @memset(&hybrid_secret, 0x11);
    var pq_binder: [32]u8 = undefined;
    @memset(&pq_binder, 0x22);

    const ticket = try session_mgr.createPostQuantumSessionTicket(hybrid_secret, pq_binder, true);

    try std.testing.expect(ticket.resumption_policy == .hybrid_pq_early_data);
    try std.testing.expect(ticket.max_early_data > 0);
    try std.testing.expect(session_mgr.validatePostQuantumSessionTicket(ticket.ticket_id, 20, pq_binder, false) == null);
    try std.testing.expect(session_mgr.validatePostQuantumSessionTicket(ticket.ticket_id, 21, pq_binder, true) != null);
}
