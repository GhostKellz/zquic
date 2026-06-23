//! QUIC Packet Number Spaces
//!
//! Implements the three QUIC packet number spaces:
//! - Initial: For initial connection establishment
//! - Handshake: For TLS handshake completion
//! - Application: For 1-RTT protected application data
//!
//! Each space maintains its own packet number sequence and crypto state.

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QUIC packet number space types
pub const PacketSpaceType = enum {
    initial,
    handshake,
    application,

    pub fn toString(self: PacketSpaceType) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .handshake => "Handshake",
            .application => "Application",
        };
    }
};

/// Packet number within a space (62-bit integer)
pub const PacketNumber = u62;

/// Maximum packet number value
pub const MAX_PACKET_NUMBER: PacketNumber = (1 << 62) - 1;

/// Packet number space state
pub const PacketSpaceState = enum(u8) {
    /// Space is ready for use
    active,
    /// Space is being discarded
    discarding,
    /// Space has been discarded
    discarded,
};

/// Sent packet information for loss detection
pub const SentPacket = struct {
    packet_number: PacketNumber,
    time_sent: u64, // Timestamp in microseconds
    ack_eliciting: bool,
    in_flight: bool,
    sent_bytes: usize,

    /// Check if packet is considered lost based on time threshold
    pub fn isTimeLost(self: SentPacket, now: u64, time_threshold: u64) bool {
        return self.time_sent + time_threshold < now;
    }

    /// Check if packet is considered lost based on packet number threshold
    pub fn isPacketLost(self: SentPacket, largest_acked: PacketNumber, packet_threshold: u32) bool {
        return self.packet_number + packet_threshold <= largest_acked;
    }
};

/// Acknowledgment range, inclusive.
pub const AckRange = struct {
    start: PacketNumber,
    end: PacketNumber,
};

/// Result of processing ACK ranges in a packet number space.
pub const AckResult = struct {
    newly_acked_count: usize = 0,
    newly_acked_bytes: u64 = 0,
    largest_newly_acked: ?PacketNumber = null,
    largest_newly_acked_time: u64 = 0,
};

/// Aggregate information for packets declared lost.
pub const LostPacketStats = struct {
    lost_count: usize = 0,
    lost_bytes: u64 = 0,
    largest_lost_time: u64 = 0,
};

/// QUIC Packet Number Space
pub const PacketSpace = struct {
    /// Space type identifier
    space_type: PacketSpaceType,

    /// Current state of this space
    state: PacketSpaceState,

    /// Next packet number to assign
    next_packet_number: PacketNumber,

    /// Largest packet number sent in this space
    largest_sent_packet: ?PacketNumber,

    /// Largest packet number acknowledged by peer
    largest_acked_packet: ?PacketNumber,

    /// Time when largest acked packet was acknowledged
    largest_acked_time: u64,

    /// Sent packets awaiting acknowledgment
    sent_packets: std.AutoHashMapUnmanaged(PacketNumber, SentPacket),

    /// Allocator for packet space operations
    allocator: std.mem.Allocator,

    /// Loss detection timer
    loss_detection_timer: ?u64,

    /// PTO (Probe Timeout) count
    pto_count: u32,

    /// Time of last ack-eliciting packet sent
    time_of_last_ack_eliciting_packet: u64,

    const Self = @This();

    /// Initialize a new packet space
    pub fn init(allocator: std.mem.Allocator, space_type: PacketSpaceType) !Self {
        return Self{
            .space_type = space_type,
            .state = .active,
            .next_packet_number = 0,
            .largest_sent_packet = null,
            .largest_acked_packet = null,
            .largest_acked_time = 0,
            .sent_packets = .empty,
            .allocator = allocator,
            .loss_detection_timer = null,
            .pto_count = 0,
            .time_of_last_ack_eliciting_packet = 0,
        };
    }

    /// Cleanup packet space resources
    pub fn deinit(self: *Self) void {
        self.sent_packets.deinit(self.allocator);
    }

    /// Get the next packet number and increment counter
    pub fn nextPacketNumber(self: *Self) PacketNumber {
        const pn = self.next_packet_number;
        self.next_packet_number += 1;
        return pn;
    }

    /// Record a sent packet for loss detection
    pub fn onPacketSent(
        self: *Self,
        packet_number: PacketNumber,
        time_sent: u64,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
    ) !void {
        const sent_packet = SentPacket{
            .packet_number = packet_number,
            .time_sent = time_sent,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .sent_bytes = sent_bytes,
        };

        try self.sent_packets.put(self.allocator, packet_number, sent_packet);

        if (ack_eliciting) {
            self.time_of_last_ack_eliciting_packet = time_sent;
        }

        self.largest_sent_packet = if (self.largest_sent_packet) |largest|
            @max(largest, packet_number)
        else
            packet_number;
    }

    /// Process acknowledgment of packets.
    ///
    /// ACK ranges that reference packet numbers never sent in this packet
    /// number space are protocol violations. Ranges are inclusive.
    pub fn processAck(
        self: *Self,
        acked_ranges: []const AckRange,
        ack_delay: u64,
        now: u64,
    ) Error.ZquicError!AckResult {
        _ = ack_delay; // Applied by LossRecovery when updating RTT.
        if (self.state != .active) return Error.ZquicError.InvalidState;

        var result = AckResult{};
        var newly_acked_packets = std.array_list.Managed(PacketNumber).init(self.allocator);
        defer newly_acked_packets.deinit();

        try self.validateAckRanges(acked_ranges);

        // Find newly acknowledged packets.
        for (acked_ranges) |range| {
            var pn = range.start;
            while (pn <= range.end) : (pn += 1) {
                if (self.sent_packets.get(pn)) |packet| {
                    try newly_acked_packets.append(pn);
                    result.newly_acked_count += 1;
                    if (packet.in_flight) {
                        result.newly_acked_bytes += packet.sent_bytes;
                    }

                    if (result.largest_newly_acked == null or pn > result.largest_newly_acked.?) {
                        result.largest_newly_acked = pn;
                        result.largest_newly_acked_time = packet.time_sent;
                    }

                    if (self.largest_acked_packet == null or pn > self.largest_acked_packet.?) {
                        self.largest_acked_packet = pn;
                        self.largest_acked_time = now;
                    }
                }
            }
        }

        for (newly_acked_packets.items) |pn| {
            _ = self.sent_packets.remove(pn);
        }

        if (result.newly_acked_count > 0) {
            self.pto_count = 0;
        }

        return result;
    }

    /// Backward-compatible ACK handler for older call sites.
    pub fn onAckReceived(
        self: *Self,
        acked_ranges: []const AckRange,
        ack_delay: u64,
        now: u64,
    ) void {
        _ = self.processAck(acked_ranges, ack_delay, now) catch return;
    }

    fn validateAckRanges(self: *const Self, acked_ranges: []const AckRange) Error.ZquicError!void {
        const largest_sent = self.largest_sent_packet orelse {
            if (acked_ranges.len == 0) return;
            return Error.ZquicError.ProtocolViolation;
        };

        for (acked_ranges, 0..) |range, i| {
            if (range.start > range.end) {
                return Error.ZquicError.ProtocolViolation;
            }
            if (range.end > largest_sent) {
                return Error.ZquicError.ProtocolViolation;
            }

            var j: usize = i + 1;
            while (j < acked_ranges.len) : (j += 1) {
                const other = acked_ranges[j];
                const overlaps = range.start <= other.end and other.start <= range.end;
                if (overlaps) {
                    return Error.ZquicError.ProtocolViolation;
                }
            }
        }
    }

    /// Return byte/time accounting for packets about to be declared lost.
    pub fn lostPacketStats(self: *const Self, lost_packets: []const PacketNumber) LostPacketStats {
        var stats = LostPacketStats{};
        for (lost_packets) |pn| {
            if (self.sent_packets.get(pn)) |packet| {
                stats.lost_count += 1;
                if (packet.in_flight) {
                    stats.lost_bytes += packet.sent_bytes;
                }
                stats.largest_lost_time = @max(stats.largest_lost_time, packet.time_sent);
            }
        }
        return stats;
    }

    /// Detect lost packets based on time and packet number thresholds
    pub fn detectLostPackets(
        self: *Self,
        now: u64,
        time_threshold: u64,
        packet_threshold: u32,
    ) std.ArrayList(PacketNumber) {
        var lost_packets: std.ArrayList(PacketNumber) = .empty;

        if (self.largest_acked_packet == null) {
            return lost_packets;
        }

        const largest_acked = self.largest_acked_packet.?;

        var iterator = self.sent_packets.iterator();
        while (iterator.next()) |entry| {
            const packet = entry.value_ptr.*;

            // Check time-based loss detection
            const time_lost = packet.isTimeLost(now, time_threshold);

            // Check packet-based loss detection
            const packet_lost = packet.isPacketLost(largest_acked, packet_threshold);

            if (time_lost or packet_lost) {
                lost_packets.append(self.allocator, packet.packet_number) catch continue;
            }
        }

        return lost_packets;
    }

    /// Remove lost packets from sent packets tracking
    pub fn onPacketsLost(self: *Self, lost_packets: []const PacketNumber) void {
        for (lost_packets) |pn| {
            _ = self.sent_packets.remove(pn);
        }
    }

    /// Check if there are any in-flight packets
    pub fn hasInFlightPackets(self: Self) bool {
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                return true;
            }
        }
        return false;
    }

    /// Get count of in-flight bytes
    pub fn bytesInFlight(self: Self) usize {
        var bytes: usize = 0;
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                bytes += packet.sent_bytes;
            }
        }
        return bytes;
    }

    /// Mark space for discarding (used when transitioning crypto states)
    pub fn markForDiscard(self: *Self) void {
        self.state = .discarding;
    }

    /// Complete discarding of space
    pub fn discard(self: *Self) void {
        self.state = .discarded;
        self.sent_packets.clearAndFree(self.allocator);
    }

    /// Check if space is active
    pub fn isActive(self: Self) bool {
        return self.state == .active;
    }

    /// Get time of earliest in-flight packet (for PTO calculation)
    pub fn getEarliestInFlightTime(self: Self) ?u64 {
        var earliest: ?u64 = null;
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                if (earliest == null or packet.time_sent < earliest.?) {
                    earliest = packet.time_sent;
                }
            }
        }
        return earliest;
    }
};

/// Manager for all three packet number spaces
pub const PacketSpaceManager = struct {
    /// Initial packet space
    initial: PacketSpace,

    /// Handshake packet space
    handshake: PacketSpace,

    /// Application packet space
    application: PacketSpace,

    /// Allocator for space management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize packet space manager
    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .initial = try PacketSpace.init(allocator, .initial),
            .handshake = try PacketSpace.init(allocator, .handshake),
            .application = try PacketSpace.init(allocator, .application),
            .allocator = allocator,
        };
    }

    /// Cleanup all packet spaces
    pub fn deinit(self: *Self) void {
        self.initial.deinit();
        self.handshake.deinit();
        self.application.deinit();
    }

    /// Get packet space by type
    pub fn getSpace(self: *Self, space_type: PacketSpaceType) *PacketSpace {
        return switch (space_type) {
            .initial => &self.initial,
            .handshake => &self.handshake,
            .application => &self.application,
        };
    }

    /// Discard initial and handshake spaces when handshake completes
    pub fn discardHandshakeSpaces(self: *Self) void {
        self.initial.discard();
        self.handshake.discard();
    }

    /// Get total bytes in flight across all active spaces
    pub fn totalBytesInFlight(self: Self) usize {
        var total: usize = 0;
        if (self.initial.isActive()) {
            total += self.initial.bytesInFlight();
        }
        if (self.handshake.isActive()) {
            total += self.handshake.bytesInFlight();
        }
        if (self.application.isActive()) {
            total += self.application.bytesInFlight();
        }
        return total;
    }

    /// Check if any space has in-flight packets
    pub fn hasAnyInFlightPackets(self: Self) bool {
        return (self.initial.isActive() and self.initial.hasInFlightPackets()) or
            (self.handshake.isActive() and self.handshake.hasInFlightPackets()) or
            (self.application.isActive() and self.application.hasInFlightPackets());
    }
};

// Tests
test "packet space basic operations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var space = try PacketSpace.init(allocator, .initial);
    defer space.deinit();

    // Test packet number generation
    try std.testing.expectEqual(@as(PacketNumber, 0), space.nextPacketNumber());
    try std.testing.expectEqual(@as(PacketNumber, 1), space.nextPacketNumber());
    try std.testing.expectEqual(@as(PacketNumber, 2), space.nextPacketNumber());

    // Test packet tracking
    try space.onPacketSent(0, 1000, true, true, 1200);
    try space.onPacketSent(1, 2000, true, true, 1200);

    try std.testing.expect(space.hasInFlightPackets());
    try std.testing.expectEqual(@as(usize, 2400), space.bytesInFlight());
}

test "packet space manager" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var manager = try PacketSpaceManager.init(allocator);
    defer manager.deinit();

    // Test space access
    const initial_space = manager.getSpace(.initial);
    try std.testing.expectEqual(PacketSpaceType.initial, initial_space.space_type);

    const handshake_space = manager.getSpace(.handshake);
    try std.testing.expectEqual(PacketSpaceType.handshake, handshake_space.space_type);

    const app_space = manager.getSpace(.application);
    try std.testing.expectEqual(PacketSpaceType.application, app_space.space_type);

    // Test discarding handshake spaces
    manager.discardHandshakeSpaces();
    try std.testing.expect(!initial_space.isActive());
    try std.testing.expect(!handshake_space.isActive());
    try std.testing.expect(app_space.isActive());
}

test "packet space acknowledgments and loss detection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var space = try PacketSpace.init(allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);
    try space.onPacketSent(2, 3_000, true, true, 1200);

    const ack_first = [_]AckRange{.{ .start = 0, .end = 0 }};
    space.onAckReceived(&ack_first, 0, 4_000);
    try std.testing.expectEqual(@as(PacketNumber, 0), space.largest_acked_packet.?);
    try std.testing.expectEqual(@as(usize, 2), space.sent_packets.count());

    const ack_latest = [_]AckRange{.{ .start = 2, .end = 2 }};
    space.onAckReceived(&ack_latest, 0, 5_000);
    try std.testing.expectEqual(@as(PacketNumber, 2), space.largest_acked_packet.?);

    var lost = space.detectLostPackets(6_000, 500, 1);
    defer lost.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), lost.items.len);
    try std.testing.expectEqual(@as(PacketNumber, 1), lost.items[0]);

    space.onPacketsLost(lost.items);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
}

test "packet space rejects invalid ack ranges" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);

    const reversed = [_]AckRange{.{ .start = 1, .end = 0 }};
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&reversed, 0, 3_000));

    const unsent = [_]AckRange{.{ .start = 2, .end = 2 }};
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&unsent, 0, 3_000));

    const overlapping = [_]AckRange{
        .{ .start = 0, .end = 1 },
        .{ .start = 1, .end = 1 },
    };
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&overlapping, 0, 3_000));
}

test "packet space reports actual newly acked bytes" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 100);
    try space.onPacketSent(1, 2_000, true, true, 200);
    try space.onPacketSent(2, 3_000, true, false, 300);

    const ack = [_]AckRange{.{ .start = 0, .end = 2 }};
    const result = try space.processAck(&ack, 0, 4_000);

    try std.testing.expectEqual(@as(usize, 3), result.newly_acked_count);
    try std.testing.expectEqual(@as(u64, 300), result.newly_acked_bytes);
    try std.testing.expectEqual(@as(PacketNumber, 2), result.largest_newly_acked.?);
    try std.testing.expectEqual(@as(u64, 3_000), result.largest_newly_acked_time);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
}
