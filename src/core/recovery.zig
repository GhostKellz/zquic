//! QUIC Loss Detection and Congestion Control
//!
//! Implements RFC 9002 - QUIC Loss Detection and Congestion Control
//! Features:
//! - Loss detection with time and packet thresholds
//! - Probe Timeout (PTO) mechanism
//! - NewReno congestion control
//! - RTT estimation and smoothing
//! - Persistent congestion detection

const std = @import("std");
const Error = @import("../utils/error.zig");
const PacketSpace = @import("packet_space.zig").PacketSpace;
const PacketNumber = @import("packet_space.zig").PacketNumber;
const AckRange = @import("packet_space.zig").AckRange;

/// RTT constants (in microseconds)
pub const RTT_CONSTANTS = struct {
    /// Initial RTT estimate (500ms)
    pub const INITIAL_RTT: u64 = 500_000;

    /// Granularity for timer calculations (1ms)
    pub const GRANULARITY: u64 = 1_000;

    /// Maximum ack delay value (25ms)
    pub const MAX_ACK_DELAY: u64 = 25_000;

    /// RTT variation multiplier for PTO calculation
    pub const K_GRANULARITY: u32 = 4;

    /// Loss time threshold multiplier
    pub const K_TIME_THRESHOLD: f64 = 9.0 / 8.0;

    /// Packet threshold for packet-based loss detection
    pub const K_PACKET_THRESHOLD: u32 = 3;

    /// Persistent congestion threshold (3 * PTO)
    pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;
};

/// Congestion control constants
pub const CC_CONSTANTS = struct {
    /// Initial congestion window (10 * MSS)
    pub const INITIAL_WINDOW: u64 = 14720;

    /// Minimum congestion window (2 * MSS)
    pub const MIN_WINDOW: u64 = 2944;

    /// Maximum datagram size
    pub const MAX_DATAGRAM_SIZE: u64 = 1472;

    /// Loss reduction factor
    pub const LOSS_REDUCTION_FACTOR: f64 = 0.5;
};

/// RTT measurements and statistics
pub const RttStats = struct {
    /// Smoothed RTT estimate
    smoothed_rtt: u64,

    /// RTT variation estimate
    rttvar: u64,

    /// Latest RTT measurement
    latest_rtt: u64,

    /// Minimum RTT observed
    min_rtt: u64,

    /// Maximum ack delay observed
    max_ack_delay: u64,

    const Self = @This();

    /// Initialize RTT statistics
    pub fn init() Self {
        return Self{
            .smoothed_rtt = RTT_CONSTANTS.INITIAL_RTT,
            .rttvar = RTT_CONSTANTS.INITIAL_RTT / 2,
            .latest_rtt = 0,
            .min_rtt = std.math.maxInt(u64),
            .max_ack_delay = RTT_CONSTANTS.MAX_ACK_DELAY,
        };
    }

    /// Update RTT statistics with new measurement
    pub fn updateRtt(self: *Self, ack_delay: u64, latest_rtt: u64, now: u64) void {
        _ = now; // TODO: Use for timestamp validation

        self.latest_rtt = latest_rtt;
        self.min_rtt = @min(self.min_rtt, latest_rtt);

        // Adjust for ack delay if reasonable
        var adjusted_rtt = latest_rtt;
        if (latest_rtt >= self.min_rtt + ack_delay and ack_delay <= self.max_ack_delay) {
            adjusted_rtt = latest_rtt - ack_delay;
        }

        // First RTT measurement
        if (self.smoothed_rtt == RTT_CONSTANTS.INITIAL_RTT and self.rttvar == RTT_CONSTANTS.INITIAL_RTT / 2) {
            self.smoothed_rtt = adjusted_rtt;
            self.rttvar = adjusted_rtt / 2;
            return;
        }

        // Update smoothed RTT and variation
        const rttvar_sample = if (self.smoothed_rtt > adjusted_rtt)
            self.smoothed_rtt - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt;

        self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) / 8;
    }

    /// Calculate Probe Timeout (PTO) duration
    pub fn calculatePto(self: Self, pto_count: u32) u64 {
        const base_pto = self.smoothed_rtt +
            @max(RTT_CONSTANTS.K_GRANULARITY * self.rttvar, RTT_CONSTANTS.GRANULARITY) +
            self.max_ack_delay;
        return base_pto << @intCast(pto_count);
    }

    /// Get time threshold for loss detection
    pub fn lossTimeThreshold(self: Self) u64 {
        return @intFromFloat(@as(f64, @floatFromInt(@max(self.latest_rtt, self.smoothed_rtt))) * RTT_CONSTANTS.K_TIME_THRESHOLD);
    }
};

/// Congestion control state
pub const CongestionController = struct {
    /// Current congestion window
    congestion_window: u64,

    /// Slow start threshold
    ssthresh: u64,

    /// Bytes acknowledged since last congestion event
    bytes_acked_since_congestion: u64,

    /// Time of last congestion event
    congestion_recovery_start_time: u64,

    /// Whether in slow start phase
    in_slow_start: bool,

    const Self = @This();

    /// Initialize congestion controller
    pub fn init() Self {
        return Self{
            .congestion_window = CC_CONSTANTS.INITIAL_WINDOW,
            .ssthresh = std.math.maxInt(u64),
            .bytes_acked_since_congestion = 0,
            .congestion_recovery_start_time = 0,
            .in_slow_start = true,
        };
    }

    /// Process acknowledgment for congestion control
    pub fn onAckReceived(
        self: *Self,
        acked_bytes: u64,
        largest_acked_time: u64,
        now: u64,
    ) void {
        _ = now; // TODO: Use for timing validation

        // Don't increase window during recovery period
        if (largest_acked_time <= self.congestion_recovery_start_time) {
            return;
        }

        if (self.in_slow_start) {
            // Slow start: increase cwnd by bytes acked
            self.congestion_window += acked_bytes;

            // Exit slow start when cwnd >= ssthresh
            if (self.congestion_window >= self.ssthresh) {
                self.in_slow_start = false;
            }
        } else {
            // Congestion avoidance: increase cwnd by MSS per RTT
            self.bytes_acked_since_congestion += acked_bytes;
            if (self.bytes_acked_since_congestion >= self.congestion_window) {
                self.bytes_acked_since_congestion -= self.congestion_window;
                self.congestion_window += CC_CONSTANTS.MAX_DATAGRAM_SIZE;
            }
        }
    }

    /// Process packet loss for congestion control
    pub fn onPacketsLost(self: *Self, lost_bytes: u64, largest_lost_time: u64) void {
        // Avoid multiple reductions for the same congestion event
        if (largest_lost_time <= self.congestion_recovery_start_time) {
            return;
        }

        self.congestion_recovery_start_time = largest_lost_time;

        // Reduce congestion window
        self.congestion_window = @max(@as(u64, @intFromFloat(@as(f64, @floatFromInt(self.congestion_window)) * CC_CONSTANTS.LOSS_REDUCTION_FACTOR)), CC_CONSTANTS.MIN_WINDOW);

        // Set slow start threshold
        self.ssthresh = self.congestion_window;
        self.in_slow_start = false;
        self.bytes_acked_since_congestion = 0;

        _ = lost_bytes; // TODO: Use for more sophisticated loss tracking
    }

    /// Handle persistent congestion
    pub fn onPersistentCongestion(self: *Self) void {
        self.congestion_window = CC_CONSTANTS.MIN_WINDOW;
        self.in_slow_start = true;
        self.ssthresh = std.math.maxInt(u64);
        self.bytes_acked_since_congestion = 0;
    }

    /// Check if sending is blocked by congestion control
    pub fn canSend(self: Self, bytes_in_flight: u64, packet_size: u64) bool {
        return bytes_in_flight + packet_size <= self.congestion_window;
    }
};

/// Loss recovery manager
pub const LossRecovery = struct {
    /// RTT statistics
    rtt_stats: RttStats,

    /// Congestion controller
    congestion_controller: CongestionController,

    /// Loss detection timer
    loss_detection_timer: ?u64,

    /// Time when loss detection timer was set
    loss_detection_timer_start: u64,

    /// PTO backoff counter
    pto_count: u32,

    const Self = @This();

    /// Initialize loss recovery
    pub fn init() Self {
        return Self{
            .rtt_stats = RttStats.init(),
            .congestion_controller = CongestionController.init(),
            .loss_detection_timer = null,
            .loss_detection_timer_start = 0,
            .pto_count = 0,
        };
    }

    /// Set loss detection timer
    pub fn setLossDetectionTimer(self: *Self, spaces: []const *PacketSpace, now: u64) void {
        var earliest_loss_time: ?u64 = null;
        var has_ack_eliciting = false;

        // Find earliest loss time across all spaces
        for (spaces) |space| {
            if (!space.isActive()) continue;

            if (space.hasInFlightPackets()) {
                has_ack_eliciting = true;

                // Check for time-based loss detection
                const loss_time = self.calculateLossTime(space, now);
                if (loss_time != null) {
                    if (earliest_loss_time == null or loss_time.? < earliest_loss_time.?) {
                        earliest_loss_time = loss_time;
                    }
                }
            }
        }

        if (earliest_loss_time != null) {
            // Set timer for loss detection
            self.loss_detection_timer = earliest_loss_time;
        } else if (has_ack_eliciting) {
            // Set PTO timer
            const pto_timeout = self.rtt_stats.calculatePto(self.pto_count);
            self.loss_detection_timer = now + pto_timeout;
        } else {
            // No timer needed
            self.loss_detection_timer = null;
        }

        self.loss_detection_timer_start = now;
    }

    /// Calculate loss time for a packet space
    fn calculateLossTime(self: Self, space: *const PacketSpace, now: u64) ?u64 {
        if (space.largest_acked_packet == null) return null;

        const loss_delay = self.rtt_stats.lossTimeThreshold();
        var earliest_loss_time: ?u64 = null;
        var iterator = space.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (!packet.ack_eliciting) continue;

            const loss_time = packet.time_sent + loss_delay;
            if (loss_time <= now) return loss_time;
            if (earliest_loss_time == null or loss_time < earliest_loss_time.?) {
                earliest_loss_time = loss_time;
            }
        }

        return earliest_loss_time;
    }

    /// Handle loss detection timer expiry
    pub fn onLossDetectionTimeout(self: *Self, spaces: []const *PacketSpace, now: u64) !void {
        var earliest_loss_time: ?u64 = null;

        // Check for time-based losses
        for (spaces) |space| {
            if (!space.isActive()) continue;

            const loss_time = self.calculateLossTime(space, now);
            if (loss_time != null and loss_time.? <= now) {
                // Detect lost packets
                const time_threshold = self.rtt_stats.lossTimeThreshold();
                var lost_packets = space.detectLostPackets(now, time_threshold, RTT_CONSTANTS.K_PACKET_THRESHOLD);
                defer lost_packets.deinit(space.allocator);

                if (lost_packets.items.len > 0) {
                    const lost_stats = space.lostPacketStats(lost_packets.items);
                    space.onPacketsLost(lost_packets.items);
                    if (lost_stats.lost_bytes > 0) {
                        self.congestion_controller.onPacketsLost(
                            lost_stats.lost_bytes,
                            lost_stats.largest_lost_time,
                        );
                    }
                }
            } else if (loss_time != null) {
                if (earliest_loss_time == null or loss_time.? < earliest_loss_time.?) {
                    earliest_loss_time = loss_time;
                }
            }
        }

        // If no losses detected, this was a PTO
        if (earliest_loss_time == null or earliest_loss_time.? > now) {
            self.onPtoTimeout(spaces, now);
        }

        // Reset timer
        self.setLossDetectionTimer(spaces, now);
    }

    /// Handle PTO timeout
    fn onPtoTimeout(self: *Self, spaces: []const *PacketSpace, now: u64) void {
        _ = spaces;
        _ = now;

        self.pto_count += 1;

        // TODO: Send probe packets
        // - Send one ack-eliciting packet in each space with in-flight packets
        // - If no spaces have in-flight packets, send in application space
    }

    /// Process acknowledgment
    pub fn onAckReceived(
        self: *Self,
        space: *PacketSpace,
        acked_ranges: []const AckRange,
        ack_delay: u64,
        now: u64,
    ) void {
        const ack_result = space.processAck(acked_ranges, ack_delay, now) catch return;

        if (ack_result.largest_newly_acked_time > 0 and ack_result.largest_newly_acked != null) {
            const rtt = now - ack_result.largest_newly_acked_time;
            self.rtt_stats.updateRtt(ack_delay, rtt, now);
        }

        self.congestion_controller.onAckReceived(
            ack_result.newly_acked_bytes,
            space.largest_acked_time,
            now,
        );

        // Reset PTO count on successful ack
        if (ack_result.newly_acked_count > 0) {
            self.pto_count = 0;
        }
    }

    /// Detect persistent congestion
    pub fn detectPersistentCongestion(
        self: *Self,
        lost_packets: []const PacketNumber,
        space: *const PacketSpace,
    ) bool {
        if (lost_packets.len == 0) return false;

        var earliest: ?u64 = null;
        var latest: ?u64 = null;
        var ack_eliciting_count: usize = 0;

        for (lost_packets) |pn| {
            const packet = space.sent_packets.get(pn) orelse continue;
            if (!packet.ack_eliciting) continue;

            ack_eliciting_count += 1;
            earliest = if (earliest) |value| @min(value, packet.time_sent) else packet.time_sent;
            latest = if (latest) |value| @max(value, packet.time_sent) else packet.time_sent;
        }

        if (ack_eliciting_count == 0) return false;

        const span = latest.? - earliest.?;
        const threshold = self.rtt_stats.calculatePto(0) *
            RTT_CONSTANTS.PERSISTENT_CONGESTION_THRESHOLD;

        if (span >= threshold) {
            self.congestion_controller.onPersistentCongestion();
            return true;
        }

        return false;
    }

    /// Get current congestion window
    pub fn getCongestionWindow(self: Self) u64 {
        return self.congestion_controller.congestion_window;
    }

    /// Get current RTT estimate
    pub fn getSmoothedRtt(self: Self) u64 {
        return self.rtt_stats.smoothed_rtt;
    }

    /// Check if we can send a packet of given size
    pub fn canSend(self: Self, bytes_in_flight: u64, packet_size: u64) bool {
        return self.congestion_controller.canSend(bytes_in_flight, packet_size);
    }
};

// Tests
test "rtt stats initialization" {
    const rtt_stats = RttStats.init();

    try std.testing.expectEqual(RTT_CONSTANTS.INITIAL_RTT, rtt_stats.smoothed_rtt);
    try std.testing.expectEqual(RTT_CONSTANTS.INITIAL_RTT / 2, rtt_stats.rttvar);
}

test "congestion controller initialization" {
    var cc = CongestionController.init();

    try std.testing.expectEqual(CC_CONSTANTS.INITIAL_WINDOW, cc.congestion_window);
    try std.testing.expect(cc.in_slow_start);
    try std.testing.expect(cc.canSend(0, 1000));
}

test "loss recovery initialization" {
    var recovery = LossRecovery.init();

    try std.testing.expectEqual(RTT_CONSTANTS.INITIAL_RTT, recovery.getSmoothedRtt());
    try std.testing.expectEqual(CC_CONSTANTS.INITIAL_WINDOW, recovery.getCongestionWindow());
}

test "ack processing uses packet-space byte accounting" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();
    var recovery = LossRecovery.init();

    try space.onPacketSent(0, 1_000, true, true, 100);
    try space.onPacketSent(1, 2_000, true, true, 200);

    const initial_cwnd = recovery.getCongestionWindow();
    const ack = [_]AckRange{.{ .start = 0, .end = 1 }};
    recovery.onAckReceived(&space, &ack, 0, 4_000);

    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    try std.testing.expectEqual(initial_cwnd + 300, recovery.getCongestionWindow());
}

test "loss timeout removes lost packets and reduces congestion window" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();
    var recovery = LossRecovery.init();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);
    try space.onPacketSent(2, 3_000, true, true, 1200);

    const ack = [_]AckRange{.{ .start = 2, .end = 2 }};
    recovery.onAckReceived(&space, &ack, 0, 4_000);

    recovery.loss_detection_timer = 5_000;
    const spaces = [_]*PacketSpace{&space};
    try recovery.onLossDetectionTimeout(&spaces, 1_000_000);

    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    try std.testing.expect(recovery.getCongestionWindow() < CC_CONSTANTS.INITIAL_WINDOW);
}

test "rtt pto includes peer ack delay" {
    var rtt_stats = RttStats.init();
    rtt_stats.updateRtt(25_000, 125_000, 200_000);

    const pto = rtt_stats.calculatePto(0);
    try std.testing.expect(pto >= rtt_stats.smoothed_rtt + rtt_stats.max_ack_delay);
}

test "persistent congestion collapses congestion window" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();
    var recovery = LossRecovery.init();
    recovery.rtt_stats.smoothed_rtt = 10_000;
    recovery.rtt_stats.rttvar = 1_000;
    recovery.rtt_stats.max_ack_delay = 1_000;

    try space.onPacketSent(1, 1_000, true, true, 1200);
    try space.onPacketSent(2, 50_000, true, true, 1200);

    recovery.congestion_controller.congestion_window = 20_000;
    const lost = [_]PacketNumber{ 1, 2 };
    try std.testing.expect(recovery.detectPersistentCongestion(&lost, &space));
    try std.testing.expectEqual(CC_CONSTANTS.MIN_WINDOW, recovery.getCongestionWindow());
}
