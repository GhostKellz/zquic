//! QUIC congestion control implementation
//!
//! Implements congestion control algorithms for QUIC according to RFC 9002

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Congestion control algorithm types
pub const CongestionAlgorithm = enum {
    new_reno,
    cubic,
    bbr,
};

/// Congestion control state
pub const CongestionState = enum {
    slow_start,
    congestion_avoidance,
    recovery,
};

/// RTT measurements and statistics
pub const RttStats = struct {
    min_rtt: u64, // microseconds
    smoothed_rtt: u64, // microseconds
    rtt_variance: u64, // microseconds
    latest_rtt: u64, // microseconds
    max_ack_delay: u64, // microseconds

    const Self = @This();

    pub fn init() Self {
        return Self{
            .min_rtt = std.math.maxInt(u64),
            .smoothed_rtt = 0,
            .rtt_variance = 0,
            .latest_rtt = 0,
            .max_ack_delay = 25_000, // 25ms default
        };
    }

    /// Update RTT measurements with a new sample
    pub fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        self.latest_rtt = rtt_sample;

        // Update min RTT
        if (rtt_sample < self.min_rtt) {
            self.min_rtt = rtt_sample;
        }

        // Adjust for ack delay
        const adjusted_rtt = if (rtt_sample > ack_delay and ack_delay <= self.max_ack_delay)
            rtt_sample - ack_delay
        else
            rtt_sample;

        // First RTT sample
        if (self.smoothed_rtt == 0) {
            self.smoothed_rtt = adjusted_rtt;
            self.rtt_variance = adjusted_rtt / 2;
            return;
        }

        // Update smoothed RTT and variance using exponential weighted moving average
        const rtt_diff = if (adjusted_rtt > self.smoothed_rtt)
            adjusted_rtt - self.smoothed_rtt
        else
            self.smoothed_rtt - adjusted_rtt;

        self.rtt_variance = (3 * self.rtt_variance + rtt_diff) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) / 8;
    }

    /// Calculate the probe timeout (PTO)
    pub fn calculatePto(self: *const Self) u64 {
        return self.smoothed_rtt + @max(4 * self.rtt_variance, 1000); // Min 1ms
    }
};

/// Congestion controller implementing New Reno algorithm
pub const NewRenoCongestionController = struct {
    state: CongestionState,
    congestion_window: u64, // bytes
    ssthresh: u64, // slow start threshold
    bytes_in_flight: u64,
    max_datagram_size: u64,
    recovery_start_time: u64, // packet number when recovery started
    rtt_stats: RttStats,

    const Self = @This();
    const INITIAL_WINDOW_PACKETS = 10;
    const MIN_WINDOW_PACKETS = 2;

    pub fn init(max_datagram_size: u64) Self {
        return Self{
            .state = .slow_start,
            .congestion_window = INITIAL_WINDOW_PACKETS * max_datagram_size,
            .ssthresh = std.math.maxInt(u64),
            .bytes_in_flight = 0,
            .max_datagram_size = max_datagram_size,
            .recovery_start_time = 0,
            .rtt_stats = RttStats.init(),
        };
    }

    /// Check if we can send a packet of given size
    pub fn canSend(self: *const Self, packet_size: u64) bool {
        return self.bytes_in_flight + packet_size <= self.congestion_window;
    }

    /// Called when a packet is sent
    pub fn onPacketSent(self: *Self, packet_size: u64) void {
        self.bytes_in_flight += packet_size;
    }

    /// Called when packets are acknowledged
    pub fn onPacketsAcked(self: *Self, acked_bytes: u64, largest_acked_packet: u64) void {
        self.bytes_in_flight = if (self.bytes_in_flight > acked_bytes)
            self.bytes_in_flight - acked_bytes
        else
            0;

        // Exit recovery if we've acked packets sent after recovery started
        if (self.state == .recovery and largest_acked_packet >= self.recovery_start_time) {
            self.state = if (self.congestion_window < self.ssthresh) .slow_start else .congestion_avoidance;
        }

        // Increase congestion window
        switch (self.state) {
            .slow_start => {
                // In slow start, increase cwnd by the number of bytes acked
                self.congestion_window += acked_bytes;

                // Exit slow start if we reach ssthresh
                if (self.congestion_window >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                }
            },
            .congestion_avoidance => {
                // In congestion avoidance, increase cwnd by MSS^2/cwnd per RTT
                const increment = (self.max_datagram_size * acked_bytes) / self.congestion_window;
                self.congestion_window += @max(increment, 1);
            },
            .recovery => {
                // Don't increase window during recovery
            },
        }
    }

    /// Called when packets are lost
    pub fn onPacketsLost(self: *Self, lost_bytes: u64, largest_lost_packet: u64) void {
        self.bytes_in_flight = if (self.bytes_in_flight > lost_bytes)
            self.bytes_in_flight - lost_bytes
        else
            0;

        // Enter recovery if not already in recovery
        if (self.state != .recovery or largest_lost_packet > self.recovery_start_time) {
            self.ssthresh = @max(self.congestion_window / 2, MIN_WINDOW_PACKETS * self.max_datagram_size);
            self.congestion_window = self.ssthresh;
            self.state = .recovery;
            self.recovery_start_time = largest_lost_packet;
        }
    }

    /// Called when the idle timer expires
    pub fn onIdleTimeout(self: *Self) void {
        // Reset to slow start
        self.state = .slow_start;
        self.congestion_window = INITIAL_WINDOW_PACKETS * self.max_datagram_size;
        self.bytes_in_flight = 0;
    }

    /// Update RTT statistics
    pub fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        self.rtt_stats.updateRtt(rtt_sample, ack_delay);
    }

    /// Get the current sending rate
    pub fn getSendingRate(self: *const Self) u64 {
        if (self.rtt_stats.smoothed_rtt == 0) {
            return std.math.maxInt(u64);
        }

        // Rate = cwnd / smoothed_rtt (bytes per microsecond)
        return (self.congestion_window * 1_000_000) / self.rtt_stats.smoothed_rtt;
    }

    /// Get available congestion window
    pub fn availableWindow(self: *const Self) u64 {
        return if (self.congestion_window > self.bytes_in_flight)
            self.congestion_window - self.bytes_in_flight
        else
            0;
    }
};

/// Simplified CUBIC congestion controller
pub const CubicCongestionController = struct {
    new_reno: NewRenoCongestionController,
    w_max: u64, // Window size just before the last reduction
    k: u64, // Time period for CUBIC function
    w_tcp: u64, // TCP-friendly window size

    const Self = @This();
    const CUBIC_C: u64 = 4; // CUBIC scaling factor
    const BETA: u64 = 7; // Multiplicative decrease factor (0.7 * 10)

    pub fn init(max_datagram_size: u64) Self {
        return Self{
            .new_reno = NewRenoCongestionController.init(max_datagram_size),
            .w_max = 0,
            .k = 0,
            .w_tcp = 0,
        };
    }

    /// Delegate most operations to New Reno for simplicity
    pub fn canSend(self: *const Self, packet_size: u64) bool {
        return self.new_reno.canSend(packet_size);
    }

    pub fn onPacketSent(self: *Self, packet_size: u64) void {
        self.new_reno.onPacketSent(packet_size);
    }

    pub fn onPacketsAcked(self: *Self, acked_bytes: u64, largest_acked_packet: u64) void {
        // Use New Reno logic but with CUBIC window calculation in congestion avoidance
        if (self.new_reno.state == .congestion_avoidance) {
            // Simplified CUBIC calculation would go here
            // For now, delegate to New Reno
        }

        self.new_reno.onPacketsAcked(acked_bytes, largest_acked_packet);
    }

    pub fn onPacketsLost(self: *Self, lost_bytes: u64, largest_lost_packet: u64) void {
        if (self.new_reno.state != .recovery) {
            self.w_max = self.new_reno.congestion_window;
        }

        self.new_reno.onPacketsLost(lost_bytes, largest_lost_packet);
    }

    pub fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        self.new_reno.updateRtt(rtt_sample, ack_delay);
    }

    pub fn availableWindow(self: *const Self) u64 {
        return self.new_reno.availableWindow();
    }
};

/// Congestion controller factory
pub const CongestionController = union(CongestionAlgorithm) {
    new_reno: NewRenoCongestionController,
    cubic: CubicCongestionController,
    bbr: void, // BBR not implemented

    const Self = @This();

    pub fn init(algorithm: CongestionAlgorithm, max_datagram_size: u64) Self {
        return switch (algorithm) {
            .new_reno => Self{ .new_reno = NewRenoCongestionController.init(max_datagram_size) },
            .cubic => Self{ .cubic = CubicCongestionController.init(max_datagram_size) },
            .bbr => Self{ .bbr = {} },
        };
    }

    pub fn canSend(self: *const Self, packet_size: u64) bool {
        return switch (self.*) {
            .new_reno => |*cc| cc.canSend(packet_size),
            .cubic => |*cc| cc.canSend(packet_size),
            .bbr => true, // BBR not implemented
        };
    }

    pub fn onPacketSent(self: *Self, packet_size: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketSent(packet_size),
            .cubic => |*cc| cc.onPacketSent(packet_size),
            .bbr => {},
        }
    }

    pub fn onPacketsAcked(self: *Self, acked_bytes: u64, largest_acked_packet: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketsAcked(acked_bytes, largest_acked_packet),
            .cubic => |*cc| cc.onPacketsAcked(acked_bytes, largest_acked_packet),
            .bbr => {},
        }
    }

    pub fn onPacketsLost(self: *Self, lost_bytes: u64, largest_lost_packet: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketsLost(lost_bytes, largest_lost_packet),
            .cubic => |*cc| cc.onPacketsLost(lost_bytes, largest_lost_packet),
            .bbr => {},
        }
    }

    pub fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.updateRtt(rtt_sample, ack_delay),
            .cubic => |*cc| cc.updateRtt(rtt_sample, ack_delay),
            .bbr => {},
        }
    }

    pub fn availableWindow(self: *const Self) u64 {
        return switch (self.*) {
            .new_reno => |*cc| cc.availableWindow(),
            .cubic => |*cc| cc.availableWindow(),
            .bbr => std.math.maxInt(u64),
        };
    }
};

test "RTT statistics" {
    var rtt_stats = RttStats.init();

    // First sample
    rtt_stats.updateRtt(100_000, 0); // 100ms
    try std.testing.expect(rtt_stats.smoothed_rtt == 100_000);
    try std.testing.expect(rtt_stats.min_rtt == 100_000);

    // Second sample
    rtt_stats.updateRtt(120_000, 10_000); // 120ms with 10ms ack delay
    try std.testing.expect(rtt_stats.smoothed_rtt < 120_000); // Should be smoothed
    try std.testing.expect(rtt_stats.min_rtt == 100_000); // Min unchanged
}

test "New Reno congestion control" {
    var cc = NewRenoCongestionController.init(1200);

    // Initial state
    try std.testing.expect(cc.state == .slow_start);
    try std.testing.expect(cc.canSend(1200));

    // Send packets
    cc.onPacketSent(1200);
    cc.onPacketSent(1200);
    try std.testing.expect(cc.bytes_in_flight == 2400);

    // Ack packets - should grow window in slow start
    const initial_cwnd = cc.congestion_window;
    cc.onPacketsAcked(2400, 2);
    try std.testing.expect(cc.congestion_window > initial_cwnd);
    try std.testing.expect(cc.bytes_in_flight == 0);

    // Simulate loss
    cc.onPacketSent(1200);
    cc.onPacketsLost(1200, 1);
    try std.testing.expect(cc.state == .recovery);
    try std.testing.expect(cc.congestion_window < initial_cwnd);
}

test "congestion controller factory" {
    var cc = CongestionController.init(.new_reno, 1200);

    try std.testing.expect(cc.canSend(1200));
    cc.onPacketSent(1200);
    cc.onPacketsAcked(1200, 1);

    const available = cc.availableWindow();
    try std.testing.expect(available > 0);
}
