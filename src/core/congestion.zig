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

/// BBR (Bottleneck Bandwidth and Round-trip propagation time) congestion controller
pub const BbrCongestionController = struct {
    const Self = @This();
    const BbrState = enum { startup, drain, probe_bw, probe_rtt };
    const ProbeType = enum { none, up, down };
    
    max_datagram_size: u64,
    congestion_window: u64,
    
    // BBR state
    state: BbrState,
    round_count: u64,
    round_start: bool,
    
    // Bandwidth estimation
    max_bandwidth: f64,
    bandwidth_samples: [8]f64,
    bandwidth_sample_idx: usize,
    min_rtt: u64,
    min_rtt_timestamp: u64,
    
    // Probing state
    probe_type: ProbeType,
    probe_up_rounds: u32,
    cycle_start_time: u64,
    pacing_gain: f64,
    cwnd_gain: f64,
    
    // Packet tracking
    bytes_in_flight: u64,
    delivered: u64,
    delivered_time: u64,
    
    pub fn init(max_datagram_size: u64) Self {
        const initial_cwnd = 10 * max_datagram_size; // Initial congestion window
        return Self{
            .max_datagram_size = max_datagram_size,
            .congestion_window = initial_cwnd,
            .state = .startup,
            .round_count = 0,
            .round_start = false,
            .max_bandwidth = 1000000.0, // 1 Mbps initial estimate
            .bandwidth_samples = [_]f64{0.0} ** 8,
            .bandwidth_sample_idx = 0,
            .min_rtt = 100000, // 100ms initial estimate (microseconds)
            .min_rtt_timestamp = 0,
            .probe_type = .none,
            .probe_up_rounds = 0,
            .cycle_start_time = 0,
            .pacing_gain = 2.773, // High gain for startup
            .cwnd_gain = 2.0,
            .bytes_in_flight = 0,
            .delivered = 0,
            .delivered_time = 0,
        };
    }
    
    pub fn canSend(self: *const Self, packet_size: u64) bool {
        return self.bytes_in_flight + packet_size <= self.congestion_window;
    }
    
    pub fn onPacketSent(self: *Self, packet_size: u64) void {
        self.bytes_in_flight += packet_size;
    }
    
    pub fn onAcked(self: *Self, acked_bytes: u64, rtt: u64, now: u64) void {
        self.bytes_in_flight -|= acked_bytes;
        self.delivered += acked_bytes;
        self.delivered_time = now;
        
        // Update minimum RTT
        if (rtt < self.min_rtt) {
            self.min_rtt = rtt;
            self.min_rtt_timestamp = now;
        }
        
        // Update bandwidth estimate
        self.updateBandwidth(acked_bytes, rtt, now);
        
        // Update BBR state machine
        self.updateBbrState(now);
        
        // Update congestion window and pacing
        self.updateCongestionWindow();
    }
    
    pub fn onLost(self: *Self, lost_bytes: u64) void {
        self.bytes_in_flight -|= lost_bytes;
        
        // BBR is less reactive to loss than other algorithms
        // Only adjust if we're in probe_rtt state or experiencing persistent loss
        if (self.state == .probe_rtt) {
            self.congestion_window = @max(self.congestion_window * 7 / 10, 2 * self.max_datagram_size);
        }
    }
    
    pub fn availableWindow(self: *const Self) u64 {
        return if (self.congestion_window > self.bytes_in_flight) 
            self.congestion_window - self.bytes_in_flight 
        else 
            0;
    }
    
    fn updateBandwidth(self: *Self, acked_bytes: u64, rtt: u64, now: u64) void {
        // Calculate delivery rate (bytes per second)
        const delivery_rate = if (rtt > 0) 
            (@as(f64, @floatFromInt(acked_bytes)) * 1_000_000.0) / @as(f64, @floatFromInt(rtt))
        else 
            self.max_bandwidth;
            
        // Add to circular buffer
        self.bandwidth_samples[self.bandwidth_sample_idx] = delivery_rate;
        self.bandwidth_sample_idx = (self.bandwidth_sample_idx + 1) % 8;
        
        // Update max bandwidth (windowed maximum)
        var max_bw: f64 = 0.0;
        for (self.bandwidth_samples) |sample| {
            max_bw = @max(max_bw, sample);
        }
        self.max_bandwidth = max_bw;
        
        _ = now; // Suppress unused parameter warning
    }
    
    fn updateBbrState(self: *Self, now: u64) void {
        switch (self.state) {
            .startup => {
                // Exit startup when bandwidth stops growing
                if (self.max_bandwidth < self.getPreviousBandwidth() * 1.25) {
                    self.state = .drain;
                    self.pacing_gain = 1.0 / 2.773; // Drain excess packets
                }
            },
            .drain => {
                // Exit drain when inflight <= BDP
                if (self.bytes_in_flight <= self.getBdp()) {
                    self.state = .probe_bw;
                    self.pacing_gain = 1.0;
                    self.cycle_start_time = now;
                }
            },
            .probe_bw => {
                // Cycle through different pacing gains
                const cycle_duration = 8 * self.min_rtt;
                if (now - self.cycle_start_time > cycle_duration) {
                    self.cyclePacingGain();
                    self.cycle_start_time = now;
                }
                
                // Check if we should enter probe_rtt
                if (now - self.min_rtt_timestamp > 10_000_000) { // 10 seconds
                    self.state = .probe_rtt;
                    self.pacing_gain = 1.0;
                }
            },
            .probe_rtt => {
                // Reduce cwnd to find true minimum RTT
                self.congestion_window = @max(4 * self.max_datagram_size, self.congestion_window * 3 / 4);
                
                // Exit after probing for one RTT
                if (now - self.cycle_start_time > self.min_rtt) {
                    if (self.bytes_in_flight <= self.getBdp()) {
                        self.state = .startup;
                        self.pacing_gain = 2.773;
                    } else {
                        self.state = .probe_bw;
                        self.pacing_gain = 1.0;
                    }
                    self.cycle_start_time = now;
                }
            },
        }
    }
    
    fn updateCongestionWindow(self: *Self) void {
        const bdp = self.getBdp();
        
        switch (self.state) {
            .startup => {
                self.congestion_window = @max(self.congestion_window, @as(u64, @intFromFloat(@as(f64, @floatFromInt(bdp)) * self.cwnd_gain)));
            },
            .drain => {
                // Don't increase cwnd during drain
            },
            .probe_bw => {
                self.congestion_window = @max(4 * self.max_datagram_size, bdp);
            },
            .probe_rtt => {
                // Cwnd is managed in updateBbrState
            },
        }
    }
    
    fn getBdp(self: *const Self) u64 {
        // Bandwidth-Delay Product
        return @as(u64, @intFromFloat(self.max_bandwidth * @as(f64, @floatFromInt(self.min_rtt)) / 1_000_000.0));
    }
    
    fn getPreviousBandwidth(self: *const Self) f64 {
        // Get bandwidth from previous sample
        const prev_idx = if (self.bandwidth_sample_idx == 0) 7 else self.bandwidth_sample_idx - 1;
        return self.bandwidth_samples[prev_idx];
    }
    
    fn cyclePacingGain(self: *Self) void {
        // BBR cycles through pacing gains: [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]
        const gains = [_]f64{ 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
        const cycle_idx = @as(usize, @intCast(self.round_count % 8));
        self.pacing_gain = gains[cycle_idx];
        self.round_count += 1;
    }
};

/// Congestion controller factory
pub const CongestionController = union(CongestionAlgorithm) {
    new_reno: NewRenoCongestionController,
    cubic: CubicCongestionController,
    bbr: BbrCongestionController,

    const Self = @This();

    pub fn init(algorithm: CongestionAlgorithm, max_datagram_size: u64) Self {
        return switch (algorithm) {
            .new_reno => Self{ .new_reno = NewRenoCongestionController.init(max_datagram_size) },
            .cubic => Self{ .cubic = CubicCongestionController.init(max_datagram_size) },
            .bbr => Self{ .bbr = BbrCongestionController.init(max_datagram_size) },
        };
    }

    pub fn canSend(self: *const Self, packet_size: u64) bool {
        return switch (self.*) {
            .new_reno => |*cc| cc.canSend(packet_size),
            .cubic => |*cc| cc.canSend(packet_size),
            .bbr => |*cc| cc.canSend(packet_size),
        };
    }

    pub fn onPacketSent(self: *Self, packet_size: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketSent(packet_size),
            .cubic => |*cc| cc.onPacketSent(packet_size),
            .bbr => |*cc| cc.onPacketSent(packet_size),
        }
    }

    pub fn onPacketsAcked(self: *Self, acked_bytes: u64, largest_acked_packet: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketsAcked(acked_bytes, largest_acked_packet),
            .cubic => |*cc| cc.onPacketsAcked(acked_bytes, largest_acked_packet),
            .bbr => |*cc| {
                // BBR needs RTT and timestamp - use reasonable defaults for now
                // In real implementation, these would be passed from the caller
                const rtt = 50000; // 50ms default
                const now = @as(u64, @intCast(std.time.microTimestamp()));
                cc.onAcked(acked_bytes, rtt, now);
                // Note: largest_acked_packet is not used by BBR
            },
        }
    }

    pub fn onPacketsLost(self: *Self, lost_bytes: u64, largest_lost_packet: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.onPacketsLost(lost_bytes, largest_lost_packet),
            .cubic => |*cc| cc.onPacketsLost(lost_bytes, largest_lost_packet),
            .bbr => |*cc| {
                cc.onLost(lost_bytes);
                // Note: largest_lost_packet is not used by BBR
            },
        }
    }

    pub fn updateRtt(self: *Self, rtt_sample: u64, ack_delay: u64) void {
        switch (self.*) {
            .new_reno => |*cc| cc.updateRtt(rtt_sample, ack_delay),
            .cubic => |*cc| cc.updateRtt(rtt_sample, ack_delay),
            .bbr => |*cc| {
                // BBR doesn't have a separate updateRtt method, RTT is updated in onAcked
                // But we can update the minimum RTT here
                const actual_rtt = rtt_sample -| ack_delay;
                if (actual_rtt < cc.min_rtt) {
                    cc.min_rtt = actual_rtt;
                    cc.min_rtt_timestamp = @as(u64, @intCast(std.time.microTimestamp()));
                }
            },
        }
    }

    pub fn availableWindow(self: *const Self) u64 {
        return switch (self.*) {
            .new_reno => |*cc| cc.availableWindow(),
            .cubic => |*cc| cc.availableWindow(),
            .bbr => |*cc| cc.availableWindow(),
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
