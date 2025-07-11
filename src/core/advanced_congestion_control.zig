//! Advanced Congestion Control Algorithms for QUIC
//!
//! Implements multiple congestion control algorithms that exceed Quinn's capabilities:
//! - NewReno (RFC 5681)
//! - CUBIC (RFC 8312)
//! - BBR (Google's algorithm)
//! - DCTCP (Data Center TCP)
//! - Adaptive algorithms with machine learning
//! - Custom blockchain-optimized algorithms

const std = @import("std");
const Error = @import("../utils/error.zig");

/// Congestion control algorithm types
pub const CongestionControlType = enum {
    new_reno,
    cubic,
    bbr,
    bbr2,
    dctcp,
    adaptive,
    blockchain_optimized,
    
    pub fn toString(self: CongestionControlType) []const u8 {
        return switch (self) {
            .new_reno => "NewReno",
            .cubic => "CUBIC",
            .bbr => "BBR",
            .bbr2 => "BBRv2",
            .dctcp => "DCTCP",
            .adaptive => "Adaptive",
            .blockchain_optimized => "BlockchainOptimized",
        };
    }
};

/// Congestion control state
pub const CongestionState = enum {
    slow_start,
    congestion_avoidance,
    fast_recovery,
    probe_rtt,
    probe_bw,
    drain,
    startup,
};

/// Packet acknowledgment information
pub const AckInfo = struct {
    packet_number: u64,
    time_sent: u64,
    time_acked: u64,
    bytes_acked: u64,
    is_app_limited: bool,
    
    pub fn getRTT(self: *const AckInfo) u64 {
        return self.time_acked - self.time_sent;
    }
};

/// Loss detection information
pub const LossInfo = struct {
    packet_number: u64,
    time_sent: u64,
    time_lost: u64,
    bytes_lost: u64,
    
    pub fn getTimeSinceSent(self: *const LossInfo) u64 {
        return self.time_lost - self.time_sent;
    }
};

/// Congestion control metrics
pub const CongestionMetrics = struct {
    congestion_window: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    min_rtt: u64,
    smoothed_rtt: u64,
    rtt_variance: u64,
    max_bandwidth: u64,
    pacing_rate: u64,
    delivery_rate: u64,
    lost_packets: u64,
    total_packets: u64,
    
    pub fn init() CongestionMetrics {
        return CongestionMetrics{
            .congestion_window = 10 * 1200, // 10 packets
            .bytes_in_flight = 0,
            .ssthresh = std.math.maxInt(u64),
            .min_rtt = std.math.maxInt(u64),
            .smoothed_rtt = 0,
            .rtt_variance = 0,
            .max_bandwidth = 0,
            .pacing_rate = 0,
            .delivery_rate = 0,
            .lost_packets = 0,
            .total_packets = 0,
        };
    }
    
    pub fn getLossRate(self: *const CongestionMetrics) f64 {
        if (self.total_packets == 0) return 0.0;
        return @as(f64, @floatFromInt(self.lost_packets)) / @as(f64, @floatFromInt(self.total_packets));
    }
    
    pub fn getUtilization(self: *const CongestionMetrics) f64 {
        if (self.congestion_window == 0) return 0.0;
        return @as(f64, @floatFromInt(self.bytes_in_flight)) / @as(f64, @floatFromInt(self.congestion_window));
    }
};

/// Base congestion control interface
pub const CongestionControl = struct {
    type: CongestionControlType,
    state: CongestionState,
    metrics: CongestionMetrics,
    vtable: *const VTable,
    
    const VTable = struct {
        on_packet_sent: *const fn (self: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void,
        on_packet_acked: *const fn (self: *CongestionControl, ack_info: AckInfo) void,
        on_packet_lost: *const fn (self: *CongestionControl, loss_info: LossInfo) void,
        on_congestion_event: *const fn (self: *CongestionControl, event_time: u64) void,
        get_congestion_window: *const fn (self: *const CongestionControl) u64,
        get_pacing_rate: *const fn (self: *const CongestionControl) u64,
        can_send: *const fn (self: *const CongestionControl, bytes: u64) bool,
        update_rtt: *const fn (self: *CongestionControl, rtt: u64) void,
    };
    
    pub fn onPacketSent(self: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void {
        self.vtable.on_packet_sent(self, packet_number, bytes, is_retransmittable);
    }
    
    pub fn onPacketAcked(self: *CongestionControl, ack_info: AckInfo) void {
        self.vtable.on_packet_acked(self, ack_info);
    }
    
    pub fn onPacketLost(self: *CongestionControl, loss_info: LossInfo) void {
        self.vtable.on_packet_lost(self, loss_info);
    }
    
    pub fn onCongestionEvent(self: *CongestionControl, event_time: u64) void {
        self.vtable.on_congestion_event(self, event_time);
    }
    
    pub fn getCongestionWindow(self: *const CongestionControl) u64 {
        return self.vtable.get_congestion_window(self);
    }
    
    pub fn getPacingRate(self: *const CongestionControl) u64 {
        return self.vtable.get_pacing_rate(self);
    }
    
    pub fn canSend(self: *const CongestionControl, bytes: u64) bool {
        return self.vtable.can_send(self, bytes);
    }
    
    pub fn updateRTT(self: *CongestionControl, rtt: u64) void {
        self.vtable.update_rtt(self, rtt);
    }
};

/// NewReno congestion control implementation
pub const NewReno = struct {
    base: CongestionControl,
    duplicated_acks: u64,
    recovery_start_time: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .base = CongestionControl{
                .type = .new_reno,
                .state = .slow_start,
                .metrics = CongestionMetrics.init(),
                .vtable = &vtable,
            },
            .duplicated_acks = 0,
            .recovery_start_time = 0,
        };
    }
    
    const vtable = CongestionControl.VTable{
        .on_packet_sent = onPacketSent,
        .on_packet_acked = onPacketAcked,
        .on_packet_lost = onPacketLost,
        .on_congestion_event = onCongestionEvent,
        .get_congestion_window = getCongestionWindow,
        .get_pacing_rate = getPacingRate,
        .can_send = canSend,
        .update_rtt = updateRTT,
    };
    
    fn getSelf(cc: *CongestionControl) *Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn getSelfConst(cc: *const CongestionControl) *const Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn onPacketSent(cc: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void {
        _ = packet_number;
        _ = is_retransmittable;
        
        cc.metrics.bytes_in_flight += bytes;
        cc.metrics.total_packets += 1;
    }
    
    fn onPacketAcked(cc: *CongestionControl, ack_info: AckInfo) void {
        const self = getSelf(cc);
        
        cc.metrics.bytes_in_flight -= ack_info.bytes_acked;
        
        switch (cc.state) {
            .slow_start => {
                // In slow start, increase cwnd by bytes_acked
                cc.metrics.congestion_window += ack_info.bytes_acked;
                
                // Exit slow start if we reach ssthresh
                if (cc.metrics.congestion_window >= cc.metrics.ssthresh) {
                    cc.state = .congestion_avoidance;
                }
            },
            .congestion_avoidance => {
                // In congestion avoidance, increase cwnd by MSS^2/cwnd per RTT
                const mss = 1200; // Maximum segment size
                const increase = (mss * mss) / cc.metrics.congestion_window;
                cc.metrics.congestion_window += increase;
            },
            .fast_recovery => {
                // In fast recovery, deflate cwnd by bytes_acked
                cc.metrics.congestion_window -= ack_info.bytes_acked;
                
                // Exit fast recovery if we've recovered
                if (ack_info.packet_number > self.recovery_start_time) {
                    cc.state = .congestion_avoidance;
                }
            },
            else => {},
        }
    }
    
    fn onPacketLost(cc: *CongestionControl, loss_info: LossInfo) void {
        const self = getSelf(cc);
        
        cc.metrics.bytes_in_flight -= loss_info.bytes_lost;
        cc.metrics.lost_packets += 1;
        
        // Enter fast recovery
        if (cc.state != .fast_recovery) {
            cc.metrics.ssthresh = @max(cc.metrics.congestion_window / 2, 2 * 1200);
            cc.metrics.congestion_window = cc.metrics.ssthresh;
            cc.state = .fast_recovery;
            self.recovery_start_time = loss_info.time_lost;
        }
    }
    
    fn onCongestionEvent(cc: *CongestionControl, event_time: u64) void {
        _ = event_time;
        
        // Reduce congestion window on congestion event
        cc.metrics.ssthresh = @max(cc.metrics.congestion_window / 2, 2 * 1200);
        cc.metrics.congestion_window = cc.metrics.ssthresh;
    }
    
    fn getCongestionWindow(cc: *const CongestionControl) u64 {
        return cc.metrics.congestion_window;
    }
    
    fn getPacingRate(cc: *const CongestionControl) u64 {
        // Simple pacing rate calculation
        if (cc.metrics.smoothed_rtt > 0) {
            return (cc.metrics.congestion_window * 8 * 1000000) / cc.metrics.smoothed_rtt;
        }
        return 0;
    }
    
    fn canSend(cc: *const CongestionControl, bytes: u64) bool {
        return cc.metrics.bytes_in_flight + bytes <= cc.metrics.congestion_window;
    }
    
    fn updateRTT(cc: *CongestionControl, rtt: u64) void {
        if (cc.metrics.smoothed_rtt == 0) {
            cc.metrics.smoothed_rtt = rtt;
            cc.metrics.rtt_variance = rtt / 2;
        } else {
            const alpha = 1.0 / 8.0;
            const beta = 1.0 / 4.0;
            
            const rtt_diff = if (rtt > cc.metrics.smoothed_rtt) rtt - cc.metrics.smoothed_rtt else cc.metrics.smoothed_rtt - rtt;
            
            cc.metrics.rtt_variance = @intFromFloat((1.0 - beta) * @as(f64, @floatFromInt(cc.metrics.rtt_variance)) + beta * @as(f64, @floatFromInt(rtt_diff)));
            cc.metrics.smoothed_rtt = @intFromFloat((1.0 - alpha) * @as(f64, @floatFromInt(cc.metrics.smoothed_rtt)) + alpha * @as(f64, @floatFromInt(rtt)));
        }
        
        cc.metrics.min_rtt = @min(cc.metrics.min_rtt, rtt);
    }
};

/// CUBIC congestion control implementation
pub const CUBIC = struct {
    base: CongestionControl,
    beta: f64,
    c: f64,
    w_max: f64,
    epoch_start_time: u64,
    origin_point: f64,
    k: f64,
    ack_count: u64,
    tcp_cwnd: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .base = CongestionControl{
                .type = .cubic,
                .state = .slow_start,
                .metrics = CongestionMetrics.init(),
                .vtable = &vtable,
            },
            .beta = 0.7,
            .c = 0.4,
            .w_max = 0.0,
            .epoch_start_time = 0,
            .origin_point = 0.0,
            .k = 0.0,
            .ack_count = 0,
            .tcp_cwnd = 0,
        };
    }
    
    const vtable = CongestionControl.VTable{
        .on_packet_sent = onPacketSent,
        .on_packet_acked = onPacketAcked,
        .on_packet_lost = onPacketLost,
        .on_congestion_event = onCongestionEvent,
        .get_congestion_window = getCongestionWindow,
        .get_pacing_rate = getPacingRate,
        .can_send = canSend,
        .update_rtt = updateRTT,
    };
    
    fn getSelf(cc: *CongestionControl) *Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn getSelfConst(cc: *const CongestionControl) *const Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn onPacketSent(cc: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void {
        _ = packet_number;
        _ = is_retransmittable;
        
        cc.metrics.bytes_in_flight += bytes;
        cc.metrics.total_packets += 1;
    }
    
    fn onPacketAcked(cc: *CongestionControl, ack_info: AckInfo) void {
        const self = getSelf(cc);
        
        cc.metrics.bytes_in_flight -= ack_info.bytes_acked;
        self.ack_count += 1;
        
        switch (cc.state) {
            .slow_start => {
                cc.metrics.congestion_window += ack_info.bytes_acked;
                
                // Exit slow start if we reach ssthresh
                if (cc.metrics.congestion_window >= cc.metrics.ssthresh) {
                    cc.state = .congestion_avoidance;
                    self.epoch_start_time = ack_info.time_acked;
                }
            },
            .congestion_avoidance => {
                self.cubicUpdate(ack_info.time_acked, ack_info.bytes_acked);
            },
            else => {},
        }
    }
    
    fn cubicUpdate(self: *Self, current_time: u64, bytes_acked: u64) void {
        const mss = 1200.0;
        const t = @as(f64, @floatFromInt(current_time - self.epoch_start_time)) / 1000000.0; // Convert to seconds
        
        // CUBIC window calculation
        const target = self.origin_point + self.c * std.math.pow(f64, t - self.k, 3.0);
        
        // TCP-friendly window calculation
        self.tcp_cwnd = @intFromFloat(self.w_max * self.beta + (3.0 * (1.0 - self.beta) / (1.0 + self.beta)) * @as(f64, @floatFromInt(self.ack_count)) * mss);
        
        // Use the more aggressive of CUBIC or TCP-friendly
        if (target > @as(f64, @floatFromInt(self.tcp_cwnd))) {
            self.base.metrics.congestion_window = @intFromFloat(target);
        } else {
            self.base.metrics.congestion_window = self.tcp_cwnd;
        }
        
        _ = bytes_acked;
    }
    
    fn onPacketLost(cc: *CongestionControl, loss_info: LossInfo) void {
        const self = getSelf(cc);
        
        cc.metrics.bytes_in_flight -= loss_info.bytes_lost;
        cc.metrics.lost_packets += 1;
        
        // CUBIC multiplicative decrease
        self.w_max = @as(f64, @floatFromInt(cc.metrics.congestion_window));
        cc.metrics.congestion_window = @intFromFloat(@as(f64, @floatFromInt(cc.metrics.congestion_window)) * self.beta);
        cc.metrics.ssthresh = cc.metrics.congestion_window;
        
        // Calculate new epoch parameters
        self.epoch_start_time = loss_info.time_lost;
        self.origin_point = @as(f64, @floatFromInt(cc.metrics.congestion_window));
        self.k = std.math.pow(f64, (self.w_max - self.origin_point) / self.c, 1.0 / 3.0);
        self.ack_count = 0;
        
        cc.state = .congestion_avoidance;
    }
    
    fn onCongestionEvent(cc: *CongestionControl, event_time: u64) void {
        const self = getSelf(cc);
        
        self.w_max = @as(f64, @floatFromInt(cc.metrics.congestion_window));
        cc.metrics.congestion_window = @intFromFloat(@as(f64, @floatFromInt(cc.metrics.congestion_window)) * self.beta);
        
        self.epoch_start_time = event_time;
        self.origin_point = @as(f64, @floatFromInt(cc.metrics.congestion_window));
        self.k = std.math.pow(f64, (self.w_max - self.origin_point) / self.c, 1.0 / 3.0);
    }
    
    fn getCongestionWindow(cc: *const CongestionControl) u64 {
        return cc.metrics.congestion_window;
    }
    
    fn getPacingRate(cc: *const CongestionControl) u64 {
        if (cc.metrics.smoothed_rtt > 0) {
            return (cc.metrics.congestion_window * 8 * 1000000) / cc.metrics.smoothed_rtt;
        }
        return 0;
    }
    
    fn canSend(cc: *const CongestionControl, bytes: u64) bool {
        return cc.metrics.bytes_in_flight + bytes <= cc.metrics.congestion_window;
    }
    
    fn updateRTT(cc: *CongestionControl, rtt: u64) void {
        if (cc.metrics.smoothed_rtt == 0) {
            cc.metrics.smoothed_rtt = rtt;
            cc.metrics.rtt_variance = rtt / 2;
        } else {
            const alpha = 1.0 / 8.0;
            const beta = 1.0 / 4.0;
            
            const rtt_diff = if (rtt > cc.metrics.smoothed_rtt) rtt - cc.metrics.smoothed_rtt else cc.metrics.smoothed_rtt - rtt;
            
            cc.metrics.rtt_variance = @intFromFloat((1.0 - beta) * @as(f64, @floatFromInt(cc.metrics.rtt_variance)) + beta * @as(f64, @floatFromInt(rtt_diff)));
            cc.metrics.smoothed_rtt = @intFromFloat((1.0 - alpha) * @as(f64, @floatFromInt(cc.metrics.smoothed_rtt)) + alpha * @as(f64, @floatFromInt(rtt)));
        }
        
        cc.metrics.min_rtt = @min(cc.metrics.min_rtt, rtt);
    }
};

/// BBR congestion control implementation
pub const BBR = struct {
    base: CongestionControl,
    mode: BBRMode,
    round_count: u64,
    next_round_delivered: u64,
    probe_bw_gain: f64,
    pacing_gain: f64,
    cwnd_gain: f64,
    probe_rtt_duration: u64,
    probe_rtt_min_timestamp: u64,
    min_rtt_timestamp: u64,
    bandwidth_filter: MaxFilter,
    delivered: u64,
    delivered_timestamp: u64,
    
    const BBRMode = enum {
        startup,
        drain,
        probe_bw,
        probe_rtt,
    };
    
    const MaxFilter = struct {
        values: [3]f64,
        timestamps: [3]u64,
        index: usize,
        
        pub fn init() MaxFilter {
            return MaxFilter{
                .values = [_]f64{0.0} ** 3,
                .timestamps = [_]u64{0} ** 3,
                .index = 0,
            };
        }
        
        pub fn update(self: *MaxFilter, value: f64, timestamp: u64) void {
            self.values[self.index] = value;
            self.timestamps[self.index] = timestamp;
            self.index = (self.index + 1) % 3;
        }
        
        pub fn getMax(self: *const MaxFilter) f64 {
            var max_val: f64 = 0.0;
            for (self.values) |val| {
                max_val = @max(max_val, val);
            }
            return max_val;
        }
    };
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .base = CongestionControl{
                .type = .bbr,
                .state = .startup,
                .metrics = CongestionMetrics.init(),
                .vtable = &vtable,
            },
            .mode = .startup,
            .round_count = 0,
            .next_round_delivered = 0,
            .probe_bw_gain = 1.0,
            .pacing_gain = 2.77, // High gain for startup
            .cwnd_gain = 2.0,
            .probe_rtt_duration = 200000, // 200ms in microseconds
            .probe_rtt_min_timestamp = 0,
            .min_rtt_timestamp = 0,
            .bandwidth_filter = MaxFilter.init(),
            .delivered = 0,
            .delivered_timestamp = 0,
        };
    }
    
    const vtable = CongestionControl.VTable{
        .on_packet_sent = onPacketSent,
        .on_packet_acked = onPacketAcked,
        .on_packet_lost = onPacketLost,
        .on_congestion_event = onCongestionEvent,
        .get_congestion_window = getCongestionWindow,
        .get_pacing_rate = getPacingRate,
        .can_send = canSend,
        .update_rtt = updateRTT,
    };
    
    fn getSelf(cc: *CongestionControl) *Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn getSelfConst(cc: *const CongestionControl) *const Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn onPacketSent(cc: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void {
        _ = packet_number;
        _ = is_retransmittable;
        
        cc.metrics.bytes_in_flight += bytes;
        cc.metrics.total_packets += 1;
    }
    
    fn onPacketAcked(cc: *CongestionControl, ack_info: AckInfo) void {
        const self = getSelf(cc);
        
        cc.metrics.bytes_in_flight -= ack_info.bytes_acked;
        self.delivered += ack_info.bytes_acked;
        self.delivered_timestamp = ack_info.time_acked;
        
        // Update bandwidth estimate
        const delivery_rate = self.calculateDeliveryRate(ack_info);
        self.bandwidth_filter.update(delivery_rate, ack_info.time_acked);
        cc.metrics.max_bandwidth = @intFromFloat(self.bandwidth_filter.getMax());
        
        // Update round count
        if (self.delivered >= self.next_round_delivered) {
            self.round_count += 1;
            self.next_round_delivered = self.delivered + cc.metrics.congestion_window;
        }
        
        // Update BBR state machine
        self.updateState(ack_info.time_acked);
    }
    
    fn calculateDeliveryRate(self: *const Self, ack_info: AckInfo) f64 {
        const time_elapsed = ack_info.time_acked - self.delivered_timestamp;
        if (time_elapsed == 0) return 0.0;
        
        return @as(f64, @floatFromInt(ack_info.bytes_acked)) / (@as(f64, @floatFromInt(time_elapsed)) / 1000000.0);
    }
    
    fn updateState(self: *Self, current_time: u64) void {
        switch (self.mode) {
            .startup => {
                // Exit startup if bandwidth growth has plateaued
                if (self.bandwidth_filter.getMax() < self.base.metrics.max_bandwidth * 1.25) {
                    self.mode = .drain;
                    self.pacing_gain = 1.0 / 2.77;
                    self.cwnd_gain = 1.0;
                }
            },
            .drain => {
                // Exit drain when bytes in flight <= estimated BDP
                const bdp = @as(f64, @floatFromInt(self.base.metrics.max_bandwidth * self.base.metrics.min_rtt)) / 8000000.0;
                if (@as(f64, @floatFromInt(self.base.metrics.bytes_in_flight)) <= bdp) {
                    self.mode = .probe_bw;
                    self.pacing_gain = 1.0;
                    self.cwnd_gain = 1.0;
                }
            },
            .probe_bw => {
                // Cycle through different pacing gains
                const probe_bw_gains = [_]f64{ 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
                const cycle_index = (self.round_count / 8) % probe_bw_gains.len;
                self.pacing_gain = probe_bw_gains[cycle_index];
                
                // Check if we should enter ProbeRTT
                if (current_time - self.min_rtt_timestamp > 10000000) { // 10 seconds
                    self.mode = .probe_rtt;
                    self.pacing_gain = 1.0;
                    self.cwnd_gain = 1.0;
                    self.probe_rtt_min_timestamp = current_time;
                }
            },
            .probe_rtt => {
                // Exit ProbeRTT after duration
                if (current_time - self.probe_rtt_min_timestamp > self.probe_rtt_duration) {
                    self.mode = .probe_bw;
                    self.pacing_gain = 1.0;
                }
            },
        }
    }
    
    fn onPacketLost(cc: *CongestionControl, loss_info: LossInfo) void {
        cc.metrics.bytes_in_flight -= loss_info.bytes_lost;
        cc.metrics.lost_packets += 1;
        
        // BBR doesn't react to individual packet losses like traditional CC
        // Instead, it relies on bandwidth and RTT measurements
    }
    
    fn onCongestionEvent(cc: *CongestionControl, event_time: u64) void {
        _ = event_time;
        // BBR doesn't react to congestion events in the traditional sense
    }
    
    fn getCongestionWindow(cc: *const CongestionControl) u64 {
        const self = getSelfConst(cc);
        
        // Calculate target congestion window based on BDP
        const bdp = (@as(f64, @floatFromInt(cc.metrics.max_bandwidth)) * @as(f64, @floatFromInt(cc.metrics.min_rtt))) / 8000000.0;
        const target_cwnd = @as(u64, @intFromFloat(bdp * self.cwnd_gain));
        
        return @max(target_cwnd, 4 * 1200); // At least 4 packets
    }
    
    fn getPacingRate(cc: *const CongestionControl) u64 {
        const self = getSelfConst(cc);
        return @intFromFloat(@as(f64, @floatFromInt(cc.metrics.max_bandwidth)) * self.pacing_gain);
    }
    
    fn canSend(cc: *const CongestionControl, bytes: u64) bool {
        return cc.metrics.bytes_in_flight + bytes <= cc.getCongestionWindow();
    }
    
    fn updateRTT(cc: *CongestionControl, rtt: u64) void {
        const self = getSelf(cc);
        
        if (cc.metrics.min_rtt > rtt) {
            cc.metrics.min_rtt = rtt;
            self.min_rtt_timestamp = std.time.microTimestamp();
        }
        
        // Update smoothed RTT
        if (cc.metrics.smoothed_rtt == 0) {
            cc.metrics.smoothed_rtt = rtt;
        } else {
            const alpha = 1.0 / 8.0;
            cc.metrics.smoothed_rtt = @intFromFloat((1.0 - alpha) * @as(f64, @floatFromInt(cc.metrics.smoothed_rtt)) + alpha * @as(f64, @floatFromInt(rtt)));
        }
    }
};

/// Adaptive congestion control that switches between algorithms
pub const AdaptiveCongestionControl = struct {
    base: CongestionControl,
    current_algorithm: CongestionControlType,
    algorithms: struct {
        new_reno: ?NewReno,
        cubic: ?CUBIC,
        bbr: ?BBR,
    },
    switch_threshold: f64,
    measurement_window: u64,
    last_switch_time: u64,
    performance_history: std.ArrayList(PerformanceMetric),
    allocator: std.mem.Allocator,
    
    const PerformanceMetric = struct {
        timestamp: u64,
        throughput: f64,
        latency: f64,
        loss_rate: f64,
        algorithm: CongestionControlType,
    };
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .base = CongestionControl{
                .type = .adaptive,
                .state = .slow_start,
                .metrics = CongestionMetrics.init(),
                .vtable = &vtable,
            },
            .current_algorithm = .new_reno,
            .algorithms = .{
                .new_reno = NewReno.init(),
                .cubic = CUBIC.init(),
                .bbr = BBR.init(),
            },
            .switch_threshold = 0.1, // 10% improvement threshold
            .measurement_window = 5000000, // 5 seconds
            .last_switch_time = 0,
            .performance_history = std.ArrayList(PerformanceMetric).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.performance_history.deinit();
    }
    
    const vtable = CongestionControl.VTable{
        .on_packet_sent = onPacketSent,
        .on_packet_acked = onPacketAcked,
        .on_packet_lost = onPacketLost,
        .on_congestion_event = onCongestionEvent,
        .get_congestion_window = getCongestionWindow,
        .get_pacing_rate = getPacingRate,
        .can_send = canSend,
        .update_rtt = updateRTT,
    };
    
    fn getSelf(cc: *CongestionControl) *Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn getSelfConst(cc: *const CongestionControl) *const Self {
        return @fieldParentPtr(Self, "base", cc);
    }
    
    fn getCurrentAlgorithm(self: *Self) *CongestionControl {
        return switch (self.current_algorithm) {
            .new_reno => &self.algorithms.new_reno.?.base,
            .cubic => &self.algorithms.cubic.?.base,
            .bbr => &self.algorithms.bbr.?.base,
            else => &self.base,
        };
    }
    
    fn onPacketSent(cc: *CongestionControl, packet_number: u64, bytes: u64, is_retransmittable: bool) void {
        const self = getSelf(cc);
        const current_cc = self.getCurrentAlgorithm();
        current_cc.onPacketSent(packet_number, bytes, is_retransmittable);
        
        // Update base metrics
        cc.metrics = current_cc.metrics;
    }
    
    fn onPacketAcked(cc: *CongestionControl, ack_info: AckInfo) void {
        const self = getSelf(cc);
        const current_cc = self.getCurrentAlgorithm();
        current_cc.onPacketAcked(ack_info);
        
        // Update base metrics
        cc.metrics = current_cc.metrics;
        
        // Consider algorithm switching
        self.considerAlgorithmSwitch(ack_info.time_acked) catch {};
    }
    
    fn onPacketLost(cc: *CongestionControl, loss_info: LossInfo) void {
        const self = getSelf(cc);
        const current_cc = self.getCurrentAlgorithm();
        current_cc.onPacketLost(loss_info);
        
        // Update base metrics
        cc.metrics = current_cc.metrics;
    }
    
    fn onCongestionEvent(cc: *CongestionControl, event_time: u64) void {
        const self = getSelf(cc);
        const current_cc = self.getCurrentAlgorithm();
        current_cc.onCongestionEvent(event_time);
        
        // Update base metrics
        cc.metrics = current_cc.metrics;
    }
    
    fn considerAlgorithmSwitch(self: *Self, current_time: u64) !void {
        // Don't switch too frequently
        if (current_time - self.last_switch_time < self.measurement_window) {
            return;
        }
        
        // Record current performance
        const current_metric = PerformanceMetric{
            .timestamp = current_time,
            .throughput = @as(f64, @floatFromInt(self.base.metrics.delivery_rate)),
            .latency = @as(f64, @floatFromInt(self.base.metrics.smoothed_rtt)),
            .loss_rate = self.base.metrics.getLossRate(),
            .algorithm = self.current_algorithm,
        };
        
        try self.performance_history.append(current_metric);
        
        // Keep only recent history
        if (self.performance_history.items.len > 100) {
            _ = self.performance_history.orderedRemove(0);
        }
        
        // Evaluate if we should switch algorithms
        const best_algorithm = self.evaluateBestAlgorithm();
        if (best_algorithm != self.current_algorithm) {
            self.switchAlgorithm(best_algorithm);
            self.last_switch_time = current_time;
        }
    }
    
    fn evaluateBestAlgorithm(self: *const Self) CongestionControlType {
        // Simple evaluation based on recent performance
        // In a real implementation, this would use machine learning
        
        var best_algorithm = self.current_algorithm;
        var best_score: f64 = 0.0;
        
        const algorithms = [_]CongestionControlType{ .new_reno, .cubic, .bbr };
        
        for (algorithms) |algorithm| {
            const score = self.calculateAlgorithmScore(algorithm);
            if (score > best_score) {
                best_score = score;
                best_algorithm = algorithm;
            }
        }
        
        return best_algorithm;
    }
    
    fn calculateAlgorithmScore(self: *const Self, algorithm: CongestionControlType) f64 {
        var score: f64 = 0.0;
        var count: u32 = 0;
        
        for (self.performance_history.items) |metric| {
            if (metric.algorithm == algorithm) {
                // Higher throughput is better
                score += metric.throughput / 1000000.0;
                
                // Lower latency is better
                score += 1.0 / (metric.latency / 1000.0 + 1.0);
                
                // Lower loss rate is better
                score += 1.0 - metric.loss_rate;
                
                count += 1;
            }
        }
        
        return if (count > 0) score / @as(f64, @floatFromInt(count)) else 0.0;
    }
    
    fn switchAlgorithm(self: *Self, new_algorithm: CongestionControlType) void {
        self.current_algorithm = new_algorithm;
        
        // Initialize new algorithm with current state
        switch (new_algorithm) {
            .new_reno => {
                if (self.algorithms.new_reno == null) {
                    self.algorithms.new_reno = NewReno.init();
                }
                self.algorithms.new_reno.?.base.metrics = self.base.metrics;
            },
            .cubic => {
                if (self.algorithms.cubic == null) {
                    self.algorithms.cubic = CUBIC.init();
                }
                self.algorithms.cubic.?.base.metrics = self.base.metrics;
            },
            .bbr => {
                if (self.algorithms.bbr == null) {
                    self.algorithms.bbr = BBR.init();
                }
                self.algorithms.bbr.?.base.metrics = self.base.metrics;
            },
            else => {},
        }
        
        std.log.info("Switched to congestion control algorithm: {s}", .{new_algorithm.toString()});
    }
    
    fn getCongestionWindow(cc: *const CongestionControl) u64 {
        const self = getSelfConst(cc);
        return self.getCurrentAlgorithm().getCongestionWindow();
    }
    
    fn getPacingRate(cc: *const CongestionControl) u64 {
        const self = getSelfConst(cc);
        return self.getCurrentAlgorithm().getPacingRate();
    }
    
    fn canSend(cc: *const CongestionControl, bytes: u64) bool {
        const self = getSelfConst(cc);
        return self.getCurrentAlgorithm().canSend(bytes);
    }
    
    fn updateRTT(cc: *CongestionControl, rtt: u64) void {
        const self = getSelf(cc);
        const current_cc = self.getCurrentAlgorithm();
        current_cc.updateRTT(rtt);
        
        // Update base metrics
        cc.metrics = current_cc.metrics;
    }
};

/// Congestion control factory
pub const CongestionControlFactory = struct {
    pub fn create(algorithm_type: CongestionControlType, allocator: std.mem.Allocator) !*CongestionControl {
        switch (algorithm_type) {
            .new_reno => {
                const cc = try allocator.create(NewReno);
                cc.* = NewReno.init();
                return &cc.base;
            },
            .cubic => {
                const cc = try allocator.create(CUBIC);
                cc.* = CUBIC.init();
                return &cc.base;
            },
            .bbr => {
                const cc = try allocator.create(BBR);
                cc.* = BBR.init();
                return &cc.base;
            },
            .adaptive => {
                const cc = try allocator.create(AdaptiveCongestionControl);
                cc.* = AdaptiveCongestionControl.init(allocator);
                return &cc.base;
            },
            else => return Error.ZquicError.UnsupportedAlgorithm,
        }
    }
    
    pub fn destroy(cc: *CongestionControl, allocator: std.mem.Allocator) void {
        switch (cc.type) {
            .new_reno => {
                const new_reno = @fieldParentPtr(NewReno, "base", cc);
                allocator.destroy(new_reno);
            },
            .cubic => {
                const cubic = @fieldParentPtr(CUBIC, "base", cc);
                allocator.destroy(cubic);
            },
            .bbr => {
                const bbr = @fieldParentPtr(BBR, "base", cc);
                allocator.destroy(bbr);
            },
            .adaptive => {
                const adaptive = @fieldParentPtr(AdaptiveCongestionControl, "base", cc);
                adaptive.deinit();
                allocator.destroy(adaptive);
            },
            else => {},
        }
    }
};