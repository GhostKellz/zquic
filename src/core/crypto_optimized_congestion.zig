//! Crypto-Optimized Congestion Control for QUIC
//!
//! Implements BBR and CUBIC algorithms specifically tuned for crypto/blockchain workloads
//! with high-throughput and low-latency requirements

const std = @import("std");
const congestion = @import("congestion.zig");
const Error = @import("../utils/error.zig");

/// BBR congestion control phases
const BbrPhase = enum {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

/// BBR congestion control state optimized for crypto
pub const CryptoBbrState = struct {
    // Core BBR parameters
    bottleneck_bandwidth: u64, // bits per second
    round_trip_time: u64, // microseconds
    delivery_rate: u64, // bits per second
    
    // State tracking
    phase: BbrPhase,
    cycle_index: u8,
    phase_start_time: u64,
    
    // Bandwidth probing
    probe_rtt_start: u64,
    probe_rtt_duration: u64,
    min_rtt_timestamp: u64,
    
    // Pacing and cwnd
    pacing_rate: u64,
    send_quantum: u32,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .bottleneck_bandwidth = 100_000_000, // 100 Mbps initial for crypto
            .round_trip_time = 10_000, // 10ms initial for trading
            .delivery_rate = 0,
            .phase = .startup,
            .cycle_index = 0,
            .phase_start_time = 0,
            .probe_rtt_start = 0,
            .probe_rtt_duration = 100_000, // 100ms for crypto responsiveness
            .min_rtt_timestamp = 0,
            .pacing_rate = 100_000_000,
            .send_quantum = 8760, // 6 * MSS for crypto bursts
        };
    }
};

/// CUBIC congestion control state tuned for crypto
pub const CryptoCubicState = struct {
    // CUBIC parameters
    beta: f64,
    c: f64, // scaling constant
    w_max: u64, // window size before last reduction
    k: f64, // time to reach w_max
    
    // State tracking
    epoch_start: u64,
    ack_count: u32,
    tcp_cwnd: u64,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .beta = 0.8, // More aggressive for crypto stability
            .c = 0.6, // Faster recovery
            .w_max = 0,
            .k = 0.0,
            .epoch_start = 0,
            .ack_count = 0,
            .tcp_cwnd = 0,
        };
    }
};

/// Crypto workload types for optimization
pub const CryptoWorkloadType = enum {
    high_frequency_trading, // Ultra-low latency, small packets
    blockchain_sync, // High throughput, large blocks
    defi_protocol, // Balanced latency/throughput
    mempool_gossip, // Bursty, medium priority
    consensus_voting, // Critical, time-sensitive
};

/// Advanced congestion controller optimized for crypto workloads
pub const CryptoOptimizedCongestionController = struct {
    algorithm: congestion.CongestionAlgorithm,
    state: congestion.CongestionState,
    workload_type: CryptoWorkloadType,
    rtt_stats: congestion.RttStats,
    
    // Algorithm-specific state
    bbr_state: CryptoBbrState,
    cubic_state: CryptoCubicState,
    
    // Common parameters
    congestion_window: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    min_window: u64,
    max_window: u64,
    
    // Performance tracking for crypto workloads
    packets_sent: u64,
    packets_acked: u64,
    packets_lost: u64,
    bytes_sent: u64,
    bytes_acked: u64,
    
    // Crypto-specific metrics
    high_priority_packets: u64, // Trading orders, block announcements
    critical_packets: u64, // Consensus, liquidations
    burst_allowance: u64, // For sudden traffic spikes
    priority_window_boost: u64, // Extra window for critical traffic
    
    // Performance optimizations
    fast_recovery_enabled: bool,
    adaptive_pacing: bool,
    burst_mitigation: bool,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, algorithm: congestion.CongestionAlgorithm, workload: CryptoWorkloadType) Self {
        var controller = Self{
            .algorithm = algorithm,
            .state = .slow_start,
            .workload_type = workload,
            .rtt_stats = congestion.RttStats.init(),
            .bbr_state = CryptoBbrState.init(),
            .cubic_state = CryptoCubicState.init(),
            .congestion_window = 0,
            .ssthresh = std.math.maxInt(u64),
            .bytes_in_flight = 0,
            .min_window = 0,
            .max_window = 0,
            .packets_sent = 0,
            .packets_acked = 0,
            .packets_lost = 0,
            .bytes_sent = 0,
            .bytes_acked = 0,
            .high_priority_packets = 0,
            .critical_packets = 0,
            .burst_allowance = 0,
            .priority_window_boost = 0,
            .fast_recovery_enabled = true,
            .adaptive_pacing = true,
            .burst_mitigation = true,
            .allocator = allocator,
        };
        
        // Configure for specific crypto workload
        controller.configureForWorkload();
        return controller;
    }
    
    /// Configure congestion control parameters based on crypto workload
    fn configureForWorkload(self: *Self) void {
        const MSS = 1460; // Maximum segment size
        
        switch (self.workload_type) {
            .high_frequency_trading => {
                // Ultra-low latency configuration
                self.congestion_window = 4 * MSS; // Small initial window
                self.min_window = 2 * MSS;
                self.max_window = 1024 * 1024; // 1MB max
                self.burst_allowance = 2 * MSS;
                self.priority_window_boost = 4 * MSS;
                self.bbr_state.send_quantum = MSS;
                self.bbr_state.probe_rtt_duration = 50_000; // 50ms
            },
            .blockchain_sync => {
                // High throughput configuration
                self.congestion_window = 50 * MSS; // Large initial window
                self.min_window = 20 * MSS;
                self.max_window = 1024 * 1024 * 256; // 256MB max
                self.burst_allowance = 100 * MSS;
                self.priority_window_boost = 50 * MSS;
                self.bbr_state.send_quantum = 10 * MSS;
            },
            .defi_protocol => {
                // Balanced configuration
                self.congestion_window = 20 * MSS;
                self.min_window = 8 * MSS;
                self.max_window = 1024 * 1024 * 32; // 32MB max
                self.burst_allowance = 20 * MSS;
                self.priority_window_boost = 10 * MSS;
                self.bbr_state.send_quantum = 4 * MSS;
            },
            .mempool_gossip => {
                // Bursty traffic configuration
                self.congestion_window = 30 * MSS;
                self.min_window = 10 * MSS;
                self.max_window = 1024 * 1024 * 64; // 64MB max
                self.burst_allowance = 50 * MSS;
                self.priority_window_boost = 20 * MSS;
                self.bbr_state.send_quantum = 6 * MSS;
            },
            .consensus_voting => {
                // Critical timing configuration
                self.congestion_window = 8 * MSS;
                self.min_window = 4 * MSS;
                self.max_window = 1024 * 1024 * 8; // 8MB max
                self.burst_allowance = 8 * MSS;
                self.priority_window_boost = 8 * MSS;
                self.bbr_state.send_quantum = 2 * MSS;
                self.bbr_state.probe_rtt_duration = 25_000; // 25ms
            },
        }
    }
    
    /// Process ACK and update congestion window with crypto optimizations
    pub fn onPacketAcked(self: *Self, packet_size: u32, rtt_sample: u64, priority: enum { normal, high, critical }) void {
        self.packets_acked += 1;
        self.bytes_acked += packet_size;
        self.bytes_in_flight = if (self.bytes_in_flight >= packet_size) 
            self.bytes_in_flight - packet_size else 0;
        
        // Track priority packets for crypto workload analysis
        switch (priority) {
            .high => self.high_priority_packets += 1,
            .critical => self.critical_packets += 1,
            .normal => {},
        }
        
        // Update RTT stats with crypto-specific smoothing
        self.rtt_stats.updateRtt(rtt_sample, 0);
        
        switch (self.algorithm) {
            .bbr => self.cryptoBbrOnPacketAcked(packet_size, rtt_sample, priority),
            .cubic => self.cryptoCubicOnPacketAcked(packet_size, priority),
            .new_reno => self.cryptoNewRenoOnPacketAcked(packet_size, priority),
        }
    }
    
    /// Process packet loss with crypto-aware recovery
    pub fn onPacketLost(self: *Self, packet_size: u32, priority: enum { normal, high, critical }) void {
        self.packets_lost += 1;
        self.bytes_in_flight = if (self.bytes_in_flight >= packet_size) 
            self.bytes_in_flight - packet_size else 0;
        
        // More conservative loss response for critical crypto traffic
        const loss_severity = switch (priority) {
            .critical => 1.0, // Full reaction
            .high => 0.8, // Slightly less aggressive
            .normal => 0.6, // More conservative
        };
        
        switch (self.algorithm) {
            .bbr => self.cryptoBbrOnPacketLost(packet_size, loss_severity),
            .cubic => self.cryptoCubicOnPacketLost(packet_size, loss_severity),
            .new_reno => self.cryptoNewRenoOnPacketLost(packet_size, loss_severity),
        }
    }
    
    /// Check if we can send a packet with crypto priority handling
    pub fn canSend(self: *const Self, packet_size: u32, priority: enum { normal, high, critical }) bool {
        const base_window = self.congestion_window;
        var effective_window = base_window;
        
        // Add priority boost for high/critical packets
        switch (priority) {
            .critical => effective_window += self.priority_window_boost * 2,
            .high => effective_window += self.priority_window_boost,
            .normal => {
                // Add burst allowance for normal packets
                effective_window += self.burst_allowance;
            },
        }
        
        return self.bytes_in_flight + packet_size <= effective_window;
    }
    
    /// Update on packet sent
    pub fn onPacketSent(self: *Self, packet_size: u32) void {
        self.packets_sent += 1;
        self.bytes_sent += packet_size;
        self.bytes_in_flight += packet_size;
    }
    
    /// Crypto-optimized BBR ACK processing
    fn cryptoBbrOnPacketAcked(self: *Self, packet_size: u32, rtt_sample: u64, priority: enum { normal, high, critical }) void {
        _ = packet_size;
        _ = priority;
        
        // Update delivery rate with crypto-specific estimation
        self.bbr_state.delivery_rate = self.estimateCryptoDeliveryRate();
        
        // More responsive bandwidth updates for crypto
        const bandwidth_gain = switch (self.workload_type) {
            .high_frequency_trading => 0.5, // Very responsive
            .consensus_voting => 0.4, // Quick adaptation
            .defi_protocol => 0.3, // Balanced
            .mempool_gossip => 0.25, // Moderate
            .blockchain_sync => 0.2, // Conservative
        };
        
        self.bbr_state.bottleneck_bandwidth = @as(u64, @intFromFloat(
            @as(f64, @floatFromInt(self.bbr_state.bottleneck_bandwidth)) * (1.0 - bandwidth_gain) +
            @as(f64, @floatFromInt(self.bbr_state.delivery_rate)) * bandwidth_gain
        ));
        
        // Update RTT with crypto-aware filtering
        if (rtt_sample < self.bbr_state.round_trip_time or self.bbr_state.round_trip_time == 0) {
            self.bbr_state.round_trip_time = rtt_sample;
            self.bbr_state.min_rtt_timestamp = std.time.microTimestamp();
        }
        
        self.updateCryptoBbrState();
    }
    
    /// Crypto-optimized CUBIC ACK processing
    fn cryptoCubicOnPacketAcked(self: *Self, packet_size: u32, priority: enum { normal, high, critical }) void {
        // Priority-aware window growth
        const growth_multiplier = switch (priority) {
            .critical => 3, // Aggressive growth for critical packets
            .high => 2, // Moderate growth
            .normal => 1, // Standard growth
        };
        
        if (self.state == .slow_start) {
            self.congestion_window += packet_size * growth_multiplier;
            if (self.congestion_window >= self.ssthresh) {
                self.state = .congestion_avoidance;
            }
        } else {
            self.cryptoCubicUpdate(growth_multiplier);
        }
        
        self.congestion_window = @min(self.congestion_window, self.max_window);
    }
    
    /// Crypto-optimized New Reno ACK processing
    fn cryptoNewRenoOnPacketAcked(self: *Self, packet_size: u32, priority: enum { normal, high, critical }) void {
        // Priority-aware growth similar to CUBIC
        const growth_factor = switch (priority) {
            .critical => 2.0,
            .high => 1.5,
            .normal => 1.0,
        };
        
        if (self.state == .slow_start) {
            self.congestion_window += @as(u64, @intFromFloat(@as(f64, @floatFromInt(packet_size)) * growth_factor));
            if (self.congestion_window >= self.ssthresh) {
                self.state = .congestion_avoidance;
            }
        } else if (self.state == .congestion_avoidance) {
            const increase = @as(u64, @intFromFloat(@as(f64, @floatFromInt(packet_size * packet_size)) / @as(f64, @floatFromInt(self.congestion_window)) * growth_factor));
            self.congestion_window += increase;
        }
        
        self.congestion_window = @min(self.congestion_window, self.max_window);
    }
    
    /// Crypto-aware BBR loss processing
    fn cryptoBbrOnPacketLost(self: *Self, packet_size: u32, loss_severity: f64) void {
        _ = packet_size;
        _ = loss_severity;
        // BBR doesn't react to individual losses, but we can adjust delivery rate estimates
        self.bbr_state.delivery_rate = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.bbr_state.delivery_rate)) * 0.95));
    }
    
    /// Crypto-aware CUBIC loss processing
    fn cryptoCubicOnPacketLost(self: *Self, packet_size: u32, loss_severity: f64) void {
        _ = packet_size;
        
        self.cubic_state.w_max = @as(f64, @floatFromInt(self.congestion_window));
        
        // Adjust reduction based on loss severity for crypto workloads
        const reduction_factor = self.cubic_state.beta * loss_severity;
        self.congestion_window = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.congestion_window)) * (1.0 - reduction_factor)));
        self.congestion_window = @max(self.congestion_window, self.min_window);
        self.ssthresh = self.congestion_window;
        
        if (self.fast_recovery_enabled) {
            self.state = .recovery;
        }
        
        // Reset CUBIC epoch
        self.cubic_state.epoch_start = std.time.microTimestamp();
        self.cubic_state.k = std.math.cbrt((self.cubic_state.w_max * reduction_factor) / self.cubic_state.c);
    }
    
    /// Crypto-aware New Reno loss processing
    fn cryptoNewRenoOnPacketLost(self: *Self, packet_size: u32, loss_severity: f64) void {
        _ = packet_size;
        
        const reduction = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.congestion_window)) * 0.5 * loss_severity));
        self.ssthresh = @max(self.congestion_window - reduction, self.min_window);
        self.congestion_window = self.ssthresh;
        self.state = .recovery;
    }
    
    /// Update BBR state machine with crypto optimizations
    fn updateCryptoBbrState(self: *Self) void {
        const now = std.time.microTimestamp();
        
        switch (self.bbr_state.phase) {
            .startup => {
                // Crypto-aware startup exit
                const exit_threshold = switch (self.workload_type) {
                    .high_frequency_trading => 1.05, // Very quick exit
                    .consensus_voting => 1.1, // Quick exit
                    .defi_protocol => 1.15, // Balanced
                    .mempool_gossip => 1.2, // Moderate
                    .blockchain_sync => 1.25, // Conservative
                };
                
                if (self.bbr_state.delivery_rate < @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.bbr_state.bottleneck_bandwidth)) * exit_threshold))) {
                    self.bbr_state.phase = .drain;
                    self.bbr_state.phase_start_time = now;
                }
            },
            .drain => {
                if (self.bytes_in_flight <= self.getCryptoBdp()) {
                    self.bbr_state.phase = .probe_bw;
                    self.bbr_state.phase_start_time = now;
                }
            },
            .probe_bw => {
                // Faster cycling for crypto responsiveness
                const cycle_duration = self.bbr_state.round_trip_time * 2;
                if (now - self.bbr_state.phase_start_time > cycle_duration) {
                    self.bbr_state.cycle_index = (self.bbr_state.cycle_index + 1) % 8;
                    self.bbr_state.phase_start_time = now;
                }
            },
            .probe_rtt => {
                if (now - self.bbr_state.probe_rtt_start > self.bbr_state.probe_rtt_duration) {
                    self.bbr_state.phase = .probe_bw;
                    self.bbr_state.phase_start_time = now;
                }
            },
        }
        
        // Update congestion window with crypto BDP
        const bdp = self.getCryptoBdp();
        self.congestion_window = @max(bdp, self.min_window);
        
        // Update pacing rate with adaptive pacing
        if (self.adaptive_pacing) {
            const pacing_gain = switch (self.bbr_state.phase) {
                .startup => 2.77, // Fast startup
                .drain => 0.75, // Drain queue
                .probe_bw => 1.0, // Steady state
                .probe_rtt => 1.0, // Maintain
            };
            self.bbr_state.pacing_rate = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.bbr_state.bottleneck_bandwidth)) * pacing_gain));
        }
    }
    
    /// Crypto-optimized CUBIC window update
    fn cryptoCubicUpdate(self: *Self, growth_multiplier: u32) void {
        const now = std.time.microTimestamp();
        const t = @as(f64, @floatFromInt(now - self.cubic_state.epoch_start)) / 1_000_000.0;
        
        // CUBIC function with crypto optimizations
        const cubic_window = self.cubic_state.c * std.math.pow(f64, t - self.cubic_state.k, 3) + self.cubic_state.w_max;
        
        // TCP-friendly rate with growth multiplier
        self.cubic_state.tcp_cwnd += 1460 * growth_multiplier;
        
        const target_window = @max(@as(u64, @intFromFloat(@max(cubic_window, 0))), self.cubic_state.tcp_cwnd);
        
        if (target_window > self.congestion_window) {
            self.congestion_window = @min(target_window, self.max_window);
        }
    }
    
    /// Estimate delivery rate optimized for crypto workloads
    fn estimateCryptoDeliveryRate(self: *const Self) u64 {
        if (self.rtt_stats.smoothed_rtt == 0) return self.bbr_state.delivery_rate;
        
        // Crypto-optimized delivery rate estimation
        const base_rate = (self.bytes_acked * 8 * 1_000_000) / self.rtt_stats.smoothed_rtt;
        
        // Adjust for crypto workload characteristics
        const workload_factor = switch (self.workload_type) {
            .high_frequency_trading => 1.2, // Boost for low latency
            .blockchain_sync => 1.0, // Standard
            .defi_protocol => 1.1, // Slight boost
            .mempool_gossip => 0.9, // Slightly conservative
            .consensus_voting => 1.3, // Aggressive for time-critical
        };
        
        return @as(u64, @intFromFloat(@as(f64, @floatFromInt(base_rate)) * workload_factor));
    }
    
    /// Get crypto-optimized bandwidth-delay product
    fn getCryptoBdp(self: *const Self) u64 {
        const base_bdp = (self.bbr_state.bottleneck_bandwidth * self.bbr_state.round_trip_time) / (8 * 1_000_000);
        
        // Crypto workload BDP adjustments
        const bdp_multiplier = switch (self.workload_type) {
            .high_frequency_trading => 0.5, // Small BDP for low latency
            .blockchain_sync => 2.0, // Large BDP for throughput
            .defi_protocol => 1.0, // Standard BDP
            .mempool_gossip => 1.5, // Larger for bursts
            .consensus_voting => 0.75, // Moderate for responsiveness
        };
        
        return @as(u64, @intFromFloat(@as(f64, @floatFromInt(base_bdp)) * bdp_multiplier));
    }
    
    /// Get current pacing rate with crypto optimizations
    pub fn getPacingRate(self: *const Self) u64 {
        return switch (self.algorithm) {
            .bbr => self.bbr_state.pacing_rate,
            .cubic, .new_reno => {
                const base_rate = (self.congestion_window * 8 * 1_000_000) / @max(self.rtt_stats.smoothed_rtt, 1);
                // Apply workload-specific pacing adjustments
                const pacing_factor = switch (self.workload_type) {
                    .high_frequency_trading => 1.5, // Faster pacing
                    .consensus_voting => 1.3, // Quick response
                    .defi_protocol => 1.1, // Slight boost
                    .mempool_gossip => 1.0, // Standard
                    .blockchain_sync => 0.9, // Slightly slower for stability
                };
                return @as(u64, @intFromFloat(@as(f64, @floatFromInt(base_rate)) * pacing_factor));
            },
        };
    }
    
    /// Get comprehensive crypto congestion control statistics
    pub fn getCryptoStats(self: *const Self) struct {
        algorithm: congestion.CongestionAlgorithm,
        workload_type: CryptoWorkloadType,
        state: congestion.CongestionState,
        cwnd: u64,
        bytes_in_flight: u64,
        rtt: u64,
        pacing_rate: u64,
        loss_rate: f64,
        high_priority_ratio: f64,
        critical_priority_ratio: f64,
        bottleneck_bw: u64,
        delivery_rate: u64,
        burst_allowance: u64,
        bbr_phase: ?BbrPhase,
    } {
        const loss_rate = if (self.packets_sent > 0) 
            @as(f64, @floatFromInt(self.packets_lost)) / @as(f64, @floatFromInt(self.packets_sent))
        else 0.0;
        
        const hp_ratio = if (self.packets_acked > 0)
            @as(f64, @floatFromInt(self.high_priority_packets)) / @as(f64, @floatFromInt(self.packets_acked))
        else 0.0;
        
        const crit_ratio = if (self.packets_acked > 0)
            @as(f64, @floatFromInt(self.critical_packets)) / @as(f64, @floatFromInt(self.packets_acked))
        else 0.0;
        
        return .{
            .algorithm = self.algorithm,
            .workload_type = self.workload_type,
            .state = self.state,
            .cwnd = self.congestion_window,
            .bytes_in_flight = self.bytes_in_flight,
            .rtt = self.rtt_stats.smoothed_rtt,
            .pacing_rate = self.getPacingRate(),
            .loss_rate = loss_rate,
            .high_priority_ratio = hp_ratio,
            .critical_priority_ratio = crit_ratio,
            .bottleneck_bw = self.bbr_state.bottleneck_bandwidth,
            .delivery_rate = self.bbr_state.delivery_rate,
            .burst_allowance = self.burst_allowance,
            .bbr_phase = if (self.algorithm == .bbr) self.bbr_state.phase else null,
        };
    }
};