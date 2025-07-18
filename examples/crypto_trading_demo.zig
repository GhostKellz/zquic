//! High-Frequency Crypto Trading Demo using ZQUIC v0.8.2
//!
//! Demonstrates all the new crypto-focused features:
//! - Post-quantum hybrid TLS (ML-KEM-768 + X25519)
//! - Zero-RTT connection resumption for ultra-low latency
//! - BBR congestion control optimized for trading
//! - Connection pooling and multiplexing
//! - Real-time telemetry and monitoring

const std = @import("std");
const zquic = @import("zquic");

// Import new v0.8.2 crypto features
const HybridPQTlsContext = zquic.crypto.HybridPQTlsContext;
const HybridConfig = zquic.crypto.HybridConfig;
const ZeroRttContext = zquic.crypto.ZeroRttContext;
const ZeroRttSessionManager = zquic.crypto.ZeroRttSessionManager;
const CryptoOptimizedCongestionController = zquic.core.CryptoOptimizedCongestionController;
const CryptoWorkloadType = zquic.core.CryptoWorkloadType;
const CryptoConnectionMultiplexer = zquic.performance.CryptoConnectionMultiplexer;
const CryptoConnectionPoolConfig = zquic.performance.CryptoConnectionPoolConfig;
const ProtocolType = zquic.performance.ProtocolType;
const ConnectionPriority = zquic.performance.ConnectionPriority;
const WorkloadPattern = zquic.performance.WorkloadPattern;
const CryptoTelemetrySystem = zquic.monitoring.CryptoTelemetrySystem;
const CryptoTelemetryConfig = zquic.monitoring.CryptoTelemetryConfig;

/// Trading order types
const OrderType = enum {
    market_buy,
    market_sell,
    limit_buy,
    limit_sell,
    stop_loss,
    take_profit,
};

/// Trading order priority
const OrderPriority = enum {
    emergency_liquidation, // Critical for margin trading
    arbitrage, // High priority for arbitrage opportunities
    normal_trading, // Standard trading orders
    portfolio_rebalancing, // Background priority
};

/// Trading order structure
const TradingOrder = struct {
    id: u64,
    symbol: []const u8, // e.g., "ETH/USD", "BTC/USD"
    order_type: OrderType,
    priority: OrderPriority,
    quantity: f64,
    price: ?f64, // null for market orders
    timestamp: i64,
    
    pub fn serialize(self: *const @This(), allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, 
            "{{\"id\":{},\"symbol\":\"{s}\",\"type\":\"{}\",\"priority\":\"{}\",\"qty\":{d:.8},\"price\":{?d:.2},\"ts\":{}}}",
            .{ self.id, self.symbol, self.order_type, self.priority, self.quantity, self.price, self.timestamp }
        );
    }
};

/// Market data update
const MarketUpdate = struct {
    symbol: []const u8,
    bid: f64,
    ask: f64,
    last_price: f64,
    volume_24h: f64,
    timestamp: i64,
    
    pub fn serialize(self: *const @This(), allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator,
            "{{\"symbol\":\"{s}\",\"bid\":{d:.2},\"ask\":{d:.2},\"last\":{d:.2},\"vol24h\":{d:.2},\"ts\":{}}}",
            .{ self.symbol, self.bid, self.ask, self.last_price, self.volume_24h, self.timestamp }
        );
    }
};

/// High-performance crypto trading client
const CryptoTradingClient = struct {
    // Core ZQUIC components with v0.8.2 features
    pq_tls_context: HybridPQTlsContext,
    zero_rtt_session_manager: ZeroRttSessionManager,
    congestion_controller: CryptoOptimizedCongestionController,
    connection_multiplexer: CryptoConnectionMultiplexer,
    telemetry_system: CryptoTelemetrySystem,
    
    // Trading state
    next_order_id: std.atomic.Atomic(u64),
    orders_sent: std.atomic.Atomic(u64),
    orders_executed: std.atomic.Atomic(u64),
    total_volume: std.atomic.Atomic(u64), // in cents to avoid floating point atomics
    
    // Performance tracking
    last_order_latency: std.atomic.Atomic(u64), // microseconds
    avg_execution_time: std.atomic.Atomic(u64), // microseconds
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) !Self {
        // Configure hybrid post-quantum TLS
        const hybrid_config = HybridConfig{
            .enable_ml_kem = true,
            .enable_x25519 = true,
            .prefer_pq = true,
            .fallback_to_classical = true,
        };
        
        // Configure connection pool for high-frequency trading
        const pool_config = CryptoConnectionPoolConfig{
            .initial_pool_size = 50, // Start with many connections for trading
            .max_pool_size = 1000, // Scale up for high volume
            .min_pool_size = 20,
            .idle_timeout_ms = 30_000, // 30 seconds for responsive trading
            .health_check_interval_ms = 1_000, // 1 second for trading stability
            .acquire_timeout_ms = 100, // 100ms max for ultra-low latency
            .enable_zero_rtt = true,
            .enable_post_quantum = true,
            .enable_connection_migration = true,
            .enable_priority_queuing = true,
            .enable_adaptive_scaling = true,
            .enable_load_balancing = true,
            .enable_burst_handling = true,
            .enable_protocol_multiplexing = true,
            .max_concurrent_protocols = 4,
        };
        
        // Configure telemetry for crypto trading
        const telemetry_config = CryptoTelemetryConfig{
            .metrics_collection_interval_ms = 100, // 100ms for real-time trading
            .performance_analysis_interval_ms = 1000, // 1 second analysis
            .health_check_interval_ms = 500, // 500ms health checks
            .max_metric_history = 36000, // 1 hour at 100ms intervals
            .enable_persistence = true,
            .latency_warning_threshold_us = 1_000, // 1ms warning for trading
            .latency_critical_threshold_us = 5_000, // 5ms critical for trading
            .loss_rate_warning_threshold = 0.001, // 0.1% warning
            .loss_rate_critical_threshold = 0.01, // 1% critical
            .throughput_warning_threshold_mbps = 50.0, // 50 Mbps minimum for trading
            .zero_rtt_success_rate_threshold = 0.95, // 95% minimum for trading
            .connection_establishment_threshold_us = 1000, // 1ms max
            .protocol_switch_threshold_us = 100, // 100μs max
            .enable_prometheus_export = true,
            .prometheus_port = 9091,
            .enable_json_export = true,
            .enable_csv_export = true,
        };
        
        return Self{
            .pq_tls_context = try HybridPQTlsContext.init(allocator, false, hybrid_config),
            .zero_rtt_session_manager = try ZeroRttSessionManager.init(allocator),
            .congestion_controller = CryptoOptimizedCongestionController.init(allocator, .bbr, .high_frequency_trading),
            .connection_multiplexer = CryptoConnectionMultiplexer.init(allocator, pool_config),
            .telemetry_system = CryptoTelemetrySystem.init(allocator, telemetry_config),
            .next_order_id = std.atomic.Atomic(u64).init(1),
            .orders_sent = std.atomic.Atomic(u64).init(0),
            .orders_executed = std.atomic.Atomic(u64).init(0),
            .total_volume = std.atomic.Atomic(u64).init(0),
            .last_order_latency = std.atomic.Atomic(u64).init(0),
            .avg_execution_time = std.atomic.Atomic(u64).init(0),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.pq_tls_context.deinit();
        self.zero_rtt_session_manager.deinit();
        self.connection_multiplexer.deinit();
        self.telemetry_system.deinit();
    }
    
    /// Send high-priority trading order with ultra-low latency
    pub fn sendTradingOrder(self: *Self, order: TradingOrder) !void {
        const start_time = std.time.microTimestamp();
        
        // Determine connection priority based on order priority
        const conn_priority = switch (order.priority) {
            .emergency_liquidation => ConnectionPriority.critical,
            .arbitrage => ConnectionPriority.high,
            .normal_trading => ConnectionPriority.normal,
            .portfolio_rebalancing => ConnectionPriority.background,
        };
        
        // Acquire connection with 0-RTT if possible
        const connection = try self.connection_multiplexer.acquireConnection(
            .custom, // Custom trading protocol
            conn_priority,
            .high_frequency_trading
        );
        defer self.connection_multiplexer.releaseConnection(connection);
        
        // Serialize order
        const order_data = try order.serialize(self.allocator);
        defer self.allocator.free(order_data);
        
        // Send order with crypto-optimized congestion control
        const can_send = self.congestion_controller.canSend(
            @as(u32, @intCast(order_data.len)), 
            order.priority == .emergency_liquidation or order.priority == .arbitrage
        );
        
        if (!can_send) {
            return error.CongestionControl;
        }
        
        // Simulate sending order (in real implementation, this would use QUIC)
        self.congestion_controller.onPacketSent(@as(u32, @intCast(order_data.len)));
        
        // Track metrics
        const end_time = std.time.microTimestamp();
        const latency = end_time - start_time;
        
        _ = self.orders_sent.fetchAdd(1, .Monotonic);
        _ = self.last_order_latency.store(latency, .Monotonic);
        
        // Update telemetry
        const protocol = .custom;
        const telemetry_priority = switch (order.priority) {
            .emergency_liquidation => .critical,
            .arbitrage => .high,
            .normal_trading => .normal,
            .portfolio_rebalancing => .background,
        };
        
        self.telemetry_system.recordRequest(protocol, telemetry_priority, latency, order_data.len);
        
        std.log.info("Sent {s} order for {s}: {} μs latency (Order ID: {})", .{
            @tagName(order.order_type), order.symbol, latency, order.id
        });
        
        // Simulate order execution confirmation
        try self.simulateOrderExecution(order, latency);
    }
    
    /// Simulate order execution with realistic latency
    fn simulateOrderExecution(self: *Self, order: TradingOrder, send_latency: u64) !void {
        // Simulate execution time based on order priority
        const execution_delay = switch (order.priority) {
            .emergency_liquidation => 100, // 100μs for critical orders
            .arbitrage => 500, // 500μs for arbitrage
            .normal_trading => 2000, // 2ms for normal orders
            .portfolio_rebalancing => 10000, // 10ms for background orders
        };
        
        // Simulate network and processing delay
        std.time.sleep(execution_delay * 1000); // Convert to nanoseconds
        
        const execution_time = send_latency + execution_delay;
        
        _ = self.orders_executed.fetchAdd(1, .Monotonic);
        
        // Update average execution time
        const current_avg = self.avg_execution_time.load(.Monotonic);
        const new_avg = (current_avg + execution_time) / 2;
        _ = self.avg_execution_time.store(new_avg, .Monotonic);
        
        // Update volume (convert to cents to avoid floating point atomics)
        if (order.price) |price| {
            const volume_cents = @as(u64, @intFromFloat(order.quantity * price * 100));
            _ = self.total_volume.fetchAdd(volume_cents, .Monotonic);
        }
        
        std.log.info("Order {} executed: {} μs total time", .{ order.id, execution_time });
    }
    
    /// Subscribe to market data with connection multiplexing
    pub fn subscribeMarketData(self: *Self, symbols: []const []const u8) !void {
        // Use HTTP/3 for market data subscription
        const connection = try self.connection_multiplexer.acquireConnection(
            .http3,
            .high,
            .defi_api
        );
        defer self.connection_multiplexer.releaseConnection(connection);
        
        for (symbols) |symbol| {
            const subscription_data = try std.fmt.allocPrint(self.allocator,
                "{{\"action\":\"subscribe\",\"channel\":\"ticker\",\"symbol\":\"{s}\"}}", .{symbol}
            );
            defer self.allocator.free(subscription_data);
            
            // Record subscription request
            self.telemetry_system.recordRequest(.http3, .high, 500, subscription_data.len); // 500μs typical
            
            std.log.info("Subscribed to market data for {s}", .{symbol});
        }
    }
    
    /// Process incoming market data updates
    pub fn processMarketUpdate(self: *Self, update: MarketUpdate) !void {
        const processing_start = std.time.microTimestamp();
        
        // Simulate market data processing
        // In a real implementation, this would trigger trading algorithms
        
        const market_data = try update.serialize(self.allocator);
        defer self.allocator.free(market_data);
        
        const processing_time = std.time.microTimestamp() - processing_start;
        
        // Record market data processing
        self.telemetry_system.recordRequest(.http3, .normal, processing_time, market_data.len);
        
        std.log.debug("Processed market update for {s}: {d:.2} @ {} μs", .{
            update.symbol, update.last_price, processing_time
        });
    }
    
    /// Get real-time trading statistics
    pub fn getTradingStats(self: *const Self) struct {
        orders_sent: u64,
        orders_executed: u64,
        execution_rate: f32,
        avg_latency_us: u64,
        avg_execution_time_us: u64,
        total_volume_usd: f64,
        telemetry_summary: @TypeOf(self.telemetry_system.getPerformanceSummary()),
        congestion_stats: @TypeOf(self.congestion_controller.getCryptoStats()),
        connection_stats: @TypeOf(self.connection_multiplexer.getStats()),
    } {
        const orders_sent = self.orders_sent.load(.Monotonic);
        const orders_executed = self.orders_executed.load(.Monotonic);
        const execution_rate = if (orders_sent > 0) 
            @as(f32, @floatFromInt(orders_executed)) / @as(f32, @floatFromInt(orders_sent)) * 100.0 
        else 0.0;
        
        const total_volume_usd = @as(f64, @floatFromInt(self.total_volume.load(.Monotonic))) / 100.0;
        
        return .{
            .orders_sent = orders_sent,
            .orders_executed = orders_executed,
            .execution_rate = execution_rate,
            .avg_latency_us = self.last_order_latency.load(.Monotonic),
            .avg_execution_time_us = self.avg_execution_time.load(.Monotonic),
            .total_volume_usd = total_volume_usd,
            .telemetry_summary = self.telemetry_system.getPerformanceSummary(),
            .congestion_stats = self.congestion_controller.getCryptoStats(),
            .connection_stats = self.connection_multiplexer.getStats(),
        };
    }
    
    /// Run performance monitoring loop
    pub fn runMonitoring(self: *Self) !void {
        while (true) {
            // Collect telemetry metrics
            try self.telemetry_system.collectMetrics();
            
            // Perform connection pool maintenance
            try self.connection_multiplexer.performMaintenance();
            
            // Log performance summary every 10 seconds
            const stats = self.getTradingStats();
            if (stats.orders_sent % 100 == 0 and stats.orders_sent > 0) {
                std.log.info("Trading Performance Summary:");
                std.log.info("  Orders: {} sent, {} executed ({d:.1}% success rate)", .{
                    stats.orders_sent, stats.orders_executed, stats.execution_rate
                });
                std.log.info("  Latency: {} μs avg, {} μs execution", .{
                    stats.avg_latency_us, stats.avg_execution_time_us
                });
                std.log.info("  Volume: ${d:.2} USD", .{stats.total_volume_usd});
                std.log.info("  Connections: {} total, {d:.1} req/s", .{
                    stats.telemetry_summary.total_connections, stats.telemetry_summary.requests_per_second
                });
                std.log.info("  Network: {} μs p99 latency, {d:.1}% loss", .{
                    stats.telemetry_summary.p99_latency_us, stats.telemetry_summary.packet_loss_rate * 100
                });
            }
            
            std.time.sleep(1_000_000_000); // 1 second
        }
    }
};

/// Demo function showcasing crypto trading with ZQUIC v0.8.2
pub fn runCryptoTradingDemo(allocator: std.mem.Allocator) !void {
    std.log.info("🚀 Starting ZQUIC v0.8.2 Crypto Trading Demo");
    std.log.info("Features: Post-Quantum Hybrid TLS, Zero-RTT, BBR, Connection Pooling, Telemetry");
    
    // Initialize high-performance trading client
    var trading_client = try CryptoTradingClient.init(allocator);
    defer trading_client.deinit();
    
    // Subscribe to market data for major crypto pairs
    const symbols = [_][]const u8{ "BTC/USD", "ETH/USD", "SOL/USD", "AVAX/USD" };
    try trading_client.subscribeMarketData(&symbols);
    
    // Start monitoring in background (simplified for demo)
    std.log.info("📊 Starting performance monitoring...");
    
    // Simulate high-frequency trading session
    std.log.info("💹 Starting high-frequency trading simulation...");
    
    var order_id: u64 = 1;
    const demo_duration_seconds = 30;
    const orders_per_second = 50; // High frequency
    
    var demo_timer = try std.time.Timer.start();
    
    while (demo_timer.read() < demo_duration_seconds * std.time.ns_per_s) {
        // Generate various types of trading orders
        const order_types = [_]OrderType{ .market_buy, .market_sell, .limit_buy, .limit_sell };
        const priorities = [_]OrderPriority{ .arbitrage, .normal_trading, .emergency_liquidation, .portfolio_rebalancing };
        
        const order = TradingOrder{
            .id = order_id,
            .symbol = symbols[order_id % symbols.len],
            .order_type = order_types[order_id % order_types.len],
            .priority = priorities[order_id % priorities.len],
            .quantity = 0.1 + (@as(f64, @floatFromInt(order_id % 100)) / 100.0), // 0.1 to 1.1
            .price = if (order_id % 2 == 0) 50000.0 + (@as(f64, @floatFromInt(order_id % 1000))) else null,
            .timestamp = std.time.microTimestamp(),
        };
        
        // Send trading order
        try trading_client.sendTradingOrder(order);
        
        // Simulate market data updates
        if (order_id % 10 == 0) {
            const market_update = MarketUpdate{
                .symbol = symbols[order_id % symbols.len],
                .bid = 49950.0 + (@as(f64, @floatFromInt(order_id % 100))),
                .ask = 50050.0 + (@as(f64, @floatFromInt(order_id % 100))),
                .last_price = 50000.0 + (@as(f64, @floatFromInt(order_id % 100))),
                .volume_24h = 1000000.0 + (@as(f64, @floatFromInt(order_id % 100000))),
                .timestamp = std.time.microTimestamp(),
            };
            
            try trading_client.processMarketUpdate(market_update);
        }
        
        order_id += 1;
        
        // Control frequency
        std.time.sleep(std.time.ns_per_s / orders_per_second);
        
        // Collect metrics periodically
        if (order_id % 100 == 0) {
            try trading_client.telemetry_system.collectMetrics();
        }
    }
    
    // Final statistics
    const final_stats = trading_client.getTradingStats();
    
    std.log.info("🎯 Crypto Trading Demo Completed!");
    std.log.info("Performance Results:");
    std.log.info("  📈 Orders: {} sent, {} executed ({d:.1}% success)", .{
        final_stats.orders_sent, final_stats.orders_executed, final_stats.execution_rate
    });
    std.log.info("  ⚡ Latency: {} μs average order latency", .{final_stats.avg_latency_us});
    std.log.info("  🏃 Execution: {} μs average execution time", .{final_stats.avg_execution_time_us});
    std.log.info("  💰 Volume: ${d:.2} USD total trading volume", .{final_stats.total_volume_usd});
    
    std.log.info("Network Performance:");
    std.log.info("  🌐 Throughput: {d:.1} Mbps", .{final_stats.telemetry_summary.throughput_mbps});
    std.log.info("  📊 P99 Latency: {} μs", .{final_stats.telemetry_summary.p99_latency_us});
    std.log.info("  🔗 Zero-RTT Success: {d:.1}%", .{final_stats.telemetry_summary.zero_rtt_success_rate * 100});
    std.log.info("  📡 Connections: {}", .{final_stats.telemetry_summary.total_connections});
    
    std.log.info("Congestion Control (BBR for HFT):");
    std.log.info("  🚀 Algorithm: {s}", .{@tagName(final_stats.congestion_stats.algorithm)});
    std.log.info("  📈 Bandwidth: {d:.1} Mbps", .{@as(f32, @floatFromInt(final_stats.congestion_stats.bottleneck_bw)) / 1_000_000});
    std.log.info("  🎯 CWND: {} bytes", .{final_stats.congestion_stats.cwnd});
    std.log.info("  🔄 Loss Rate: {d:.3}%", .{final_stats.congestion_stats.loss_rate * 100});
    
    std.log.info("🛡️  Security: Post-Quantum Hybrid TLS (ML-KEM-768 + X25519) - Quantum Safe! ✓");
    std.log.info("⚡ Zero-RTT: Ultra-low latency connection resumption ✓");
    std.log.info("🧠 BBR: Crypto-optimized congestion control ✓");
    std.log.info("🔗 Multiplexing: Efficient connection pooling ✓");
    std.log.info("📊 Telemetry: Real-time performance monitoring ✓");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try runCryptoTradingDemo(allocator);
}