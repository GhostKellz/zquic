//! GhostScale VPN Example
//!
//! Demonstrates a complete tailscale-like VPN implementation using zQUIC with:
//! - UDP multiplexing for multiple connections
//! - TokiZ async runtime integration
//! - VPN packet routing
//! - Load balancing with connection pooling
//! - Enhanced TLS 1.3 cryptography

const std = @import("std");
const zquic = @import("zquic");

/// GhostScale VPN node configuration
pub const VpnNodeConfig = struct {
    node_id: []const u8,
    listen_address: std.net.Address,
    peer_addresses: []const std.net.Address,
    max_connections: u32 = 100,
    enable_load_balancing: bool = true,
    cipher_suite: zquic.EnhancedCrypto.EnhancedCipherSuite = .aes_256_gcm_sha384,
};

/// GhostScale VPN node
pub const VpnNode = struct {
    config: VpnNodeConfig,
    allocator: std.mem.Allocator,
    
    // Core components
    runtime: zquic.AsyncRuntime.QuicRuntime,
    router: zquic.VpnRouter.PacketRouter,
    load_balancer: ?zquic.LoadBalancer.ConnectionLoadBalancer,
    tls_context: zquic.EnhancedCrypto.EnhancedTlsContext,
    
    // Active connections
    connections: std.ArrayList(*zquic.Connection.Connection),
    peer_connections: std.HashMap(u64, *zquic.Connection.Connection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, config: VpnNodeConfig) !Self {
        // Initialize async runtime
        const runtime_config = zquic.AsyncRuntime.QuicRuntimeConfig{
            .max_connections = config.max_connections,
            .worker_threads = 0, // Auto-detect
            .enable_connection_pooling = true,
        };
        
        const runtime = try zquic.AsyncRuntime.QuicRuntime.init(allocator, config.listen_address, runtime_config);
        
        // Initialize packet router
        const router_config = zquic.VpnRouter.RoutingConfig{
            .enable_nat = true,
            .max_routes = 1000,
        };
        const router = zquic.VpnRouter.PacketRouter.init(allocator, router_config);
        
        // Initialize load balancer if enabled
        const load_balancer = if (config.enable_load_balancing) blk: {
            const lb_config = zquic.LoadBalancer.LoadBalancerConfig{
                .strategy = .least_connections,
                .enable_circuit_breaker = true,
            };
            break :blk zquic.LoadBalancer.ConnectionLoadBalancer.init(allocator, lb_config);
        } else null;
        
        // Initialize enhanced TLS context
        const tls_context = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, false, config.cipher_suite);
        
        return Self{
            .config = config,
            .allocator = allocator,
            .runtime = runtime,
            .router = router,
            .load_balancer = load_balancer,
            .tls_context = tls_context,
            .connections = std.ArrayList(*zquic.Connection.Connection).init(allocator),
            .peer_connections = std.HashMap(u64, *zquic.Connection.Connection, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.runtime.deinit();
        self.router.deinit();
        if (self.load_balancer) |*lb| {
            lb.deinit();
        }
        self.tls_context.deinit();
        
        // Clean up connections
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
        self.peer_connections.deinit();
    }
    
    /// Start the VPN node
    pub fn start(self: *Self) !void {
        std.log.info("Starting GhostScale VPN node: {s}", .{self.config.node_id});
        
        // Add VPN interface
        try self.router.addInterface("ghost0", self.config.listen_address, 1420);
        
        // Set up load balancer backends if enabled
        if (self.load_balancer) |*lb| {
            for (self.config.peer_addresses, 0..) |peer_addr, i| {
                const backend_id = try std.fmt.allocPrint(self.allocator, "peer_{d}", .{i});
                defer self.allocator.free(backend_id);
                
                try lb.addBackend(backend_id, peer_addr, 1, 10);
            }
        }
        
        // Start async runtime
        try self.runtime.start();
        
        // Connect to peers
        try self.connectToPeers();
        
        std.log.info("GhostScale VPN node started successfully");
    }
    
    /// Stop the VPN node
    pub fn stop(self: *Self) void {
        std.log.info("Stopping GhostScale VPN node: {s}", .{self.config.node_id});
        self.runtime.stop();
    }
    
    /// Connect to peer nodes
    fn connectToPeers(self: *Self) !void {
        for (self.config.peer_addresses, 0..) |peer_addr, i| {
            const conn_id = try zquic.Packet.ConnectionId.init(&[_]u8{ 
                @truncate(i),
                @truncate(i >> 8),
                @truncate(std.time.microTimestamp()),
                @truncate(std.time.microTimestamp() >> 8),
            });
            
            const connection = try self.allocator.create(zquic.Connection.Connection);
            connection.* = zquic.Connection.Connection.init(self.allocator, .client, conn_id);
            
            // Initialize TLS keys for this connection
            try self.tls_context.initializeInitialKeys(conn_id.bytes());
            
            // Add to runtime
            try self.runtime.spawnConnection(connection, peer_addr);
            
            // Add route for this peer
            try self.router.addRoute(peer_addr, peer_addr, "ghost0", conn_id);
            
            // Store connection
            try self.connections.append(connection);
            const peer_hash = hashAddress(peer_addr);
            try self.peer_connections.put(peer_hash, connection);
            
            std.log.info("Connected to peer {d}: {}", .{ i, peer_addr });
        }
    }
    
    /// Handle incoming VPN packet
    pub fn handleVpnPacket(self: *Self, packet_data: []const u8, source: std.net.Address, destination: std.net.Address) !void {
        // Route the packet through the VPN
        const forward_result = try self.router.forwardPacket(packet_data, source, destination);
        
        // Find connection for the next hop
        var target_connection: ?*zquic.Connection.Connection = null;
        
        if (self.load_balancer) |*lb| {
            // Use load balancer to select backend
            const result = lb.acquireConnection() catch |err| {
                std.log.warn("Load balancer failed to acquire connection: {}", .{err});
                return;
            };
            target_connection = result.connection;
        } else {
            // Direct peer lookup
            const next_hop_hash = hashAddress(forward_result.next_hop);
            target_connection = self.peer_connections.get(next_hop_hash);
        }
        
        if (target_connection) |connection| {
            // Create a stream and send the packet
            if (connection.createStream(.client_unidirectional)) |stream| {
                _ = connection.sendStreamData(stream.id.id, forward_result.packet_data, true) catch |err| {
                    std.log.warn("Failed to send VPN packet: {}", .{err});
                };
            } else |err| {
                std.log.warn("Failed to create stream: {}", .{err});
            }
        } else {
            std.log.warn("No connection available for next hop: {}", .{forward_result.next_hop});
        }
    }
    
    /// Run the VPN node main loop
    pub fn run(self: *Self) !void {
        std.log.info("Running GhostScale VPN node main loop");
        
        while (self.runtime.is_running) {
            // Run I/O focused event loop
            self.runtime.runIoFocused() catch |err| {
                std.log.warn("Runtime error: {}", .{err});
            };
            
            // Periodic maintenance
            self.performMaintenance();
            
            // Small delay
            std.time.sleep(10_000_000); // 10ms
        }
    }
    
    /// Perform periodic maintenance tasks
    fn performMaintenance(self: *Self) void {
        // Clean up expired routes
        _ = self.router.cleanup();
        
        // Update connection statistics
        self.updateStatistics();
    }
    
    /// Update node statistics
    fn updateStatistics(self: *Self) void {
        const runtime_stats = self.runtime.getStats();
        const router_stats = self.router.getStats();
        
        if (self.load_balancer) |*lb| {
            const lb_stats = lb.getStats();
            
            std.log.debug("VPN Node Stats - Connections: {d}, Routes: {d}, LB Success Rate: {d:.2}%", 
                .{ runtime_stats.active_connections, router_stats.route_count, lb_stats.success_rate * 100 });
        } else {
            std.log.debug("VPN Node Stats - Connections: {d}, Routes: {d}", 
                .{ runtime_stats.active_connections, router_stats.route_count });
        }
    }
    
    /// Hash a network address for use as a key
    fn hashAddress(address: std.net.Address) u64 {
        const bytes = std.mem.asBytes(&address);
        return std.hash_map.hashString(bytes);
    }
};

/// Main GhostScale VPN example
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("🌐 GhostScale VPN - Tailscale-like VPN using zQUIC", .{});
    
    // Configure VPN node
    const listen_addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 4433);
    const peer_addrs = [_]std.net.Address{
        std.net.Address.initIp4([4]u8{ 10, 0, 0, 2 }, 4433),
        std.net.Address.initIp4([4]u8{ 10, 0, 0, 3 }, 4433),
    };
    
    const config = VpnNodeConfig{
        .node_id = "ghost-node-1",
        .listen_address = listen_addr,
        .peer_addresses = &peer_addrs,
        .max_connections = 50,
        .enable_load_balancing = true,
        .cipher_suite = .aes_256_gcm_sha384,
    };
    
    // Initialize VPN node
    var vpn_node = VpnNode.init(allocator, config) catch |err| switch (err) {
        zquic.Error.ZquicError.AddressInUse => {
            std.log.err("Address already in use. Try a different port.", .{});
            return;
        },
        else => return err,
    };
    defer vpn_node.deinit();
    
    // Start the VPN node
    try vpn_node.start();
    defer vpn_node.stop();
    
    // Simulate some VPN traffic
    try simulateVpnTraffic(&vpn_node);
    
    // Run the main loop for a short time
    std.log.info("Running VPN node for 5 seconds...");
    const start_time = std.time.milliTimestamp();
    
    while (std.time.milliTimestamp() - start_time < 5000) {
        vpn_node.performMaintenance();
        std.time.sleep(100_000_000); // 100ms
    }
    
    std.log.info("✅ GhostScale VPN example completed successfully!");
}

/// Simulate VPN traffic for demonstration
fn simulateVpnTraffic(vpn_node: *VpnNode) !void {
    std.log.info("Simulating VPN traffic...");
    
    const source_addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 0);
    const dest_addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 2 }, 0);
    
    // Simulate some packets
    for (0..5) |i| {
        const packet_data = try std.fmt.allocPrint(vpn_node.allocator, "VPN packet {d}: Hello from GhostScale!", .{i});
        defer vpn_node.allocator.free(packet_data);
        
        vpn_node.handleVpnPacket(packet_data, source_addr, dest_addr) catch |err| {
            std.log.warn("Failed to handle VPN packet {d}: {}", .{ i, err });
        };
        
        std.time.sleep(100_000_000); // 100ms between packets
    }
    
    std.log.info("VPN traffic simulation completed");
}