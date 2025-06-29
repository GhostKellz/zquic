//! VPN Packet Router for GhostScale
//!
//! Provides packet routing and forwarding for tailscale-like VPN functionality

const std = @import("std");
const Error = @import("../utils/error.zig");
const Packet = @import("../core/packet.zig");

/// VPN route entry
pub const Route = struct {
    destination: std.net.Address,
    gateway: std.net.Address,
    connection_id: Packet.ConnectionId,
    metric: u32 = 1,
    interface: []const u8,
    expires_at: ?i64 = null, // timestamp in microseconds

    pub fn isExpired(self: *const @This(), current_time: i64) bool {
        return if (self.expires_at) |expiry| current_time > expiry else false;
    }
};

/// Network interface for VPN routing
pub const VpnInterface = struct {
    name: []const u8,
    local_address: std.net.Address,
    mtu: u32 = 1420, // MTU suitable for QUIC over UDP
    is_active: bool = true,
    connection_id: ?Packet.ConnectionId = null,

    // Statistics
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
};

/// Routing table configuration
pub const RoutingConfig = struct {
    max_routes: u32 = 10000,
    route_timeout_ms: u32 = 3600_000, // 1 hour
    cleanup_interval_ms: u32 = 300_000, // 5 minutes
    enable_nat: bool = true,
    default_metric: u32 = 100,
};

/// NAT (Network Address Translation) entry
pub const NatEntry = struct {
    internal_addr: std.net.Address,
    external_addr: std.net.Address,
    connection_id: Packet.ConnectionId,
    created_at: i64,
    last_used: i64,

    pub fn isExpired(self: *const @This(), current_time: i64, timeout_us: i64) bool {
        return current_time - self.last_used > timeout_us;
    }
};

/// VPN packet router for handling routing between QUIC connections
pub const PacketRouter = struct {
    routes: std.ArrayList(Route),
    interfaces: std.HashMap(u64, VpnInterface, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    nat_table: std.HashMap(u64, NatEntry, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    config: RoutingConfig,
    allocator: std.mem.Allocator,

    // Default route
    default_gateway: ?std.net.Address = null,
    default_interface: ?[]const u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: RoutingConfig) Self {
        return Self{
            .routes = std.ArrayList(Route).init(allocator),
            .interfaces = std.HashMap(u64, VpnInterface, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .nat_table = std.HashMap(u64, NatEntry, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .config = config,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free interface names
        var interface_iterator = self.interfaces.iterator();
        while (interface_iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.name);
        }

        // Free route interface names
        for (self.routes.items) |route| {
            self.allocator.free(route.interface);
        }

        self.routes.deinit();
        self.interfaces.deinit();
        self.nat_table.deinit();
    }

    /// Add a VPN interface
    pub fn addInterface(self: *Self, name: []const u8, local_address: std.net.Address, mtu: u32) Error.ZquicError!void {
        const interface_name = self.allocator.dupe(u8, name) catch return Error.ZquicError.OutOfMemory;

        const interface = VpnInterface{
            .name = interface_name,
            .local_address = local_address,
            .mtu = mtu,
        };

        const interface_hash = std.hash_map.hashString(name);
        self.interfaces.put(interface_hash, interface) catch return Error.ZquicError.OutOfMemory;
    }

    /// Remove a VPN interface
    pub fn removeInterface(self: *Self, name: []const u8) void {
        const interface_hash = std.hash_map.hashString(name);
        if (self.interfaces.fetchRemove(interface_hash)) |entry| {
            self.allocator.free(entry.value.name);
        }
    }

    /// Add a route to the routing table
    pub fn addRoute(self: *Self, destination: std.net.Address, gateway: std.net.Address, interface: []const u8, connection_id: Packet.ConnectionId) Error.ZquicError!void {
        if (self.routes.items.len >= self.config.max_routes) {
            return Error.ZquicError.ResourceExhausted;
        }

        const interface_name = self.allocator.dupe(u8, interface) catch return Error.ZquicError.OutOfMemory;

        const route = Route{
            .destination = destination,
            .gateway = gateway,
            .connection_id = connection_id,
            .metric = self.config.default_metric,
            .interface = interface_name,
            .expires_at = if (self.config.route_timeout_ms > 0)
                std.time.microTimestamp() + @as(i64, self.config.route_timeout_ms) * 1000
            else
                null,
        };

        self.routes.append(route) catch return Error.ZquicError.OutOfMemory;
    }

    /// Remove a route from the routing table
    pub fn removeRoute(self: *Self, destination: std.net.Address) bool {
        for (self.routes.items, 0..) |route, i| {
            if (addressEqual(route.destination, destination)) {
                const removed_route = self.routes.swapRemove(i);
                self.allocator.free(removed_route.interface);
                return true;
            }
        }
        return false;
    }

    /// Set default gateway
    pub fn setDefaultGateway(self: *Self, gateway: std.net.Address, interface: []const u8) Error.ZquicError!void {
        if (self.default_interface) |old_interface| {
            self.allocator.free(old_interface);
        }

        self.default_gateway = gateway;
        self.default_interface = self.allocator.dupe(u8, interface) catch return Error.ZquicError.OutOfMemory;
    }

    /// Route a packet to the appropriate destination
    pub fn routePacket(self: *Self, packet_data: []const u8, source: std.net.Address, destination: std.net.Address) Error.ZquicError!RoutingResult {
        // Check if we have a specific route for this destination
        var best_route: ?*const Route = null;
        var best_metric: u32 = std.math.maxInt(u32);

        const current_time = std.time.microTimestamp();

        for (self.routes.items) |*route| {
            if (route.isExpired(current_time)) continue;

            if (isDestinationMatch(destination, route.destination) and route.metric < best_metric) {
                best_route = route;
                best_metric = route.metric;
            }
        }

        if (best_route) |route| {
            // Update interface statistics
            if (self.getInterface(route.interface)) |interface| {
                interface.packets_sent += 1;
                interface.bytes_sent += packet_data.len;
            }

            return RoutingResult{
                .next_hop = route.gateway,
                .interface = route.interface,
                .connection_id = route.connection_id,
                .requires_nat = self.config.enable_nat and needsNat(source, destination),
            };
        }

        // Use default gateway if available
        if (self.default_gateway) |gateway| {
            if (self.default_interface) |interface| {
                return RoutingResult{
                    .next_hop = gateway,
                    .interface = interface,
                    .connection_id = null, // Will need to be resolved
                    .requires_nat = self.config.enable_nat,
                };
            }
        }

        return Error.ZquicError.NetworkUnreachable;
    }

    /// Forward a packet through the VPN
    pub fn forwardPacket(self: *Self, packet_data: []const u8, source: std.net.Address, destination: std.net.Address) Error.ZquicError!ForwardingResult {
        const routing_result = try self.routePacket(packet_data, source, destination);

        const forwarded_packet = packet_data;
        var source_addr = source;
        var dest_addr = destination;

        // Apply NAT if required
        if (routing_result.requires_nat) {
            const nat_result = try self.applyNat(source, destination, routing_result.connection_id orelse return Error.ZquicError.InvalidArgument);
            source_addr = nat_result.external_source;
            dest_addr = nat_result.external_destination;
        }

        return ForwardingResult{
            .packet_data = forwarded_packet,
            .source = source_addr,
            .destination = dest_addr,
            .next_hop = routing_result.next_hop,
            .interface = routing_result.interface,
            .connection_id = routing_result.connection_id,
        };
    }

    /// Apply Network Address Translation
    pub fn applyNat(self: *Self, internal_source: std.net.Address, internal_dest: std.net.Address, connection_id: Packet.ConnectionId) Error.ZquicError!NatResult {
        const nat_key = hashAddressPair(internal_source, internal_dest);
        const current_time = std.time.microTimestamp();

        // Check if NAT entry already exists
        if (self.nat_table.getPtr(nat_key)) |entry| {
            entry.last_used = current_time;
            return NatResult{
                .external_source = entry.external_addr,
                .external_destination = internal_dest, // Destination remains the same
            };
        }

        // Create new NAT entry
        // For simplicity, we'll use the internal address as external (in real implementation, would use NAT pool)
        const external_addr = internal_source;

        const nat_entry = NatEntry{
            .internal_addr = internal_source,
            .external_addr = external_addr,
            .connection_id = connection_id,
            .created_at = current_time,
            .last_used = current_time,
        };

        self.nat_table.put(nat_key, nat_entry) catch return Error.ZquicError.OutOfMemory;

        return NatResult{
            .external_source = external_addr,
            .external_destination = internal_dest,
        };
    }

    /// Clean up expired routes and NAT entries
    pub fn cleanup(self: *Self) u32 {
        const current_time = std.time.microTimestamp();
        var cleaned_count: u32 = 0;

        // Clean up expired routes
        var i: usize = 0;
        while (i < self.routes.items.len) {
            if (self.routes.items[i].isExpired(current_time)) {
                const removed_route = self.routes.swapRemove(i);
                self.allocator.free(removed_route.interface);
                cleaned_count += 1;
            } else {
                i += 1;
            }
        }

        // Clean up expired NAT entries
        const nat_timeout_us = @as(i64, self.config.route_timeout_ms) * 1000;
        var nat_iterator = self.nat_table.iterator();
        var expired_nat_keys = std.ArrayList(u64).init(self.allocator);
        defer expired_nat_keys.deinit();

        while (nat_iterator.next()) |entry| {
            if (entry.value_ptr.isExpired(current_time, nat_timeout_us)) {
                expired_nat_keys.append(entry.key_ptr.*) catch continue;
            }
        }

        for (expired_nat_keys.items) |key| {
            _ = self.nat_table.remove(key);
            cleaned_count += 1;
        }

        return cleaned_count;
    }

    /// Get interface by name
    pub fn getInterface(self: *Self, name: []const u8) ?*VpnInterface {
        const interface_hash = std.hash_map.hashString(name);
        return self.interfaces.getPtr(interface_hash);
    }

    /// Get routing statistics
    pub fn getStats(self: *const Self) RoutingStats {
        var total_packets_sent: u64 = 0;
        var total_packets_received: u64 = 0;
        var total_bytes_sent: u64 = 0;
        var total_bytes_received: u64 = 0;

        var interface_iterator = self.interfaces.iterator();
        while (interface_iterator.next()) |entry| {
            const interface = entry.value_ptr;
            total_packets_sent += interface.packets_sent;
            total_packets_received += interface.packets_received;
            total_bytes_sent += interface.bytes_sent;
            total_bytes_received += interface.bytes_received;
        }

        return RoutingStats{
            .route_count = self.routes.items.len,
            .interface_count = self.interfaces.count(),
            .nat_entry_count = self.nat_table.count(),
            .total_packets_sent = total_packets_sent,
            .total_packets_received = total_packets_received,
            .total_bytes_sent = total_bytes_sent,
            .total_bytes_received = total_bytes_received,
        };
    }

    // Helper functions
    fn addressEqual(addr1: std.net.Address, addr2: std.net.Address) bool {
        return std.meta.eql(addr1, addr2);
    }

    fn isDestinationMatch(destination: std.net.Address, route_dest: std.net.Address) bool {
        // Simplified matching - in real implementation would support subnet masks
        return addressEqual(destination, route_dest);
    }

    fn needsNat(source: std.net.Address, destination: std.net.Address) bool {
        _ = source;
        _ = destination;
        // Simplified NAT decision - in real implementation would check private/public address ranges
        return true;
    }

    fn hashAddressPair(addr1: std.net.Address, addr2: std.net.Address) u64 {
        // Simple hash combining two addresses
        const bytes1 = std.mem.asBytes(&addr1);
        const bytes2 = std.mem.asBytes(&addr2);

        var hasher = std.hash.Wyhash.init(0);
        hasher.update(bytes1);
        hasher.update(bytes2);
        return hasher.final();
    }
};

/// Result of packet routing
pub const RoutingResult = struct {
    next_hop: std.net.Address,
    interface: []const u8,
    connection_id: ?Packet.ConnectionId,
    requires_nat: bool,
};

/// Result of packet forwarding
pub const ForwardingResult = struct {
    packet_data: []const u8,
    source: std.net.Address,
    destination: std.net.Address,
    next_hop: std.net.Address,
    interface: []const u8,
    connection_id: ?Packet.ConnectionId,
};

/// Result of NAT application
pub const NatResult = struct {
    external_source: std.net.Address,
    external_destination: std.net.Address,
};

/// Routing statistics
pub const RoutingStats = struct {
    route_count: usize,
    interface_count: u32,
    nat_entry_count: u32,
    total_packets_sent: u64,
    total_packets_received: u64,
    total_bytes_sent: u64,
    total_bytes_received: u64,
};

test "packet router initialization" {
    const config = RoutingConfig{};
    var router = PacketRouter.init(std.testing.allocator, config);
    defer router.deinit();

    const stats = router.getStats();
    try std.testing.expect(stats.route_count == 0);
    try std.testing.expect(stats.interface_count == 0);
}

test "interface management" {
    const config = RoutingConfig{};
    var router = PacketRouter.init(std.testing.allocator, config);
    defer router.deinit();

    const local_addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 0);
    try router.addInterface("tun0", local_addr, 1420);

    const interface = router.getInterface("tun0");
    try std.testing.expect(interface != null);
    try std.testing.expect(interface.?.mtu == 1420);
}

test "routing table operations" {
    const config = RoutingConfig{};
    var router = PacketRouter.init(std.testing.allocator, config);
    defer router.deinit();

    const dest_addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 0 }, 0);
    const gateway_addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 0);
    const conn_id = try Packet.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });

    try router.addRoute(dest_addr, gateway_addr, "tun0", conn_id);

    const stats = router.getStats();
    try std.testing.expect(stats.route_count == 1);

    const removed = router.removeRoute(dest_addr);
    try std.testing.expect(removed);
}
