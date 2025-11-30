//! ZQUIC VPN Feature Module
//!
//! Provides VPN functionality for ZQUIC.
//! Only included when the 'vpn' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Re-export VPN functionality
pub const PacketRouter = @import("vpn/router.zig").PacketRouter;
pub const VpnInterface = @import("vpn/router.zig").VpnInterface;
pub const RoutingConfig = @import("vpn/router.zig").RoutingConfig;

// VPN-specific types
pub const VpnMode = enum {
    client,
    server,
    peer,
};

pub const VpnProtocol = enum {
    wireguard_over_quic,
    openvpn_over_quic,
    ipsec_over_quic,
    custom,
};

pub const VpnConfig = struct {
    mode: VpnMode = .client,
    protocol: VpnProtocol = .wireguard_over_quic,
    local_address: std.net.Address,
    remote_address: std.net.Address,
    mtu: u32 = 1420,
    enable_nat: bool = true,
    enable_compression: bool = false,
    keep_alive_interval_ms: u32 = 25000,
    reconnect_delay_ms: u32 = 5000,
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: VpnConfig) !void {
    _ = allocator;
    _ = config;
    // Initialize VPN-specific state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up VPN-specific state
}

// VPN utilities
pub const VpnUtils = struct {
    /// Create a new VPN interface
    pub fn createInterface(allocator: std.mem.Allocator, config: VpnConfig) !*VpnInterface {
        _ = allocator;
        _ = config;
        // Implementation would create and configure VPN interface
        return undefined;
    }

    /// Establish VPN connection
    pub fn connect(allocator: std.mem.Allocator, interface: *VpnInterface, config: VpnConfig) !*VpnConnection {
        _ = allocator;
        _ = interface;
        _ = config;
        // Implementation would establish VPN connection
        return undefined;
    }

    /// Disconnect VPN
    pub fn disconnect(connection: *VpnConnection) void {
        _ = connection;
        // Implementation would disconnect VPN
    }
};

pub const VpnConnection = struct {
    interface: *VpnInterface,
    router: *PacketRouter,
    is_connected: bool,
    bytes_sent: u64,
    bytes_received: u64,
    connected_at: i64,
};
