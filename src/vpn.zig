//! ZQUIC VPN Feature Module
//!
//! Provides VPN functionality for ZQUIC.
//! Only included when the 'vpn' feature is enabled.

const std = @import("std");
const NetAddress = @import("net/address.zig");
const Address = NetAddress.Address;

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
    local_address: Address,
    remote_address: Address,
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
        const interface = try allocator.create(VpnInterface);
        interface.* = .{
            .name = "zquic-vpn0",
            .local_address = config.local_address,
            .mtu = config.mtu,
            .is_active = true,
        };
        return interface;
    }

    /// Establish VPN connection
    pub fn connect(allocator: std.mem.Allocator, interface: *VpnInterface, config: VpnConfig) !*VpnConnection {
        const router = try allocator.create(PacketRouter);
        errdefer allocator.destroy(router);
        router.* = PacketRouter.init(allocator, .{
            .enable_nat = config.enable_nat,
        });

        const connection = try allocator.create(VpnConnection);
        connection.* = .{
            .interface = interface,
            .router = router,
            .is_connected = true,
            .bytes_sent = 0,
            .bytes_received = 0,
            .connected_at = std.time.microTimestamp(),
        };
        return connection;
    }

    /// Disconnect VPN
    pub fn disconnect(connection: *VpnConnection) void {
        connection.is_connected = false;
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
