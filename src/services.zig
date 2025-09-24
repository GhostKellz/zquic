//! ZQUIC Services Feature Module
//!
//! Provides GhostBridge and Wraith services for ZQUIC.
//! Only included when the 'services' feature is enabled.

const std = @import("std");
const zquic_core = @import("zquic_core");
const zcrypto = @import("zcrypto");

// Re-export service functionality
pub const GhostBridge = @import("services/ghostbridge.zig").GhostBridge;
pub const Wraith = @import("services/wraith.zig").Wraith;
pub const GhostBridgeConfig = @import("services/ghostbridge.zig").GhostBridgeConfig;
pub const WraithConfig = @import("services/wraith.zig").WraithConfig;

// Service-specific types
pub const ServiceType = enum {
    ghostbridge,
    wraith,
    custom,
};

pub const ServiceConfig = union(ServiceType) {
    ghostbridge: GhostBridgeConfig,
    wraith: WraithConfig,
    custom: struct {
        name: []const u8,
        config: []const u8, // JSON or custom format
    },
};

// Services configuration
pub const ServicesConfig = struct {
    enabled_services: []const ServiceType = &.{.ghostbridge},
    ghostbridge_config: GhostBridgeConfig = .{},
    wraith_config: WraithConfig = .{},
    max_concurrent_services: u32 = 10,
    service_timeout_ms: u32 = 30000,
};

// Feature-specific initialization
pub fn init(allocator: std.mem.Allocator, config: ServicesConfig) !void {
    _ = allocator;
    _ = config;
    // Initialize services-specific state
}

// Feature-specific cleanup
pub fn deinit() void {
    // Clean up services-specific state
}

// Service utilities
pub const ServiceUtils = struct {
    /// Register a new service
    pub fn registerService(allocator: std.mem.Allocator, service_type: ServiceType, config: ServiceConfig) !*anyopaque {
        _ = allocator;
        _ = service_type;
        _ = config;
        // Implementation would register and start the service
        return undefined;
    }

    /// Unregister a service
    pub fn unregisterService(service_handle: *anyopaque) void {
        _ = service_handle;
        // Implementation would stop and unregister the service
    }

    /// Get service status
    pub fn getServiceStatus(service_handle: *anyopaque) ServiceStatus {
        _ = service_handle;
        // Implementation would return current service status
        return .stopped;
    }
};

pub const ServiceStatus = enum {
    starting,
    running,
    stopping,
    stopped,
    errored,
};
