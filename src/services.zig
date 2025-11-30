//! ZQUIC Services Feature Module
//!
//! Provides GhostBridge and Wraith services for ZQUIC.
//! Only included when the 'services' feature is enabled.

const std = @import("std");
const ghostbridge_mod = @import("services/ghostbridge.zig");
const wraith_mod = @import("services/wraith.zig");
const cns_mod = @import("services/cns_resolver.zig");
const zvm_mod = @import("services/zvm_integration.zig");

// Re-export service functionality
pub const GhostBridge = ghostbridge_mod.GhostBridge;
pub const GhostBridgeConfig = ghostbridge_mod.GhostBridgeConfig;
pub const BridgeStats = ghostbridge_mod.BridgeStats;
pub const ServiceRegistration = ghostbridge_mod.ServiceRegistration;

pub const Wraith = wraith_mod.WraithProxy;
pub const WraithProxy = wraith_mod.WraithProxy;
pub const WraithConfig = wraith_mod.WraithConfig;
pub const ResponseCache = wraith_mod.ResponseCache;
pub const ProxyStats = wraith_mod.ProxyStats;

pub const CnsResolver = cns_mod.CnsResolver;
pub const CnsResolverConfig = cns_mod.CnsResolverConfig;
pub const DnsQuestion = cns_mod.DnsQuestion;
pub const DnsRecordType = cns_mod.DnsRecordType;
pub const DnsClass = cns_mod.DnsClass;
pub const DnsCacheEntry = cns_mod.CacheEntry;

pub const ZvmQuicServer = zvm_mod.ZvmQuicServer;
pub const WasmExecutionRequest = zvm_mod.WasmExecutionRequest;
pub const WasmExecutionResult = zvm_mod.WasmExecutionResult;

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
