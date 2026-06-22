//! Services integration tests for GhostBridge lifecycle

const std = @import("std");
const zquic = @import("zquic");

const ResponseCache = zquic.services.ResponseCache;
const DnsQuestion = zquic.services.DnsQuestion;
const DnsRecordType = zquic.services.DnsRecordType;
const DnsClass = zquic.services.DnsClass;
const CacheEntry = zquic.services.DnsCacheEntry;
const Time = zquic.Time;

fn nowSeconds() i64 {
    return Time.nowSeconds();
}

test "integration: ghostbridge manages services and connections" {
    if (!@hasDecl(zquic.services, "GhostBridge")) return error.SkipZigTest;

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const GhostBridge = zquic.services.GhostBridge;
    const GhostBridgeConfig = zquic.services.GhostBridgeConfig;

    var bridge = try GhostBridge.init(allocator, GhostBridgeConfig{
        .max_connections = 8,
    });
    defer bridge.deinit();

    try bridge.registerService("ghostd", "127.0.0.1:50051", .ghostd);
    try std.testing.expect(bridge.services.count() == 1);

    const health = bridge.checkServiceHealth("ghostd");
    try std.testing.expect(health == .unknown or health == .healthy or health == .unhealthy);

    const connection = try bridge.createConnection("ghostd");
    const quic_conn = connection.quic_connection;
    const connection_id = connection.connection_id;

    try std.testing.expect(connection_id == 1);
    try std.testing.expect(bridge.connections.count() == 1);
    try std.testing.expect(bridge.stats.active_connections == 1);

    bridge.closeConnection(connection_id);
    allocator.destroy(quic_conn);

    try std.testing.expect(bridge.connections.count() == 0);
    try std.testing.expect(bridge.stats.active_connections == 0);

    try bridge.unregisterService("ghostd");
}

test "ghostbridge stats uptime reflects helper timestamps" {
    if (!@hasDecl(zquic.services, "GhostBridge")) return error.SkipZigTest;

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const GhostBridge = zquic.services.GhostBridge;
    var bridge = try GhostBridge.init(allocator, .{});
    defer bridge.deinit();

    // Pretend the service started in the past and ensure updateStats consumes helper timestamps.
    bridge.stats.start_time = nowSeconds() - 3;
    bridge.updateStats();
    try std.testing.expect(bridge.stats.uptime_seconds >= 3);

    bridge.stats.start_time = nowSeconds() - 1;
    bridge.updateStats();
    try std.testing.expect(bridge.stats.uptime_seconds >= 1);
    try std.testing.expect(bridge.stats.uptime_seconds <= 2);
}

test "wraith response cache expires entries with helper time" {
    var cache = ResponseCache.init(std.testing.allocator, 1);
    defer cache.deinit();

    const key: u64 = 0xdeadbeef;
    const payload = "cached-response";
    try cache.put(key, payload, 10);

    try std.testing.expect(cache.get(key) != null);

    {
        cache.mutex.lock();
        defer cache.mutex.unlock();
        if (cache.cache.getPtr(key)) |entry| {
            entry.expiry_time = nowSeconds() - 1;
        }
    }

    try std.testing.expect(cache.get(key) == null);
}

test "dns cache entry helper expiry" {
    var question = try DnsQuestion.init(std.testing.allocator, "example.ghost", DnsRecordType.A, DnsClass.IN);
    defer question.deinit(std.testing.allocator);

    var entry = try CacheEntry.init(std.testing.allocator, &question);
    defer entry.deinit(std.testing.allocator);

    entry.expiry_time = nowSeconds() + 5;
    try std.testing.expect(!entry.isExpired());

    entry.expiry_time = nowSeconds() - 1;
    try std.testing.expect(entry.isExpired());
}
