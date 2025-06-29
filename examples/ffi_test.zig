//! FFI Test Example
//!
//! Demonstrates the FFI layer functionality for GhostChain ecosystem integration

const std = @import("std");

// Note: In a real implementation, this would import the compiled FFI library
// For this test, we'll simulate the FFI interface
const ZQuicConfig = extern struct {
    port: u16,
    max_connections: u32,
    connection_timeout_ms: u32,
    enable_ipv6: u8,
    tls_verify: u8,
    reserved: [16]u8,
};

const ZQuicCryptoResult = extern struct {
    status: u32,
    data: [128]u8,
    len: usize,
    error_msg: [256]u8,
};

const ZQuicDnsResponse = extern struct {
    data: [512]u8,
    len: usize,
    query_type: u16,
    rcode: u8,
    ttl: u32,
};

const ZQuicGrpcResponse = extern struct {
    data: ?[*]u8,
    len: usize,
    status: u32,
};

// Mock FFI functions for testing
fn zquic_version() [*:0]const u8 {
    return "ZQUIC 0.2.0-alpha FFI+GhostChain";
}

fn zquic_test_echo(input: [*:0]const u8) [*:0]const u8 {
    _ = input;
    return "ZQUIC FFI Test OK";
}

fn zquic_test_add(a: c_int, b: c_int) c_int {
    return a + b;
}

fn zquic_init(config: *const ZQuicConfig) ?*anyopaque {
    _ = config;
    return @ptrFromInt(0x1234); // Mock pointer
}

fn zquic_destroy(ctx: ?*anyopaque) void {
    _ = ctx;
}

fn zquic_create_connection(ctx: ?*anyopaque, addr: [*:0]const u8) ?*anyopaque {
    _ = ctx;
    _ = addr;
    return @ptrFromInt(0x5678); // Mock pointer
}

fn zquic_close_connection(conn: ?*anyopaque) void {
    _ = conn;
}

fn zquic_crypto_init() c_int {
    return 0; // Success
}

fn zquic_crypto_keygen(key_type: u8, public_key: [*]u8, private_key: [*]u8, result: *ZQuicCryptoResult) c_int {
    _ = key_type;
    _ = public_key;
    _ = private_key;
    result.status = 0;
    result.len = 32;
    return 0;
}

fn zquic_crypto_sign(key_type: u8, private_key: [*]const u8, data: [*]const u8, data_len: usize, signature: [*]u8, result: *ZQuicCryptoResult) c_int {
    _ = key_type;
    _ = private_key;
    _ = data;
    _ = data_len;
    _ = signature;
    result.status = 0;
    result.len = 64;
    return 0;
}

fn zquic_crypto_hash(hash_type: u8, data: [*]const u8, data_len: usize, hash_output: [*]u8, result: *ZQuicCryptoResult) c_int {
    _ = hash_type;
    _ = data;
    _ = data_len;
    _ = hash_output;
    result.status = 0;
    result.len = 32;
    return 0;
}

fn zquic_dns_query(conn: ?*anyopaque, domain: [*:0]const u8, query_type: u16, response: *ZQuicDnsResponse) c_int {
    _ = conn;
    _ = domain;
    response.query_type = query_type;
    response.len = 42;
    response.rcode = 0;
    response.ttl = 300;
    return 0;
}

fn zquic_grpc_call(conn: ?*anyopaque, method: [*:0]const u8, data: [*]const u8, len: usize) ?*ZQuicGrpcResponse {
    _ = conn;
    _ = method;
    _ = data;
    _ = len;

    // Allocate mock response
    const response = std.heap.c_allocator.create(ZQuicGrpcResponse) catch return null;
    response.* = ZQuicGrpcResponse{
        .data = null,
        .len = 0,
        .status = 0,
    };
    return response;
}

fn zquic_grpc_response_free(response: ?*ZQuicGrpcResponse) void {
    if (response) |resp| {
        std.heap.c_allocator.destroy(resp);
    }
}

// Constants
const ZQUIC_KEY_ED25519: u8 = 1;
const ZQUIC_HASH_BLAKE3: u8 = 1;
const ZQUIC_DNS_ENS: u16 = 65001;
const ZQUIC_DNS_ZNS: u16 = 65002;
const ZQUIC_DNS_A: u16 = 1;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    std.debug.print("🔗 ZQUIC FFI Test Example\n", .{});
    std.debug.print("Version: {s}\n", .{zquic_version()});

    // Test basic FFI functions
    testBasicFunctions();
    testCryptoFunctions();
    testDnsFunctions();
    testGrpcFunctions();

    std.debug.print("\n✨ FFI test complete!\n", .{});
}

fn testBasicFunctions() void {
    std.debug.print("\n📡 Testing Basic FFI Functions:\n", .{});

    // Test echo function
    const echo_result = zquic_test_echo("Hello FFI!");
    std.debug.print("  Echo test: {s}\n", .{echo_result});

    // Test add function
    const add_result = zquic_test_add(42, 24);
    std.debug.print("  Add test: 42 + 24 = {}\n", .{add_result});

    // Test context creation
    const config = ZQuicConfig{
        .port = 8443,
        .max_connections = 100,
        .connection_timeout_ms = 30000,
        .enable_ipv6 = 1,
        .tls_verify = 1,
        .reserved = std.mem.zeroes([16]u8),
    };

    const ctx = zquic_init(&config);
    if (ctx != null) {
        std.debug.print("  Context creation: SUCCESS\n", .{});
        zquic_destroy(ctx);
        std.debug.print("  Context cleanup: SUCCESS\n", .{});
    } else {
        std.debug.print("  Context creation: FAILED\n", .{});
    }
}

fn testCryptoFunctions() void {
    std.debug.print("\n🔐 Testing ZCrypto Integration:\n", .{});

    // Initialize crypto subsystem
    const init_result = zquic_crypto_init();
    std.debug.print("  Crypto init: {s}\n", .{if (init_result == 0) "SUCCESS" else "FAILED"});

    // Test key generation
    var public_key: [64]u8 = undefined;
    var private_key: [64]u8 = undefined;
    var result = std.mem.zeroes(ZQuicCryptoResult);

    const keygen_result = zquic_crypto_keygen(ZQUIC_KEY_ED25519, &public_key, &private_key, &result);
    std.debug.print("  Ed25519 keygen: {s}\n", .{if (keygen_result == 0) "SUCCESS" else "FAILED"});

    // Test signing
    const test_data = "Hello GhostChain!";
    var signature: [64]u8 = undefined;
    const sign_result = zquic_crypto_sign(ZQUIC_KEY_ED25519, &private_key, test_data.ptr, test_data.len, &signature, &result);
    std.debug.print("  Ed25519 signing: {s}\n", .{if (sign_result == 0) "SUCCESS" else "FAILED"});

    // Test hashing
    var hash_output: [32]u8 = undefined;
    const hash_result = zquic_crypto_hash(ZQUIC_HASH_BLAKE3, test_data.ptr, test_data.len, &hash_output, &result);
    std.debug.print("  Blake3 hashing: {s}\n", .{if (hash_result == 0) "SUCCESS" else "FAILED"});
}

fn testDnsFunctions() void {
    std.debug.print("\n🌐 Testing DNS-over-QUIC (CNS/ZNS):\n", .{});

    // Create context for DNS testing
    const config = ZQuicConfig{
        .port = 853, // Standard DNS-over-QUIC port
        .max_connections = 10,
        .connection_timeout_ms = 5000,
        .enable_ipv6 = 1,
        .tls_verify = 1,
        .reserved = std.mem.zeroes([16]u8),
    };

    const ctx = zquic_init(&config);
    defer if (ctx != null) zquic_destroy(ctx);

    if (ctx == null) {
        std.debug.print("  DNS context creation: FAILED\n", .{});
        return;
    }

    // Create mock connection for DNS testing
    const conn = zquic_create_connection(ctx, "dns.cloudflare.com");
    defer if (conn != null) zquic_close_connection(conn);

    if (conn == null) {
        std.debug.print("  DNS connection creation: FAILED\n", .{});
        return;
    }

    // Test different DNS query types
    var response = std.mem.zeroes(ZQuicDnsResponse);

    // Test ENS resolution
    const ens_result = zquic_dns_query(conn, "vitalik.eth", ZQUIC_DNS_ENS, &response);
    std.debug.print("  ENS query (vitalik.eth): {s}\n", .{if (ens_result == 0) "SUCCESS" else "FAILED"});

    // Test ZNS resolution
    const zns_result = zquic_dns_query(conn, "ghost.zns", ZQUIC_DNS_ZNS, &response);
    std.debug.print("  ZNS query (ghost.zns): {s}\n", .{if (zns_result == 0) "SUCCESS" else "FAILED"});

    // Test A record
    const a_result = zquic_dns_query(conn, "example.com", ZQUIC_DNS_A, &response);
    std.debug.print("  A record query: {s}\n", .{if (a_result == 0) "SUCCESS" else "FAILED"});
}

fn testGrpcFunctions() void {
    std.debug.print("\n🌉 Testing gRPC-over-QUIC (GhostBridge):\n", .{});

    // Create context for gRPC testing
    const config = ZQuicConfig{
        .port = 9443,
        .max_connections = 50,
        .connection_timeout_ms = 10000,
        .enable_ipv6 = 1,
        .tls_verify = 1,
        .reserved = std.mem.zeroes([16]u8),
    };

    const ctx = zquic_init(&config);
    defer if (ctx != null) zquic_destroy(ctx);

    if (ctx == null) {
        std.debug.print("  gRPC context creation: FAILED\n", .{});
        return;
    }

    // Create mock connection for gRPC testing
    const conn = zquic_create_connection(ctx, "ghostd.local:9090");
    defer if (conn != null) zquic_close_connection(conn);

    if (conn == null) {
        std.debug.print("  gRPC connection creation: FAILED\n", .{});
        return;
    }

    // Test gRPC call
    const request_data = "{\"wallet_id\": \"test123\", \"amount\": 1000}";
    const grpc_response = zquic_grpc_call(conn, "ghost.wallet.WalletService/SendTransaction", request_data.ptr, request_data.len);

    if (grpc_response != null) {
        std.debug.print("  gRPC call: SUCCESS\n", .{});
        std.debug.print("    Response status: {}\n", .{grpc_response.?.status});
        std.debug.print("    Response length: {} bytes\n", .{grpc_response.?.len});
        zquic_grpc_response_free(grpc_response);
    } else {
        std.debug.print("  gRPC call: FAILED\n", .{});
    }
}
