//! C Header Generation for FFI
//!
//! Generates C header files for Rust integration

const std = @import("std");

const headers = [_]HeaderFile{
    .{ .name = "zquic.h", .content = 
    \\#ifndef ZQUIC_H
    \\#define ZQUIC_H
    \\
    \\#ifdef __cplusplus
    \\extern "C" {
    \\#endif
    \\
    \\#include <stdint.h>
    \\#include <stddef.h>
    \\
    \\// Opaque pointer types
    \\typedef void* ZQuicContext;
    \\typedef void* ZQuicConnection;
    \\typedef void* ZQuicStream;
    \\typedef void* ZQuicServer;
    \\typedef void* CpuOptimizer;
    \\typedef void* OptimizedBlake3;
    \\typedef void* OptimizedChaCha20Poly1305;
    \\typedef void* ZvmQuicServer;
    \\typedef void* ZvmQuicClient;
    \\
    \\// Configuration structure
    \\typedef struct {
    \\    uint16_t port;
    \\    uint32_t max_connections;
    \\    uint32_t connection_timeout_ms;
    \\    uint8_t enable_ipv6;
    \\    uint8_t tls_verify;
    \\    uint8_t reserved[16];
    \\} ZQuicConfig;
    \\
    \\// Connection info structure
    \\typedef struct {
    \\    char remote_addr[64];
    \\    uint8_t connection_id[16];
    \\    uint8_t state;
    \\    uint32_t rtt_us;
    \\    uint64_t bytes_sent;
    \\    uint64_t bytes_received;
    \\} ZQuicConnectionInfo;
    \\
    \\// Core functions
    \\ZQuicContext* zquic_init(const ZQuicConfig* config);
    \\void zquic_destroy(ZQuicContext* ctx);
    \\
    \\// Server functions
    \\int zquic_create_server(ZQuicContext* ctx);
    \\int zquic_start_server(ZQuicContext* ctx);
    \\void zquic_stop_server(ZQuicContext* ctx);
    \\
    \\// Connection functions
    \\ZQuicConnection* zquic_create_connection(ZQuicContext* ctx, const char* remote_addr);
    \\void zquic_close_connection(ZQuicConnection* conn);
    \\ssize_t zquic_send_data(ZQuicConnection* conn, const uint8_t* data, size_t len);
    \\ssize_t zquic_receive_data(ZQuicConnection* conn, uint8_t* buffer, size_t max_len);
    \\
    \\// Stream functions
    \\ZQuicStream* zquic_create_stream(ZQuicConnection* conn, uint8_t stream_type);
    \\void zquic_close_stream(ZQuicStream* stream);
    \\ssize_t zquic_stream_send(ZQuicStream* stream, const uint8_t* data, size_t len);
    \\ssize_t zquic_stream_receive(ZQuicStream* stream, uint8_t* buffer, size_t max_len);
    \\
    \\// Info and utility functions
    \\int zquic_get_connection_info(ZQuicConnection* conn, ZQuicConnectionInfo* info);
    \\void zquic_set_connection_callback(ZQuicContext* ctx, void (*callback)(ZQuicConnection*, uint8_t, void*));
    \\const char* zquic_version(void);
    \\const char* zquic_last_error(void);
    \\
    \\// Test functions
    \\const char* zquic_test_echo(const char* input);
    \\int zquic_test_add(int a, int b);
    \\
    \\#ifdef __cplusplus
    \\}
    \\#endif
    \\
    \\#endif // ZQUIC_H
    \\
    },
    .{ .name = "zcrypto.h", .content = 
    \\#ifndef ZCRYPTO_H
    \\#define ZCRYPTO_H
    \\
    \\#ifdef __cplusplus
    \\extern "C" {
    \\#endif
    \\
    \\#include <stdint.h>
    \\#include <stddef.h>
    \\
    \\// Key and hash sizes
    \\#define ED25519_PUBLIC_KEY_SIZE 32
    \\#define ED25519_PRIVATE_KEY_SIZE 32
    \\#define ED25519_SIGNATURE_SIZE 64
    \\#define SECP256K1_PUBLIC_KEY_SIZE 33
    \\#define SECP256K1_PRIVATE_KEY_SIZE 32
    \\#define SECP256K1_SIGNATURE_SIZE 64
    \\#define BLAKE3_HASH_SIZE 32
    \\#define SHA256_HASH_SIZE 32
    \\
    \\// Post-quantum key sizes (ML-KEM-768)
    \\#define ML_KEM_768_PUBLIC_KEY_SIZE 1184
    \\#define ML_KEM_768_PRIVATE_KEY_SIZE 2400
    \\#define ML_KEM_768_CIPHERTEXT_SIZE 1088
    \\#define ML_KEM_768_SHARED_SECRET_SIZE 32
    \\
    \\// Post-quantum signature sizes (SLH-DSA-128f)
    \\#define SLH_DSA_128F_PUBLIC_KEY_SIZE 32
    \\#define SLH_DSA_128F_PRIVATE_KEY_SIZE 64
    \\#define SLH_DSA_128F_SIGNATURE_SIZE 17088
    \\
    \\// Error codes
    \\#define ZCRYPTO_SUCCESS 0
    \\#define ZCRYPTO_ERROR_INVALID_INPUT -1
    \\#define ZCRYPTO_ERROR_INVALID_KEY -2
    \\#define ZCRYPTO_ERROR_INVALID_SIGNATURE -3
    \\#define ZCRYPTO_ERROR_BUFFER_TOO_SMALL -4
    \\#define ZCRYPTO_ERROR_INTERNAL -5
    \\
    \\// Ed25519 functions
    \\int zcrypto_ed25519_keypair(uint8_t* public_key, uint8_t* private_key);
    \\int zcrypto_ed25519_sign(const uint8_t* private_key, const uint8_t* message, size_t message_len, uint8_t* signature);
    \\int zcrypto_ed25519_verify(const uint8_t* public_key, const uint8_t* message, size_t message_len, const uint8_t* signature);
    \\
    \\// Secp256k1 functions
    \\int zcrypto_secp256k1_keypair(uint8_t* public_key, uint8_t* private_key);
    \\int zcrypto_secp256k1_sign(const uint8_t* private_key, const uint8_t* message_hash, uint8_t* signature);
    \\int zcrypto_secp256k1_verify(const uint8_t* public_key, const uint8_t* message_hash, const uint8_t* signature);
    \\
    \\// Hash functions
    \\int zcrypto_blake3_hash(const uint8_t* input, size_t input_len, uint8_t* output);
    \\int zcrypto_sha256_hash(const uint8_t* input, size_t input_len, uint8_t* output);
    \\
    \\// Post-quantum ML-KEM-768 functions
    \\int zcrypto_ml_kem_768_keypair(uint8_t* public_key, uint8_t* private_key);
    \\int zcrypto_ml_kem_768_encaps(const uint8_t* public_key, uint8_t* ciphertext, uint8_t* shared_secret);
    \\int zcrypto_ml_kem_768_decaps(const uint8_t* private_key, const uint8_t* ciphertext, uint8_t* shared_secret);
    \\
    \\// Post-quantum SLH-DSA-128f functions
    \\int zcrypto_slh_dsa_128f_keypair(uint8_t* public_key, uint8_t* private_key);
    \\int zcrypto_slh_dsa_128f_sign(const uint8_t* private_key, const uint8_t* message, size_t message_len, uint8_t* signature);
    \\int zcrypto_slh_dsa_128f_verify(const uint8_t* public_key, const uint8_t* message, size_t message_len, const uint8_t* signature);
    \\
    \\// Utility functions
    \\int zcrypto_random_bytes(uint8_t* buffer, size_t len);
    \\int zcrypto_secure_compare(const uint8_t* a, const uint8_t* b, size_t len);
    \\void zcrypto_secure_zero(uint8_t* buffer, size_t len);
    \\
    \\// Multi-signature functions
    \\int zcrypto_multisig_create_context(uint32_t threshold, uint32_t total_signers, const uint8_t* public_keys, uint8_t* context_out);
    \\int zcrypto_multisig_add_signature(uint8_t* context, uint32_t signer_index, const uint8_t* signature, const uint8_t* message, size_t message_len);
    \\int zcrypto_multisig_verify(const uint8_t* context, const uint8_t* message, size_t message_len);
    \\
    \\// Info functions
    \\const char* zcrypto_version(void);
    \\const char* zcrypto_last_error(void);
    \\int zcrypto_test_hash_known_input(void);
    \\
    \\#ifdef __cplusplus
    \\}
    \\#endif
    \\
    \\#endif // ZCRYPTO_H
    \\
    },
    .{ .name = "ghostbridge.h", .content = 
    \\#ifndef GHOSTBRIDGE_H
    \\#define GHOSTBRIDGE_H
    \\
    \\#ifdef __cplusplus
    \\extern "C" {
    \\#endif
    \\
    \\#include <stdint.h>
    \\#include <stddef.h>
    \\
    \\// Opaque pointer types
    \\typedef void* GhostBridge;
    \\typedef void* GrpcConnection;
    \\typedef void* GrpcStream;
    \\
    \\// Configuration structure
    \\typedef struct {
    \\    uint16_t port;
    \\    uint32_t max_connections;
    \\    uint32_t request_timeout_ms;
    \\    uint8_t enable_discovery;
    \\    uint8_t reserved[32];
    \\} BridgeConfig;
    \\
    \\// gRPC request structure
    \\typedef struct {
    \\    char service[64];
    \\    char method[64];
    \\    const uint8_t* data;
    \\    size_t data_len;
    \\    uint64_t request_id;
    \\} GrpcRequest;
    \\
    \\// gRPC response structure
    \\typedef struct {
    \\    uint8_t* data;
    \\    size_t data_len;
    \\    uint32_t status;
    \\    char error_message[256];
    \\    uint64_t response_id;
    \\} GrpcResponse;
    \\
    \\// Service info structure
    \\typedef struct {
    \\    char name[64];
    \\    char endpoint[128];
    \\    uint8_t service_type;
    \\    uint8_t health_status;
    \\} ServiceInfo;
    \\
    \\// Core bridge functions
    \\GhostBridge* ghostbridge_init(const BridgeConfig* config);
    \\void ghostbridge_destroy(GhostBridge* bridge);
    \\int ghostbridge_start(GhostBridge* bridge);
    \\void ghostbridge_stop(GhostBridge* bridge);
    \\
    \\// Service management
    \\int ghostbridge_register_service(GhostBridge* bridge, const char* name, const char* endpoint);
    \\int ghostbridge_unregister_service(GhostBridge* bridge, const char* name);
    \\int ghostbridge_get_services(GhostBridge* bridge, ServiceInfo* services, size_t max_services);
    \\uint8_t ghostbridge_check_service_health(GhostBridge* bridge, const char* service_name);
    \\void ghostbridge_set_health_callback(GhostBridge* bridge, void (*callback)(const char*, uint8_t));
    \\
    \\// gRPC communication
    \\GrpcConnection* ghostbridge_create_grpc_connection(GhostBridge* bridge, const char* service_name);
    \\void ghostbridge_close_grpc_connection(GrpcConnection* conn);
    \\GrpcResponse* ghostbridge_send_grpc_request(GrpcConnection* conn, const GrpcRequest* request);
    \\void ghostbridge_free_grpc_response(GrpcResponse* response);
    \\
    \\// Streaming gRPC
    \\GrpcStream* ghostbridge_create_grpc_stream(GrpcConnection* conn, const char* service, const char* method);
    \\void ghostbridge_close_grpc_stream(GrpcStream* stream);
    \\ssize_t ghostbridge_stream_send(GrpcStream* stream, const uint8_t* data, size_t len);
    \\ssize_t ghostbridge_stream_receive(GrpcStream* stream, uint8_t* buffer, size_t max_len);
    \\
    \\// Statistics and monitoring
    \\int ghostbridge_get_stats(GhostBridge* bridge, uint64_t* total_connections, uint32_t* active_connections, uint64_t* requests_handled, uint64_t* errors);
    \\
    \\// Testing function
    \\const char* ghostbridge_test_echo(const char* input);
    \\
    \\#ifdef __cplusplus
    \\}
    \\#endif
    \\
    \\#endif // GHOSTBRIDGE_H
    \\
    },
    .{ .name = "zquic_services.h", .content = 
    \\#ifndef ZQUIC_SERVICES_H
    \\#define ZQUIC_SERVICES_H
    \\
    \\#ifdef __cplusplus
    \\extern "C" {
    \\#endif
    \\
    \\#include <stdint.h>
    \\#include <stddef.h>
    \\
    \\// Forward declarations for Wraith Proxy
    \\typedef void* WraithProxy;
    \\typedef void* BackendPool;
    \\
    \\// Forward declarations for CNS Resolver
    \\typedef void* CnsResolver;
    \\typedef void* DnsMessage;
    \\
    \\// Wraith Proxy Configuration
    \\typedef struct {
    \\    const char* address;
    \\    uint16_t port;
    \\    uint32_t max_connections;
    \\    const char* cert_path;
    \\    const char* key_path;
    \\    uint8_t enable_post_quantum;
    \\    uint8_t enable_compression;
    \\    uint32_t cache_size_mb;
    \\    uint32_t health_check_interval_s;
    \\} WraithConfig;
    \\
    \\// Load balancing algorithms
    \\typedef enum {
    \\    WRAITH_LB_ROUND_ROBIN = 0,
    \\    WRAITH_LB_LEAST_CONNECTIONS = 1,
    \\    WRAITH_LB_LEAST_RESPONSE_TIME = 2,
    \\    WRAITH_LB_WEIGHTED_ROUND_ROBIN = 3,
    \\    WRAITH_LB_IP_HASH = 4,
    \\    WRAITH_LB_CONSISTENT_HASH = 5
    \\} WraithLoadBalancingAlgorithm;
    \\
    \\// Backend health status
    \\typedef enum {
    \\    WRAITH_BACKEND_UNKNOWN = 0,
    \\    WRAITH_BACKEND_HEALTHY = 1,
    \\    WRAITH_BACKEND_UNHEALTHY = 2,
    \\    WRAITH_BACKEND_MAINTENANCE = 3,
    \\    WRAITH_BACKEND_DRAINING = 4
    \\} WraithBackendHealth;
    \\
    \\// Wraith Proxy functions
    \\WraithProxy* wraith_init(const WraithConfig* config);
    \\void wraith_destroy(WraithProxy* proxy);
    \\int wraith_start(WraithProxy* proxy);
    \\int wraith_stop(WraithProxy* proxy);
    \\
    \\// Backend management
    \\int wraith_add_backend(WraithProxy* proxy, const char* id, const char* address, uint16_t port, uint8_t weight);
    \\int wraith_remove_backend(WraithProxy* proxy, const char* backend_id);
    \\int wraith_set_load_balancing(WraithProxy* proxy, WraithLoadBalancingAlgorithm algorithm);
    \\
    \\// Proxy statistics
    \\typedef struct {
    \\    uint64_t total_requests;
    \\    uint64_t successful_requests;
    \\    uint64_t failed_requests;
    \\    uint64_t cache_hits;
    \\    uint64_t cache_misses;
    \\    uint64_t avg_response_time_us;
    \\    uint32_t healthy_backends;
    \\    uint32_t total_load;
    \\} WraithStats;
    \\
    \\int wraith_get_stats(WraithProxy* proxy, WraithStats* stats);
    \\
    \\// CNS Resolver Configuration
    \\typedef struct {
    \\    const char* address;
    \\    uint16_t port;
    \\    uint32_t max_connections;
    \\    const char* cert_path;
    \\    const char* key_path;
    \\    uint8_t enable_post_quantum;
    \\    uint8_t enable_caching;
    \\    uint32_t cache_size_mb;
    \\    uint32_t default_cache_ttl_s;
    \\    const char* eth_rpc_endpoint;
    \\    const char* ghost_rpc_endpoint;
    \\    const char* zns_rpc_endpoint;
    \\} CnsResolverConfig;
    \\
    \\// DNS record types
    \\typedef enum {
    \\    DNS_TYPE_A = 1,
    \\    DNS_TYPE_NS = 2,
    \\    DNS_TYPE_CNAME = 5,
    \\    DNS_TYPE_SOA = 6,
    \\    DNS_TYPE_PTR = 12,
    \\    DNS_TYPE_MX = 15,
    \\    DNS_TYPE_TXT = 16,
    \\    DNS_TYPE_AAAA = 28,
    \\    DNS_TYPE_SRV = 33,
    \\    DNS_TYPE_BLOCKCHAIN = 65280,
    \\    DNS_TYPE_IPFS = 65281,
    \\    DNS_TYPE_CONTENT = 65282
    \\} DnsRecordType;
    \\
    \\// CNS Resolver functions
    \\CnsResolver* cns_resolver_init(const CnsResolverConfig* config);
    \\void cns_resolver_destroy(CnsResolver* resolver);
    \\int cns_resolver_start(CnsResolver* resolver);
    \\int cns_resolver_stop(CnsResolver* resolver);
    \\
    \\// DNS resolution
    \\typedef struct {
    \\    char* name;
    \\    DnsRecordType type;
    \\    uint32_t ttl;
    \\    uint16_t data_len;
    \\    uint8_t* data;
    \\} DnsRecord;
    \\
    \\DnsRecord* cns_resolve_domain(CnsResolver* resolver, const char* domain, DnsRecordType type);
    \\void cns_record_destroy(DnsRecord* record);
    \\
    \\// Resolver statistics
    \\typedef struct {
    \\    uint64_t total_queries;
    \\    uint64_t successful_queries;
    \\    uint64_t failed_queries;
    \\    uint64_t cache_hits;
    \\    uint64_t cache_misses;
    \\    uint64_t blockchain_queries;
    \\    uint64_t avg_response_time_us;
    \\    uint64_t uptime_seconds;
    \\    double cache_hit_rate;
    \\} CnsResolverStats;
    \\
    \\int cns_resolver_get_stats(CnsResolver* resolver, CnsResolverStats* stats);
    \\
    \\#ifdef __cplusplus
    \\}
    \\#endif
    \\
    \\#endif // ZQUIC_SERVICES_H
    \\
    },
};

const HeaderFile = struct {
    name: []const u8,
    content: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.args();
    _ = args.skip(); // Skip program name

    var output_dir: []const u8 = "include";

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--output-dir")) {
            if (args.next()) |dir| {
                output_dir = dir;
            }
        }
    }

    // Create output directory
    std.fs.cwd().makeDir(output_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Generate all header files
    for (headers) |header| {
        const file_path = try std.fs.path.join(allocator, &.{ output_dir, header.name });
        defer allocator.free(file_path);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(header.content);
        std.debug.print("Generated: {s}\n", .{file_path});
    }

    std.debug.print("C headers generated successfully in '{s}'\n", .{output_dir});
}
