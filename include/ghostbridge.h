#ifndef GHOSTBRIDGE_H
#define GHOSTBRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Opaque pointer types
typedef void* GhostBridge;
typedef void* GrpcConnection;
typedef void* GrpcStream;

// Configuration structure
typedef struct {
    uint16_t port;
    uint32_t max_connections;
    uint32_t request_timeout_ms;
    uint8_t enable_discovery;
    uint8_t reserved[32];
} BridgeConfig;

// gRPC request structure
typedef struct {
    char service[64];
    char method[64];
    const uint8_t* data;
    size_t data_len;
    uint64_t request_id;
} GrpcRequest;

// gRPC response structure
typedef struct {
    uint8_t* data;
    size_t data_len;
    uint32_t status;
    char error_message[256];
    uint64_t response_id;
} GrpcResponse;

// Service info structure
typedef struct {
    char name[64];
    char endpoint[128];
    uint8_t service_type;
    uint8_t health_status;
} ServiceInfo;

// Core bridge functions
GhostBridge* ghostbridge_init(const BridgeConfig* config);
void ghostbridge_destroy(GhostBridge* bridge);
int ghostbridge_start(GhostBridge* bridge);
void ghostbridge_stop(GhostBridge* bridge);

// Service management
int ghostbridge_register_service(GhostBridge* bridge, const char* name, const char* endpoint);
int ghostbridge_unregister_service(GhostBridge* bridge, const char* name);
int ghostbridge_get_services(GhostBridge* bridge, ServiceInfo* services, size_t max_services);
uint8_t ghostbridge_check_service_health(GhostBridge* bridge, const char* service_name);
void ghostbridge_set_health_callback(GhostBridge* bridge, void (*callback)(const char*, uint8_t));

// gRPC communication
GrpcConnection* ghostbridge_create_grpc_connection(GhostBridge* bridge, const char* service_name);
void ghostbridge_close_grpc_connection(GrpcConnection* conn);
GrpcResponse* ghostbridge_send_grpc_request(GrpcConnection* conn, const GrpcRequest* request);
void ghostbridge_free_grpc_response(GrpcResponse* response);

// Streaming gRPC
GrpcStream* ghostbridge_create_grpc_stream(GrpcConnection* conn, const char* service, const char* method);
void ghostbridge_close_grpc_stream(GrpcStream* stream);
ssize_t ghostbridge_stream_send(GrpcStream* stream, const uint8_t* data, size_t len);
ssize_t ghostbridge_stream_receive(GrpcStream* stream, uint8_t* buffer, size_t max_len);

// Statistics and monitoring
int ghostbridge_get_stats(GhostBridge* bridge, uint64_t* total_connections, uint32_t* active_connections, uint64_t* requests_handled, uint64_t* errors);

// Testing function
const char* ghostbridge_test_echo(const char* input);

#ifdef __cplusplus
}
#endif

#endif // GHOSTBRIDGE_H
