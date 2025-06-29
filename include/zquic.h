#ifndef ZQUIC_H
#define ZQUIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Opaque pointer types
typedef void* ZQuicContext;
typedef void* ZQuicConnection;
typedef void* ZQuicStream;
typedef void* ZQuicServer;

// Configuration structure
typedef struct {
    uint16_t port;
    uint32_t max_connections;
    uint32_t connection_timeout_ms;
    uint8_t enable_ipv6;
    uint8_t tls_verify;
    uint8_t reserved[16];
} ZQuicConfig;

// Connection info structure
typedef struct {
    char remote_addr[64];
    uint8_t connection_id[16];
    uint8_t state;
    uint32_t rtt_us;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} ZQuicConnectionInfo;

// Core functions
ZQuicContext* zquic_init(const ZQuicConfig* config);
void zquic_destroy(ZQuicContext* ctx);

// Server functions
int zquic_create_server(ZQuicContext* ctx);
int zquic_start_server(ZQuicContext* ctx);
void zquic_stop_server(ZQuicContext* ctx);

// Connection functions
ZQuicConnection* zquic_create_connection(ZQuicContext* ctx, const char* remote_addr);
void zquic_close_connection(ZQuicConnection* conn);
ssize_t zquic_send_data(ZQuicConnection* conn, const uint8_t* data, size_t len);
ssize_t zquic_receive_data(ZQuicConnection* conn, uint8_t* buffer, size_t max_len);

// Stream functions
ZQuicStream* zquic_create_stream(ZQuicConnection* conn, uint8_t stream_type);
void zquic_close_stream(ZQuicStream* stream);
ssize_t zquic_stream_send(ZQuicStream* stream, const uint8_t* data, size_t len);
ssize_t zquic_stream_receive(ZQuicStream* stream, uint8_t* buffer, size_t max_len);

// Info and utility functions
int zquic_get_connection_info(ZQuicConnection* conn, ZQuicConnectionInfo* info);
void zquic_set_connection_callback(ZQuicContext* ctx, void (*callback)(ZQuicConnection*, uint8_t, void*));
const char* zquic_version(void);
const char* zquic_last_error(void);

// Test functions
const char* zquic_test_echo(const char* input);
int zquic_test_add(int a, int b);

#ifdef __cplusplus
}
#endif

#endif // ZQUIC_H
