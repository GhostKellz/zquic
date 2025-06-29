/*
 * Simple C test for ZQUIC FFI layer
 * Demonstrates integration with Rust/C services in GhostChain ecosystem
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/zquic.h"

int main(void) {
    printf("🔗 ZQUIC C FFI Test\n");
    printf("Version: %s\n", zquic_version());

    // Test basic functions
    printf("\n📡 Testing Basic Functions:\n");
    const char* echo_result = zquic_test_echo("Hello from C!");
    printf("  Echo test: %s\n", echo_result);

    int add_result = zquic_test_add(100, 23);
    printf("  Add test: 100 + 23 = %d\n", add_result);

    // Test context creation
    ZQuicConfig config = {
        .port = 8443,
        .max_connections = 100,
        .connection_timeout_ms = 30000,
        .enable_ipv6 = 1,
        .tls_verify = 1,
        .reserved = {0}
    };

    ZQuicContext* ctx = zquic_init(&config);
    if (ctx) {
        printf("  Context creation: SUCCESS\n");

        // Test connection creation
        ZQuicConnection* conn = zquic_create_connection(ctx, "example.com");
        if (conn) {
            printf("  Connection creation: SUCCESS\n");

            // Test crypto functions
            printf("\n🔐 Testing Crypto Functions:\n");
            int crypto_init_result = zquic_crypto_init();
            printf("  Crypto init: %s\n", crypto_init_result == 0 ? "SUCCESS" : "FAILED");

            // Test key generation
            unsigned char public_key[64];
            unsigned char private_key[64];
            ZQuicCryptoResult result;

            int keygen_result = zquic_crypto_keygen(
                ZQUIC_KEY_ED25519,
                public_key,
                private_key,
                &result
            );
            printf("  Ed25519 keygen: %s\n", keygen_result == 0 ? "SUCCESS" : "FAILED");

            // Test DNS functions
            printf("\n🌐 Testing DNS Functions:\n");
            ZQuicDnsResponse dns_response;
            int dns_result = zquic_dns_query(conn, "vitalik.eth", ZQUIC_DNS_ENS, &dns_response);
            printf("  ENS query: %s\n", dns_result == 0 ? "SUCCESS" : "FAILED");
            if (dns_result == 0) {
                printf("    Response: %.*s\n", (int)dns_response.len, dns_response.data);
            }

            // Test gRPC functions
            printf("\n🌉 Testing gRPC Functions:\n");
            const char* request_data = "{\"test\": \"data\"}";
            ZQuicGrpcResponse* grpc_response = zquic_grpc_call(
                conn,
                "ghost.test.TestService/Echo",
                (unsigned char*)request_data,
                strlen(request_data)
            );

            if (grpc_response) {
                printf("  gRPC call: SUCCESS\n");
                printf("    Status: %u\n", grpc_response->status);
                printf("    Response: %.*s\n", (int)grpc_response->len, grpc_response->data);
                zquic_grpc_response_free(grpc_response);
            } else {
                printf("  gRPC call: FAILED\n");
            }

            zquic_close_connection(conn);
        } else {
            printf("  Connection creation: FAILED\n");
        }

        zquic_destroy(ctx);
        printf("  Context cleanup: SUCCESS\n");
    } else {
        printf("  Context creation: FAILED\n");
    }

    printf("\n✨ C FFI test complete!\n");
    return 0;
}
