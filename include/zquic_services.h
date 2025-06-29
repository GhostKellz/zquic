#ifndef ZQUIC_SERVICES_H
#define ZQUIC_SERVICES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Forward declarations for Wraith Proxy
typedef void* WraithProxy;
typedef void* BackendPool;

// Forward declarations for CNS Resolver
typedef void* CnsResolver;
typedef void* DnsMessage;

// Wraith Proxy Configuration
typedef struct {
    const char* address;
    uint16_t port;
    uint32_t max_connections;
    const char* cert_path;
    const char* key_path;
    uint8_t enable_post_quantum;
    uint8_t enable_compression;
    uint32_t cache_size_mb;
    uint32_t health_check_interval_s;
} WraithConfig;

// Load balancing algorithms
typedef enum {
    WRAITH_LB_ROUND_ROBIN = 0,
    WRAITH_LB_LEAST_CONNECTIONS = 1,
    WRAITH_LB_LEAST_RESPONSE_TIME = 2,
    WRAITH_LB_WEIGHTED_ROUND_ROBIN = 3,
    WRAITH_LB_IP_HASH = 4,
    WRAITH_LB_CONSISTENT_HASH = 5
} WraithLoadBalancingAlgorithm;

// Backend health status
typedef enum {
    WRAITH_BACKEND_UNKNOWN = 0,
    WRAITH_BACKEND_HEALTHY = 1,
    WRAITH_BACKEND_UNHEALTHY = 2,
    WRAITH_BACKEND_MAINTENANCE = 3,
    WRAITH_BACKEND_DRAINING = 4
} WraithBackendHealth;

// Wraith Proxy functions
WraithProxy* wraith_init(const WraithConfig* config);
void wraith_destroy(WraithProxy* proxy);
int wraith_start(WraithProxy* proxy);
int wraith_stop(WraithProxy* proxy);

// Backend management
int wraith_add_backend(WraithProxy* proxy, const char* id, const char* address, uint16_t port, uint8_t weight);
int wraith_remove_backend(WraithProxy* proxy, const char* backend_id);
int wraith_set_load_balancing(WraithProxy* proxy, WraithLoadBalancingAlgorithm algorithm);

// Proxy statistics
typedef struct {
    uint64_t total_requests;
    uint64_t successful_requests;
    uint64_t failed_requests;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t avg_response_time_us;
    uint32_t healthy_backends;
    uint32_t total_load;
} WraithStats;

int wraith_get_stats(WraithProxy* proxy, WraithStats* stats);

// CNS Resolver Configuration
typedef struct {
    const char* address;
    uint16_t port;
    uint32_t max_connections;
    const char* cert_path;
    const char* key_path;
    uint8_t enable_post_quantum;
    uint8_t enable_caching;
    uint32_t cache_size_mb;
    uint32_t default_cache_ttl_s;
    const char* eth_rpc_endpoint;
    const char* ghost_rpc_endpoint;
    const char* zns_rpc_endpoint;
} CnsResolverConfig;

// DNS record types
typedef enum {
    DNS_TYPE_A = 1,
    DNS_TYPE_NS = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA = 6,
    DNS_TYPE_PTR = 12,
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_AAAA = 28,
    DNS_TYPE_SRV = 33,
    DNS_TYPE_BLOCKCHAIN = 65280,
    DNS_TYPE_IPFS = 65281,
    DNS_TYPE_CONTENT = 65282
} DnsRecordType;

// CNS Resolver functions
CnsResolver* cns_resolver_init(const CnsResolverConfig* config);
void cns_resolver_destroy(CnsResolver* resolver);
int cns_resolver_start(CnsResolver* resolver);
int cns_resolver_stop(CnsResolver* resolver);

// DNS resolution
typedef struct {
    char* name;
    DnsRecordType type;
    uint32_t ttl;
    uint16_t data_len;
    uint8_t* data;
} DnsRecord;

DnsRecord* cns_resolve_domain(CnsResolver* resolver, const char* domain, DnsRecordType type);
void cns_record_destroy(DnsRecord* record);

// Resolver statistics
typedef struct {
    uint64_t total_queries;
    uint64_t successful_queries;
    uint64_t failed_queries;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t blockchain_queries;
    uint64_t avg_response_time_us;
    uint64_t uptime_seconds;
    double cache_hit_rate;
} CnsResolverStats;

int cns_resolver_get_stats(CnsResolver* resolver, CnsResolverStats* stats);

#ifdef __cplusplus
}
#endif

#endif // ZQUIC_SERVICES_H
