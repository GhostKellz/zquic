# ZQUIC FFI Integration Guide for Crypto Projects

*Version: 0.3.0*  
*Updated: June 28, 2025*

## 🎯 **Overview**

ZQUIC provides a comprehensive FFI (Foreign Function Interface) layer specifically designed for integration with cryptographic and blockchain projects. This guide covers everything needed to integrate ZQUIC as the high-performance transport layer for your crypto services.

## 🚀 **Quick Start**

### For Rust Projects (Recommended)

```toml
# Cargo.toml
[dependencies]
zquic = { path = "../zquic/bindings/rust" }
tokio = "1.0"
```

```rust
use zquic::{ZQuic, ZQuicConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize ZQUIC for your crypto service
    let config = ZQuicConfig::default()
        .port(9443)
        .max_connections(1000)
        .enable_ipv6(true);
        
    let zquic = ZQuic::new(config)?;
    
    // Connect to peer crypto service
    let conn = zquic.connect("peer.crypto.network:9443").await?;
    
    // Make gRPC call to remote service
    let response = conn.grpc_call(
        "crypto.wallet.WalletService/SendTransaction",
        &transaction_data
    ).await?;
    
    println!("Transaction response: {:?}", response);
    Ok(())
}
```

### For C/C++ Projects

```c
#include "zquic.h"

int main() {
    // Initialize ZQUIC context
    ZQuicConfig config = {
        .port = 9443,
        .max_connections = 1000,
        .enable_ipv6 = 1,
        .tls_verify = 1
    };
    
    ZQuicContext* ctx = zquic_init(&config);
    if (!ctx) return 1;
    
    // Connect to peer
    ZQuicConnection* conn = zquic_create_connection(ctx, "peer.crypto.network:9443");
    if (!conn) {
        zquic_destroy(ctx);
        return 1;
    }
    
    // Send crypto transaction
    const char* tx_data = "{\"transaction\": \"...\"}";
    ssize_t sent = zquic_send_data(conn, (const uint8_t*)tx_data, strlen(tx_data));
    
    // Cleanup
    zquic_close_connection(conn);
    zquic_destroy(ctx);
    return 0;
}
```

## 🏗️ **Architecture for Crypto Projects**

### **Transport Layer Design**

```
┌─────────────────────────────────────────────────────┐
│                 Crypto Application                  │
├─────────────────────────────────────────────────────┤
│ gRPC Services (Wallet, Trading, DeFi, etc.)       │
├─────────────────────────────────────────────────────┤
│ ZQUIC FFI Layer                                    │
│ ├─ GhostBridge (gRPC-over-QUIC)                   │
│ ├─ Wraith (Reverse Proxy)                         │
│ ├─ CNS/ZNS (Crypto DNS)                           │
│ └─ ZCrypto Integration                             │
├─────────────────────────────────────────────────────┤
│ QUIC Transport (High-Performance)                  │
├─────────────────────────────────────────────────────┤
│ UDP/IPv6 Network Layer                             │
└─────────────────────────────────────────────────────┘
```

## 🔐 **Cryptographic Operations**

### **Key Generation**

```rust
use zquic::crypto::{KeyType, CryptoResult};

// Generate Ed25519 key pair for signatures
let mut public_key = [0u8; 32];
let mut private_key = [0u8; 32];
let mut result = CryptoResult::new();

let status = unsafe {
    zquic_crypto_keygen(
        KeyType::Ed25519 as u8,
        public_key.as_mut_ptr(),
        private_key.as_mut_ptr(),
        &mut result
    )
};

if status == 0 {
    println!("Generated Ed25519 key pair");
    // Use keys for crypto operations
}
```

### **Digital Signatures**

```rust
use zquic::crypto::{KeyType, CryptoResult};

// Sign transaction data
let transaction_data = b"transfer 100 tokens to 0x1234...";
let mut signature = [0u8; 64];
let mut result = CryptoResult::new();

let status = unsafe {
    zquic_crypto_sign(
        KeyType::Ed25519 as u8,
        private_key.as_ptr(),
        transaction_data.as_ptr(),
        transaction_data.len(),
        signature.as_mut_ptr(),
        &mut result
    )
};

if status == 0 {
    println!("Transaction signed successfully");
    // Broadcast signed transaction
}
```

### **Cryptographic Hashing**

```rust
use zquic::crypto::{HashType, CryptoResult};

// Hash block data with Blake3
let block_data = b"block header + transactions";
let mut hash_output = [0u8; 32];
let mut result = CryptoResult::new();

let status = unsafe {
    zquic_crypto_hash(
        HashType::Blake3 as u8,
        block_data.as_ptr(),
        block_data.len(),
        hash_output.as_mut_ptr(),
        &mut result
    )
};

if status == 0 {
    println!("Block hash: {:?}", hex::encode(hash_output));
}
```

## 🌐 **gRPC-over-QUIC for Crypto Services**

### **Client-Side gRPC Calls**

```rust
use zquic::{ZQuic, grpc::GrpcResponse};

async fn send_transaction(zquic: &ZQuic, tx_data: &[u8]) -> Result<GrpcResponse> {
    let conn = zquic.connect("wallet.service.crypto:9443").await?;
    
    // Make gRPC call over QUIC
    let response = conn.grpc_call(
        "crypto.wallet.WalletService/SendTransaction",
        tx_data
    ).await?;
    
    // Parse response
    let tx_hash = parse_transaction_response(&response.data)?;
    println!("Transaction hash: {}", tx_hash);
    
    Ok(response)
}
```

### **Server-Side gRPC Handling**

```rust
use zquic::{ZQuic, grpc::GrpcRequest};

// Set up gRPC handler for incoming requests
let handler = |method: &str, request: &[u8]| -> Result<Vec<u8>> {
    match method {
        "crypto.wallet.WalletService/SendTransaction" => {
            let tx = parse_transaction(request)?;
            let tx_hash = process_transaction(tx)?;
            Ok(format_response(tx_hash))
        }
        "crypto.wallet.WalletService/GetBalance" => {
            let address = parse_address(request)?;
            let balance = get_balance(address)?;
            Ok(format_balance_response(balance))
        }
        _ => Err("Unknown method".into())
    }
};

zquic.grpc_serve(handler).await?;
```

## 🔗 **Blockchain Integration Examples**

### **DeFi Trading Service**

```rust
struct DeFiTradingService {
    zquic: ZQuic,
}

impl DeFiTradingService {
    pub async fn execute_trade(&self, trade: Trade) -> Result<TradeResult> {
        // Connect to DEX service
        let conn = self.zquic.connect("dex.crypto.exchange:9443").await?;
        
        // Prepare trade data
        let trade_data = serialize_trade(&trade)?;
        
        // Execute trade via gRPC
        let response = conn.grpc_call(
            "defi.exchange.TradingService/ExecuteTrade",
            &trade_data
        ).await?;
        
        // Parse execution result
        let result = parse_trade_result(&response.data)?;
        Ok(result)
    }
    
    pub async fn get_market_data(&self, symbol: &str) -> Result<MarketData> {
        let conn = self.zquic.connect("market.data.service:9443").await?;
        
        let request = format!(r#"{{"symbol": "{}"}}"#, symbol);
        let response = conn.grpc_call(
            "defi.market.MarketService/GetMarketData",
            request.as_bytes()
        ).await?;
        
        let market_data = parse_market_data(&response.data)?;
        Ok(market_data)
    }
}
```

### **Wallet Service Integration**

```rust
struct CryptoWallet {
    zquic: ZQuic,
}

impl CryptoWallet {
    pub async fn send_payment(&self, to: &str, amount: u64) -> Result<String> {
        // Connect to blockchain node
        let conn = self.zquic.connect("node.blockchain.network:9443").await?;
        
        // Create transaction
        let tx = Transaction {
            to: to.to_string(),
            amount,
            timestamp: SystemTime::now(),
        };
        
        // Sign transaction
        let tx_data = serialize_transaction(&tx)?;
        let signature = self.sign_transaction(&tx_data)?;
        
        // Submit via gRPC
        let request = SignedTransaction { tx, signature };
        let response = conn.grpc_call(
            "blockchain.node.NodeService/SubmitTransaction",
            &serialize_signed_tx(&request)?
        ).await?;
        
        // Return transaction hash
        let tx_hash = parse_tx_hash(&response.data)?;
        Ok(tx_hash)
    }
    
    pub async fn get_balance(&self, address: &str) -> Result<u64> {
        let conn = self.zquic.connect("indexer.blockchain.network:9443").await?;
        
        let request = format!(r#"{{"address": "{}"}}"#, address);
        let response = conn.grpc_call(
            "blockchain.indexer.IndexerService/GetBalance",
            request.as_bytes()
        ).await?;
        
        let balance = parse_balance(&response.data)?;
        Ok(balance)
    }
}
```

## 🌍 **DNS-over-QUIC for Crypto Domains**

### **ENS Resolution**

```rust
use zquic::dns::{DnsQueryType, DnsResponse};

async fn resolve_ens_domain(zquic: &ZQuic, domain: &str) -> Result<String> {
    let conn = zquic.connect("ens.resolver.eth:9443").await?;
    
    let mut response = DnsResponse::new();
    let status = unsafe {
        zquic_dns_query(
            conn.as_ptr(),
            format!("{}\0", domain).as_ptr() as *const i8,
            DnsQueryType::Ens as u16,
            &mut response
        )
    };
    
    if status == 0 {
        let address = String::from_utf8(response.data[0..response.len].to_vec())?;
        Ok(address)
    } else {
        Err("ENS resolution failed".into())
    }
}

// Usage
let address = resolve_ens_domain(&zquic, "vitalik.eth").await?;
println!("vitalik.eth resolves to: {}", address);
```

### **ZNS Resolution**

```rust
async fn resolve_zns_domain(zquic: &ZQuic, domain: &str) -> Result<String> {
    let conn = zquic.connect("zns.resolver.ghost:9443").await?;
    
    let mut response = DnsResponse::new();
    let status = unsafe {
        zquic_dns_query(
            conn.as_ptr(),
            format!("{}\0", domain).as_ptr() as *const i8,
            DnsQueryType::Zns as u16,
            &mut response
        )
    };
    
    if status == 0 {
        let address = String::from_utf8(response.data[0..response.len].to_vec())?;
        Ok(address)
    } else {
        Err("ZNS resolution failed".into())
    }
}

// Usage
let address = resolve_zns_domain(&zquic, "wallet.ghost").await?;
println!("wallet.ghost resolves to: {}", address);
```

## 🔧 **Configuration for Crypto Projects**

### **High-Performance Configuration**

```rust
use zquic::ZQuicConfig;

let config = ZQuicConfig::default()
    // Network settings for crypto services
    .port(9443)                    // Standard crypto service port
    .max_connections(10000)        // High connection limit for exchanges
    .connection_timeout_ms(30000)  // 30 second timeout
    .enable_ipv6(true)            // IPv6 support for global reach
    
    // Security settings
    .tls_verify(true)             // Always verify TLS for crypto
    
    // Performance tuning for crypto workloads
    .initial_max_data(10 * 1024 * 1024)      // 10MB per connection
    .initial_max_streams(1000)                // Support many concurrent operations
    .max_packet_size(1472)                   // Optimal for most networks
    
    // Crypto-specific settings
    .enable_0rtt(false)                      // Disable 0-RTT for security
    .require_crypto_validation(true);        // Always validate crypto operations
```

### **Exchange/Trading Configuration**

```rust
let trading_config = ZQuicConfig::default()
    .port(9443)
    .max_connections(50000)        // Very high for exchanges
    .connection_timeout_ms(5000)   // Fast timeout for trading
    .enable_ipv6(true)
    .priority_queues(true)         // Prioritize trading messages
    .low_latency_mode(true);       // Optimize for minimal latency
```

### **Wallet Service Configuration**

```rust
let wallet_config = ZQuicConfig::default()
    .port(9443)
    .max_connections(1000)         // Moderate for wallet services
    .connection_timeout_ms(60000)  // Longer timeout for user operations
    .enable_ipv6(true)
    .require_authentication(true); // Always require auth for wallets
```

## 📊 **Performance Tuning for Crypto Workloads**

### **Trading Systems**
- **Ultra-Low Latency**: Optimize for sub-millisecond response times
- **High Throughput**: Handle thousands of trades per second
- **Connection Pooling**: Maintain persistent connections to exchanges
- **Priority Queues**: Prioritize market data and execution messages

### **Blockchain Nodes**
- **Block Propagation**: Optimize for fast block distribution
- **Transaction Pool**: Efficient mempool synchronization
- **Peer Discovery**: Rapid peer connection establishment
- **State Sync**: Fast blockchain state synchronization

### **DeFi Protocols**
- **MEV Protection**: Anti-frontrunning measures in transport layer
- **Flash Loan Support**: Ultra-fast transaction execution
- **Cross-Chain**: Support for multiple blockchain networks
- **Oracle Integration**: Real-time price feed handling

## 🛡️ **Security Best Practices**

### **Connection Security**
```rust
// Always verify peer certificates in production
let config = ZQuicConfig::default()
    .tls_verify(true)
    .require_valid_certificate(true)
    .allowed_certificate_authorities(&ca_list);

// Use connection pinning for known peers
zquic.pin_certificate("exchange.crypto.com", &certificate)?;
```

### **Data Validation**
```rust
// Always validate incoming data
fn handle_trade_request(data: &[u8]) -> Result<TradeResponse> {
    // Validate data integrity
    if !validate_checksum(data) {
        return Err("Invalid checksum".into());
    }
    
    // Parse and validate trade
    let trade = parse_trade(data)?;
    if !validate_trade(&trade) {
        return Err("Invalid trade parameters".into());
    }
    
    // Process trade
    execute_trade(trade)
}
```

### **Rate Limiting**
```rust
// Implement rate limiting for API endpoints
let rate_limiter = RateLimiter::new(1000, Duration::seconds(1)); // 1000 requests/second

zquic.add_middleware(move |request| {
    if !rate_limiter.check(&request.peer_address) {
        return Err("Rate limit exceeded".into());
    }
    Ok(())
});
```

## 🚀 **Deployment Examples**

### **Docker Deployment**

```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/crypto-service /usr/local/bin/

EXPOSE 9443
CMD ["crypto-service"]
```

### **Kubernetes Deployment**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crypto-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: crypto-service
  template:
    metadata:
      labels:
        app: crypto-service
    spec:
      containers:
      - name: crypto-service
        image: crypto-service:latest
        ports:
        - containerPort: 9443
          protocol: UDP
        env:
        - name: ZQUIC_PORT
          value: "9443"
        - name: ZQUIC_MAX_CONNECTIONS
          value: "10000"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: crypto-service
spec:
  selector:
    app: crypto-service
  ports:
  - port: 9443
    targetPort: 9443
    protocol: UDP
  type: LoadBalancer
```

## 📚 **API Reference**

### **Core Functions**
- `zquic_init(config)` - Initialize ZQUIC context
- `zquic_create_connection(ctx, addr)` - Create connection to peer
- `zquic_send_data(conn, data, len)` - Send data over connection
- `zquic_receive_data(conn, buffer, max_len)` - Receive data from connection
- `zquic_create_stream(conn, type)` - Create new stream
- `zquic_close_connection(conn)` - Close connection
- `zquic_destroy(ctx)` - Cleanup context

### **gRPC Functions**
- `zquic_grpc_call(conn, method, data, len)` - Make gRPC call
- `zquic_grpc_response_free(response)` - Free gRPC response
- `zquic_grpc_serve(ctx, handler)` - Start gRPC server

### **Crypto Functions**
- `zquic_crypto_init()` - Initialize crypto subsystem
- `zquic_crypto_keygen(type, pubkey, privkey, result)` - Generate key pair
- `zquic_crypto_sign(type, privkey, data, len, sig, result)` - Sign data
- `zquic_crypto_verify(type, pubkey, data, len, sig, result)` - Verify signature
- `zquic_crypto_hash(type, data, len, output, result)` - Hash data

### **DNS Functions**
- `zquic_dns_query(conn, domain, type, response)` - DNS query over QUIC
- `zquic_dns_serve(ctx, resolver)` - Start DNS server

### **Proxy Functions**
- `zquic_proxy_create(ctx, config)` - Create reverse proxy
- `zquic_proxy_route(proxy, conn)` - Route connection through proxy

## 🔍 **Troubleshooting**

### **Common Issues**

1. **Connection Failures**
   ```rust
   // Check network connectivity and firewall settings
   match zquic.connect("peer.crypto.com:9443").await {
       Ok(conn) => { /* success */ }
       Err(e) => eprintln!("Connection failed: {}", e),
   }
   ```

2. **Certificate Validation Errors**
   ```rust
   // Ensure proper certificate configuration
   let config = ZQuicConfig::default()
       .tls_verify(true)
       .ca_certificates("/etc/ssl/certs/ca-certificates.crt");
   ```

3. **Performance Issues**
   ```rust
   // Monitor connection statistics
   let stats = conn.get_statistics();
   println!("RTT: {}μs, Bytes sent: {}, Bytes received: {}", 
            stats.rtt_us, stats.bytes_sent, stats.bytes_received);
   ```

### **Debugging**

```rust
// Enable debug logging
env::set_var("RUST_LOG", "zquic=debug,crypto=debug");
env_logger::init();

// Monitor connection events
zquic.set_connection_callback(|conn, event, data| {
    match event {
        EVENT_CONNECTED => println!("Connected to peer"),
        EVENT_DISCONNECTED => println!("Disconnected from peer"),
        EVENT_ERROR => println!("Connection error: {:?}", data),
        _ => {}
    }
});
```

## 📞 **Support & Community**

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Complete API documentation available
- **Examples**: See `examples/` directory for sample implementations
- **Integration Tests**: Run `cargo test` for validation

---

**ZQUIC FFI Integration is production-ready for crypto projects. Start building the future of decentralized finance with high-performance QUIC transport!** 🚀
