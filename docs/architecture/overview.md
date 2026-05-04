# System Overview

ZQUIC architecture and design principles for high-performance networking.

## 🏗️ Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    ZIG APPLICATION LAYER                   │
├─────────────────┬─────────────────┬─────────────────────────┤
│   QUIC Bridge   │   QUIC Proxy    │     DNS-over-QUIC       │ 
│ (gRPC-over-QUIC)│  (Reverse Proxy)│      (Resolver)         │
├─────────────────┼─────────────────┼─────────────────────────┤
│            ZQUIC HTTP/3 Layer + Services                   │
│          (Enhanced server, routing, middleware)            │
├─────────────────────────────────────────────────────────────┤
│                   QUIC Core Transport                      │
│     (connection.zig, packet.zig, stream.zig)              │
├─────────────────────────────────────────────────────────────┤
│              Crypto Layer (zcrypto v1.0.3)                │
│   ML-KEM-768, SLH-DSA, Ed25519, Secp256k1, Blake3, SHA256  │
├─────────────────────────────────────────────────────────────┤
│                 Networking Foundation                      │
│        (udp.zig, socket.zig, ipv6.zig, async.zig)         │
├─────────────────────────────────────────────────────────────┤
│                    FFI Integration Layer                   │
│           (Cross-language bindings)                       │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 Design Principles

### **Zero-Copy Operations**
- Minimize memory allocations and copies throughout the stack
- Direct buffer manipulation where possible
- Efficient packet processing pipeline

### **Explicit Memory Management**  
- All allocations are explicit and trackable
- Paired allocation/deallocation patterns
- Arena allocators for temporary operations
- Ring buffers for streaming data

### **Modular Architecture**
- Components can be used independently
- Feature-based conditional compilation
- Clean separation of concerns
- Minimal dependencies between modules

### **Compile-Time Safety**
- Leverage Zig's compile-time features for correctness
- Type safety without runtime overhead
- Comprehensive error handling
- Memory safety guarantees

### **Performance First**
- Optimized for high-throughput, low-latency scenarios
- Async processing with native runtime integration
- Lock-free data structures where possible
- SIMD-friendly algorithms

## 🧩 Core Modules

### **src/core/** - QUIC Transport Core
```zig
src/core/
├── connection.zig      # Connection state management
├── packet.zig         # Packet parsing/serialization  
├── stream.zig         # Stream multiplexing
├── flow_control.zig   # Flow control implementation
├── congestion.zig     # BBR/CUBIC congestion control
├── recovery.zig       # Loss detection & recovery
├── packet_space.zig   # Packet number spaces
├── crypto.zig         # Crypto interface
├── io.zig            # I/O abstractions
├── buffers.zig       # Ring buffer management
└── errors.zig        # Error definitions
```

### **src/crypto/** - Post-Quantum Cryptography
```zig
src/crypto/
├── comprehensive_tls.zig    # Full TLS 1.3 implementation
├── hybrid_pq_tls.zig       # Post-quantum hybrid TLS
├── zero_rtt_resumption.zig # 0-RTT session resumption
├── async_crypto.zig        # Asynchronous crypto processing
├── tls.zig                 # TLS integration
├── handshake.zig           # Handshake management
└── keys.zig                # Key derivation & rotation
```

### **src/http3/** - HTTP/3 Implementation
```zig
src/http3/
├── server.zig         # HTTP/3 server implementation
├── frame.zig          # HTTP/3 frame handling
├── qpack.zig          # QPACK compression
├── router.zig         # Request routing
├── middleware.zig     # Middleware system
└── response.zig       # Response handling
```

### **src/services/** - High-Level Services
```zig
src/services/
├── quic_bridge.zig    # gRPC-over-QUIC relay
├── quic_proxy.zig     # Reverse proxy & load balancer
├── dns_resolver.zig   # DNS-over-QUIC resolver
└── vpn_router.zig     # VPN routing functionality
```

### **src/net/** - Networking Foundation
```zig
src/net/
├── udp.zig           # UDP socket abstraction
├── socket.zig        # Socket management
├── ipv6.zig          # IPv6 support
├── address.zig       # Address handling
└── async.zig         # Async networking with native runtime
```

## 🔄 Data Flow

### **Inbound Packet Processing**
```
UDP Socket → Packet Parser → Connection Lookup → Stream Demux → Application
     ↓              ↓              ↓              ↓              ↓
  Raw bytes → QUIC packet → Connection → Stream data → HTTP/3 frame
```

### **Outbound Packet Processing**  
```
Application → Stream Mux → Connection → Packet Builder → UDP Socket
     ↓           ↓           ↓             ↓             ↓
HTTP/3 frame → Stream data → QUIC packet → Raw bytes → Network
```

### **Crypto Processing Pipeline**
```
Plaintext → Async Crypto → Worker Pool → Crypto Engine → Ciphertext
    ↓           ↓             ↓             ↓             ↓
  Clear data → Queue → Process → ML-KEM/X25519 → Encrypted
```

## ⚡ Performance Architecture

### **Async Processing with Native Runtime**
- Non-blocking I/O operations
- Worker thread pools for CPU-intensive tasks
- Channel-based communication
- Efficient task scheduling

### **Zero-Copy Buffer Management**
```zig
// Ring buffer for streaming data
pub const RingBuffer = struct {
    data: []u8,
    read_pos: usize,
    write_pos: usize,
    allocator: std.mem.Allocator,
    
    // Zero-copy read/write operations
    pub fn readSlice(self: *Self, len: usize) ?[]const u8 { ... }
    pub fn writeSlice(self: *Self, len: usize) ?[]u8 { ... }
};
```

### **Memory Pool Management**
```zig
// Arena allocator for connection-scoped allocations
pub const ConnectionArena = struct {
    arena: std.heap.ArenaAllocator,
    
    pub fn init(backing_allocator: std.mem.Allocator) Self { ... }
    pub fn deinit(self: *Self) void { ... }
    pub fn allocator(self: *Self) std.mem.Allocator { ... }
};
```

## 🛡️ Security Architecture

### **Post-Quantum Cryptography Integration**
- Hybrid ML-KEM-768 + X25519 key exchange
- SLH-DSA-128f digital signatures  
- Seamless fallback to classical algorithms
- Future-proof crypto agility

### **Memory Safety**
- Explicit allocator management
- Bounds checking in debug builds
- Safe pointer arithmetic
- Secure memory clearing

### **Protocol Security**
- TLS 1.3 compliance
- Perfect forward secrecy
- Anti-replay protection for 0-RTT
- Connection migration support

## 🔌 Integration Points

### **FFI Layer**
```c
// C API for cross-language integration
typedef struct ZQuicServer ZQuicServer;
typedef struct ZQuicConfig ZQuicConfig;

ZQuicServer* zquic_server_init(const ZQuicConfig* config);
int zquic_server_start(ZQuicServer* server);
void zquic_server_stop(ZQuicServer* server);
void zquic_server_destroy(ZQuicServer* server);
```

### **Rust Bindings**
```rust
// High-level Rust wrapper
pub struct QuicServer {
    inner: *mut ffi::ZQuicServer,
}

impl QuicServer {
    pub fn new(config: ServerConfig) -> Result<Self, Error> { ... }
    pub async fn start(&mut self) -> Result<(), Error> { ... }
}
```

## 📊 Monitoring & Observability

### **Performance Metrics**
- Connection establishment time
- Packet processing latency
- Memory usage tracking
- CPU utilization per module

### **Protocol Metrics**
- Stream multiplexing efficiency
- Congestion control effectiveness
- Crypto operation performance
- Error rates and recovery

### **Integration with Runtime Telemetry**
- Async task queue depths
- Worker pool utilization
- Channel throughput metrics
- Resource contention detection

## ✅ Verification & Testing

- **Core unit tests** (`zig build test`) cover connection, packet space, congestion, and crypto primitives.
- **Handshake integration tests** (`tests/handshake_integration_test.zig`, run via `zig build integration-tests`) simulate the full client/server TLS+QUIC handshake flow.
- **Packet parser fuzzing** (`tests/packet_fuzz_test.zig`, run via `zig build fuzz-tests`) pounds the header parser with randomized corpora to catch regressions early.
- **dev/test.sh** orchestrates all three stages so CI and local developers exercise the same coverage set.

---

**Next**: [Modular Design](modular.md) - Deep dive into modularity
