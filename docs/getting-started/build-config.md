# Build Configuration

Configure ZQUIC v0.9.0-RC1 for your specific needs with flexible build options.

## 🧩 Modular Build System

ZQUIC's modular architecture allows you to include only the features you need:

| Build Type | Size | Features | Use Cases |
|------------|------|----------|-----------|
| **Minimal** | ~1.5MB | Core QUIC + zsync | Embedded, IoT, minimal clients |
| **Web** | ~3.5MB | + HTTP/3 + DoQ + PQ | Web servers, CDNs, proxies |
| **Enterprise** | ~5.5MB | + Services + VPN + All | Production servers, services |

## 🚀 Build Options

### Core Features

```bash
# Enable/disable post-quantum cryptography
zig build -Dpost-quantum=true|false

# Enable/disable HTTP/3 support
zig build -Dhttp3=true|false

# Enable/disable DNS-over-QUIC
zig build -Ddoq=true|false

# Enable/disable VPN features
zig build -Dvpn=true|false

# Enable/disable high-level services
zig build -Dservices=true|false
```

### Debug and Development

```bash
# Enable debug logging
zig build -Ddebug=true

# Enable verbose output
zig build -Dverbose=true

# Enable memory safety checks
zig build -Dsafety=true

# Enable performance profiling
zig build -Dprofiling=true
```

### Optimization Levels

```bash
# Debug build (default for development)
zig build -Doptimize=Debug

# Release with safety checks
zig build -Doptimize=ReleaseSafe

# Optimized for speed
zig build -Doptimize=ReleaseFast

# Optimized for size
zig build -Doptimize=ReleaseSmall
```

## 📋 Predefined Configurations

### Minimal Client Build
```bash
zig build -Dpost-quantum=false -Dservices=false -Dvpn=false -Dhttp3=false -Ddoq=false -Doptimize=ReleaseSmall
```
**Result**: ~1.5MB binary with core QUIC transport only

### Web Server Build
```bash
zig build -Dhttp3=true -Ddoq=true -Dpost-quantum=true -Dservices=false -Dvpn=false -Doptimize=ReleaseFast
```
**Result**: ~3.5MB binary optimized for web serving

### Enterprise Build (Default)
```bash
zig build
# Equivalent to: zig build -Dpost-quantum=true -Dhttp3=true -Ddoq=true -Dservices=true -Dvpn=true
```
**Result**: ~5.5MB binary with full feature set

### Embedded/IoT Build
```bash
zig build -Dpost-quantum=false -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Doptimize=ReleaseSmall -Dtarget=arm-linux-musleabi
```
**Result**: Minimal binary for ARM embedded systems

## 🔧 Custom build.zig Configuration

Add to your project's `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // Add ZQUIC dependency
    const zquic_dep = b.dependency("zquic", .{
        .target = target,
        .optimize = optimize,
        // Configure ZQUIC features
        .post_quantum = true,
        .http3 = true,
        .doq = true,
        .services = false,  // Disable services for this build
        .vpn = false,       // Disable VPN features
    });
    
    const exe = b.addExecutable(.{
        .name = "my-quic-server",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    
    exe.root_module.addImport("zquic", zquic_dep.module("zquic"));
    b.installArtifact(exe);
}
```

## ⚙️ Advanced Configuration

### Crypto Configuration

```zig
// In your build.zig
const zquic_options = b.addOptions();
zquic_options.addOption(bool, "enable_ml_kem_768", true);
zquic_options.addOption(bool, "enable_x25519", true);
zquic_options.addOption(bool, "enable_slh_dsa", true);
zquic_options.addOption(bool, "enable_ed25519", true);
zquic_options.addOption(u32, "max_connections", 10000);
zquic_options.addOption(u32, "buffer_size", 65536);
```

### Performance Tuning

```zig
// Network buffer sizes
-Dnetwork_buffer_size=65536
-Dcrypto_buffer_size=32768
-Dmax_packet_size=1472

// Connection limits
-Dmax_connections=10000
-Dmax_streams_per_connection=1000

// Async worker configuration
-Dasync_workers=4
-Dcrypto_workers=2
```

## 🎯 Target-Specific Builds

### Linux Server
```bash
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast
```

### macOS Development
```bash
zig build -Dtarget=aarch64-macos -Doptimize=Debug
```

### Windows Production
```bash
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSafe
```

### ARM Embedded
```bash
zig build -Dtarget=arm-linux-musleabi -Doptimize=ReleaseSmall -Dpost-quantum=false
```

## 📊 Build Size Comparison

| Configuration | Binary Size | Features Included |
|---------------|-------------|-------------------|
| Minimal | 1.2MB | Core QUIC only |
| + HTTP/3 | 2.1MB | + HTTP/3 server |
| + Post-Quantum | 3.4MB | + ML-KEM-768, SLH-DSA |
| + Services | 4.8MB | + Bridge, Proxy, DoQ |
| + VPN | 5.5MB | + VPN routing |
| Full Debug | 8.2MB | + Debug symbols |

## 🔍 Feature Dependencies

```
Core QUIC
├── zsync (async runtime)
├── zcrypto (base crypto)
└── Network layer

HTTP/3
├── Core QUIC
├── QPACK compression
└── Frame parsing

Post-Quantum
├── zcrypto (ML-KEM, SLH-DSA)
└── Hybrid TLS implementation

Services
├── HTTP/3
├── Post-Quantum
└── Service implementations

VPN
├── Services
├── Routing logic
└── Tunnel management
```

## 🚀 Recommended Configurations

### **Development**
```bash
zig build -Ddebug=true -Doptimize=Debug
```

### **Testing**
```bash
zig build -Dsafety=true -Dverbose=true -Doptimize=ReleaseSafe
```

### **Production Web Server**
```bash
zig build -Dhttp3=true -Dpost-quantum=true -Doptimize=ReleaseFast
```

### **High-Performance Trading**
```bash
zig build -Dservices=true -Dpost-quantum=true -Doptimize=ReleaseFast -Dmax_connections=50000
```

### **Embedded/Resource-Constrained**
```bash
zig build -Dpost-quantum=false -Dhttp3=false -Dservices=false -Doptimize=ReleaseSmall
```

---

**Next**: [Basic Examples](examples.md) - See ZQUIC in action