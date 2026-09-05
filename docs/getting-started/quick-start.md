# Quick Start Guide

## Requirements

Use the Zig version declared by `minimum_zig_version` in `build.zig.zon`, or a
compatible newer development build.

## Install

After the `v0.9.17` tag is published:

```bash
zig fetch --save https://github.com/ghostkellz/zquic/archive/refs/tags/v0.9.17.tar.gz
```

For an unreleased checkout:

```bash
git clone https://github.com/ghostkellz/zquic
cd zquic
zig build
```

## Build and Test

```bash
# Default core + HTTP/3 + DoQ build
zig build

# Native verification
zig build test --summary all
zig build integration-tests --summary all
zig build fuzz-tests --summary all

# Complete local release matrix
./dev/validate.sh
```

Useful build profiles:

```bash
# Minimal core
zig build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Dexamples=false

# Optional services, VPN, and monitoring
zig build -Dservices=true -Dvpn=true -Dmonitoring=true

# Experimental post-quantum paths
zig build test -Dpost-quantum=true -Dexperimental-crypto=true
```

Installed example binaries are written under `zig-out/bin/`. They demonstrate
individual modules; they are not a production HTTP/3 client/server pair.

## Import the Package

Add the fetched dependency to your executable module:

```zig
const zquic_dep = b.dependency("zquic", .{
    .target = target,
    .optimize = optimize,
    .http3 = true,
    .doq = true,
    .services = false,
    .vpn = false,
    .@"post-quantum" = false,
    .monitoring = false,
});

exe.root_module.addImport("zquic", zquic_dep.module("zquic"));
```

The public core is module-oriented:

```zig
const std = @import("std");
const zquic = @import("zquic");

pub fn example(allocator: std.mem.Allocator) !void {
    var connection = try zquic.Connection.Connection.init(
        allocator,
        .client,
        .{},
    );
    defer connection.deinit();

    const stream = try connection.createStream(.client_bidirectional);
    _ = try stream.write("hello", false);
}
```

See the [Core API Reference](../api/core.md) before using lower-level raw packet
or TLS helpers; those surfaces have explicit ownership and maturity boundaries.

## External Interop Probe

The bounded probe completes one fixed TLS 1.3 and HTTP/3 `GET /` exchange
against quiche, ngtcp2/gtlsclient, and aioquic:

```bash
./dev/docker_validate.sh interop-zquic-server
```

This is release evidence for the probe profile, not broad QUIC or production
certificate-validation support. See [Interop Methodology](../interop/methodology.md).

## Troubleshooting

- Confirm `zig version` satisfies `build.zig.zon`.
- Run `zig build --fetch` if dependencies are not cached.
- Confirm `.zig-cache` and `zig-out` are owned by your user.
- Use `./dev/consumer_smoke_test.sh` to validate package import from a clean
  generated consumer.

## Next Steps

- [Build Configuration](build-config.md)
- [Core API Reference](../api/core.md)
- [Feature Overview](../features/overview.md)
- [Crypto Maturity](../features/crypto-maturity.md)
- [Release Validation](../architecture/release-validation.md)
