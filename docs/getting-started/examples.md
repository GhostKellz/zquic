# Examples

Every installed example binary should have a matching command here so release
archives are easy to smoke test.

## Default Examples

Built by `zig build` with default flags:

| Binary | Source | Command |
|--------|--------|---------|
| `zquic` | `src/main.zig` | `zig build run -- --help` |
| `zquic-client` | `examples/client.zig` | `./zig-out/bin/zquic-client --help` |
| `zquic-server` | `examples/server.zig` | `./zig-out/bin/zquic-server --help` |
| `zquic-http3-server` | `examples/http3_server.zig` | `./zig-out/bin/zquic-http3-server` |
| `zquic-doq-server` | `examples/doq_echo_server.zig` | `./zig-out/bin/zquic-doq-server` |

## Feature-Gated Examples

| Binary | Flags | Source | Command |
|--------|-------|--------|---------|
| `quic-vpn-server-demo` | `-Dvpn=true` | `examples/quic_vpn_server.zig` | `zig build -Dvpn=true && ./zig-out/bin/quic-vpn-server-demo` |
| `quic-vpn-client-demo` | `-Dvpn=true` | `examples/quic_vpn_client.zig` | `zig build -Dvpn=true && ./zig-out/bin/quic-vpn-client-demo` |
| `zquic-pq-demo` | `-Dpost-quantum=true -Dexperimental-crypto=true` | `examples/pq_quic_demo.zig` | `zig build -Dpost-quantum=true -Dexperimental-crypto=true && ./zig-out/bin/zquic-pq-demo` |

## Deferred Sources

The following example sources are kept for development reference but are not
installed by the current build graph:

- `examples/crypto_trading_demo.zig`
- `examples/integration_test.zig`

Do not document a source as a shipped binary unless `build.zig` installs it.
