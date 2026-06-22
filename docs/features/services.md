# Services

The `-Dservices=true` feature exposes higher-level integrations built on top of
core QUIC, HTTP/3, DoQ, and the native runtime. These modules are useful for
Ghost ecosystem deployments, but they are not all general-purpose stable APIs.

## Maturity Matrix

| Service | Code | Maturity | Default | Notes |
|---------|------|----------|---------|-------|
| GhostBridge | `src/services/ghostbridge.zig` | Ghost-specific | Enabled in service config | gRPC-over-QUIC bridge surface for Ghost deployments. |
| Wraith | `src/services/wraith.zig` | Experimental | Opt-in | Reverse proxy/cache/load-balancer pieces; useful but still hardening. |
| CNS Resolver | `src/services/cns_resolver.zig` | Ghost-specific | Opt-in | CNS/DNS helper surface for Ghost naming flows. |
| ZVM Integration | `src/services/zvm_integration.zig` | Ghost-specific | Opt-in | WASM/ZVM execution integration, not a generic QUIC feature. |

The same classification is available programmatically through
`zquic.services.service_descriptors` and `zquic.services.descriptorFor()`.

## GhostBridge

GhostBridge is supported as a Ghost-specific integration surface. It should be
tested with `zig build test -Dservices=true --summary all` before changes ship.

## Wraith

Wraith remains experimental. Treat it as an in-tree proving ground for reverse
proxy behavior, response caching, and backend selection. Do not describe Wraith
as production-stable until its upstream/downstream HTTP/3 behavior and failure
modes have release-grade tests.

## CNS Resolver

The CNS resolver is scoped to Ghost naming flows. General DNS-over-QUIC support
lives under `src/doq/` instead.

## ZVM Integration

ZVM integration is Ghost-specific and experimental. Keep WASM execution,
allocator lifetime, and request cleanup under separate tests when expanding it.

## Release Rule

Service modules must not change stable QUIC, HTTP/3, DoQ, or crypto defaults.
If a service requires experimental crypto, VPN, or Ghost-only behavior, that
status must be visible in docs and build flags.
