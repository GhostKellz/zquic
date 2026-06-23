# Feature Overview

ZQUIC ships as a collection of composable subsystems. Every directory under `src/` wires into the build graph through feature flags so you can ship a 1.3 MB QUIC core or a full HTTP/3 + DoQ + VPN control plane.

## Feature Surface Map

```mermaid
flowchart TD
    flags["Build flags"] --> default["Default profile"]
    flags --> optional["Optional profiles"]
    flags --> experimental["Experimental profiles"]

    default --> core["Core QUIC<br/>src/core"]
    default --> http3["HTTP/3<br/>src/http3"]
    default --> doq["DoQ<br/>src/doq"]

    optional --> monitoring["Monitoring<br/>src/monitoring"]
    optional --> services["Services<br/>src/services"]
    optional --> vpn["VPN<br/>src/vpn"]

    experimental --> pq["PQ preview<br/>src/crypto/pq_quic.zig"]
    experimental --> ssh["SSH/QUIC draft<br/>src/crypto/ssh_quic.zig"]
    experimental --> comprehensive["TLS scaffold<br/>src/crypto/comprehensive_tls.zig"]

    core --> packet["Packets"]
    core --> stream["Streams"]
    core --> recovery["Recovery"]
    http3 --> router["Router + middleware"]
    http3 --> qpack["QPACK subset"]
    doq --> dns["DNS message and stream framing"]
    pq --> zcrypto["zcrypto v1.0.6"]
```

## Maturity Overview

```mermaid
flowchart LR
    stable["Default stable-ish release surface"] --> core["core QUIC"]
    stable --> http3["HTTP/3"]
    stable --> doq["DoQ"]
    stable --> metrics["Prometheus names"]

    bounded["Bounded helpers"] --> tls["enhanced/comprehensive TLS helpers"]
    bounded --> zero["0-RTT ticket helpers"]

    preview["Preview / draft"] --> pq["PQ"]
    preview --> ssh["SSH/QUIC"]
    preview --> vpn["VPN"]
    preview --> ghost["Ghost services"]

    pq --> review["Requires external review before graduation"]
    tls --> certgap["Delegated X.509 boundary; no production-complete TLS stack"]
```

## Core Transport
- QUIC v1 handshake, streams, congestion control, and pacing live in `src/core/`.
- The internal async runtime replaces the old zsync dependency and powers the event loop, timers, and zero-copy packet pipeline.
- Ecosystem positioning notes against quiche, ngtcp2, MsQuic, and aioquic live in `docs/features/quic-ecosystem.md`.
- v0.9.15 interop planning and the optional smoke harness are tracked in `docs/features/quic-interop.md`.

## SSH/QUIC Integration
- `src/crypto/ssh_quic.zig` implements [draft-denis-ssh-quic](https://datatracker.ietf.org/doc/draft-denis-ssh-quic/) secret injection.
- Allows SSH key exchange to **bypass TLS handshake** entirely—useful for SSH-over-QUIC tunnels or environments where SSH authentication is already established.
- `SshQuicSecrets` holds pre-derived 32-byte client/server secrets with secure zeroing support.
- `SshQuicContext` wraps `TlsContext` and supports both SSH-injected and standard TLS modes.
- Proper bidirectional encryption: client→server and server→client use separate key material.
- Security: secrets passed by pointer, automatic `secureZero()` on cleanup.
- Status: draft integration. See `docs/features/crypto-maturity.md` for support boundaries.

## Crypto Module Maturity
- Supported default crypto lives in `src/core/crypto.zig` plus stable zcrypto primitives.
- `enhanced_tls.zig` is a QUIC TLS utility surface, while `comprehensive_tls.zig` exposes a bounded experimental engine with zcrypto-backed record parsing, delegated X.509 verification, ALPN validation, and raw Ed25519 CertificateVerify checks; `hybrid_pq_tls.zig` remains experimental scaffolding.
- Current module-level posture is documented in `docs/features/crypto-maturity.md`.
- RFC 9001 packet protection, TLS, key lifecycle, 0-RTT, and Retry gaps are
  tracked in `docs/features/rfc9001-crypto-audit.md`.

## HTTP/3 + Middleware
- `src/http3/` contains the router, middleware pipeline, QPACK codecs, and the advanced server used by GhostBridge/Wraith.
- Middleware is global by default—fallback/404 responses still flow through auth/logging/static handlers.
- Current RFC 9114 coverage notes live in `docs/features/http3-doq-compliance.md`.

## DNS-over-QUIC (DoQ)
- `src/doq/` exposes a DNS resolver/server stack with post-quantum TLS hooks.
- The server now emits Prometheus metrics for query counts, errors, and active connections so operators can monitor real deployments.
- Current RFC 9250 coverage notes live in `docs/features/http3-doq-compliance.md`.

## Services
- `src/services/` contains Ghost-specific and experimental higher-level modules.
- Service maturity is documented in `docs/features/services.md` and exposed through `zquic.services.service_descriptors`.

## Post-Quantum Crypto (Experimental)
- PQ code paths require both `-Dpost-quantum=true` and `-Dexperimental-crypto=true`.
- Current primitives use zcrypto `v1.0.6`: ML-KEM for key encapsulation and ML-DSA-65 for authentication helpers.
- PQ multiplexer integration remains deferred; see `docs/future-features.md` for that release boundary.

## QUIC VPN (Experimental)
- `src/vpn/router.zig` implements an in-progress packet router that pushes QUIC-encrypted traffic over UDP tunnels.
- Think of it as a **conceptual alternative to mesh VPNs (Tailscale, NetBird, etc.)**—useful for research and lab topologies but not a drop-in replacement yet.
- Dedicated docs live in `docs/features/quic-vpn.md` and two runnable demos (`examples/quic_vpn_server.zig` + `examples/quic_vpn_client.zig`).

## Monitoring + Telemetry
- `src/monitoring/` now includes a Prometheus exporter that surfaces HTTP/3, DoQ, and VPN counters/gauges.
- Telemetry ties back into the existing crypto-focused analytics in `monitoring/crypto_telemetry.zig`.

## Integrations
- `docs/integrations/` covers real-world wiring for Prometheus and zcrypto tuning.
- More guides will be added as people contribute recipes for Envoy, HAProxy, or observability stacks.

## Feature Routing

```mermaid
flowchart TD
    need{"Need"}
    need -->|"Small library core"| minimal["-Dhttp3=false<br/>-Ddoq=false<br/>-Dexamples=false"]
    need -->|"Web edge"| web["default HTTP/3 + DoQ"]
    need -->|"Metrics"| mon["-Dmonitoring=true"]
    need -->|"Ghost workload"| svc["-Dservices=true"]
    need -->|"VPN lab"| vpn["-Dvpn=true"]
    need -->|"PQ experiment"| pq["-Dpost-quantum=true<br/>-Dexperimental-crypto=true"]

    minimal --> core["Core transport"]
    web --> http3["HTTP/3 router and DoQ"]
    mon --> prom["Prometheus exporter"]
    svc --> services["GhostBridge / Wraith / CNS / ZVM"]
    vpn --> tunnel["QUIC-over-UDP tunnel helpers"]
    pq --> crypto["ML-KEM / ML-DSA preview paths"]
```
