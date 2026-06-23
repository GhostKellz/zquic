# Deployment Operations

This page collects operational decisions for running zquic-based services. It
focuses on build profiles, validation, observability, crypto posture, and
incident response.

## Deployment Shape

```mermaid
flowchart TD
    source["Source checkout"] --> build["zig build profile"]
    build --> tests["test matrix"]
    tests --> image["Docker variant"]
    image --> deploy["service deployment"]
    deploy --> metrics["Prometheus scrape"]
    deploy --> logs["structured logs"]
    deploy --> incident["incident response"]

    tests --> default["default"]
    tests --> pq["PQ preview"]
    tests --> services["services/VPN/monitoring"]
    tests --> interop["interop smoke when tools exist"]
```

## Build Profile Selection

```mermaid
flowchart LR
    need{"Deployment need"} --> core["Small transport library"]
    need --> edge["HTTP/3 or DoQ edge"]
    need --> ghost["Ghost services"]
    need --> lab["VPN or PQ lab"]

    core --> minimal["minimal profile"]
    edge --> default["default profile"]
    ghost --> services["services + monitoring"]
    lab --> gated["explicit preview flags"]

    gated --> review["document local review boundary"]
    services --> metrics["enable Prometheus scrape"]
```

| Profile | Use when | Required validation |
|---------|----------|---------------------|
| Minimal | embedding core QUIC only | default tests and consumer smoke |
| Default | HTTP/3 + DoQ service path | default tests, integration tests, Docker release variant |
| Monitoring | exporting `zquic_*` metrics | Prometheus docs and metrics test |
| Services | GhostBridge/Wraith/CNS/ZVM surfaces | services build matrix and service maturity docs |
| VPN | lab tunnel experiments | VPN smoke and explicit non-production posture |
| PQ Preview | experimental ML-KEM/ML-DSA path | PQ matrix, PQ review checklist, issuer-management plan |

## Validation Pipeline

```mermaid
sequenceDiagram
    participant Dev
    participant Zig as Zig test matrix
    participant Docker
    participant Interop
    participant Release

    Dev->>Zig: zig build test --summary all
    Dev->>Zig: PQ and feature-gated matrices
    Dev->>Docker: dev/docker_validate.sh release
    Dev->>Docker: dev/docker_validate.sh valgrind
    Dev->>Interop: dev/interop_smoke.sh when peers exist
    Interop-->>Release: tested/skipped/gap notes
    Docker-->>Release: container evidence
    Zig-->>Release: local evidence
```

## Observability

```mermaid
flowchart TD
    app["zquic application"] --> exporter["Prometheus exporter"]
    exporter --> http3["HTTP/3 streams, queue depth, status families"]
    exporter --> doq["DoQ query and response codes"]
    exporter --> quic["QUIC packet loss and retransmits"]
    exporter --> crypto["handshake, key update, 0-RTT, Retry, reset"]
    exporter --> vpn["VPN packet/byte/route gauges"]
    exporter --> scrape["/metrics scrape"]
```

Metric names are documented in [Prometheus Integration](../integrations/prometheus.md).
Keep dashboards on `zquic_*` names and avoid parsing logs as a substitute for
metrics.

## Crypto Operations

```mermaid
flowchart TD
    crypto{"Crypto path"} --> default["default stable primitives"]
    crypto --> tls["TLS helper surfaces"]
    crypto --> pq["PQ preview"]

    default --> zcrypto["zcrypto v1.0.6"]
    tls --> boundary["certificate validation boundary documented"]
    pq --> issuer["ticket issuer management"]
    pq --> review["PQ review checklist"]

    issuer --> active["active issuer signs"]
    issuer --> previous["previous issuer validates only"]
    issuer --> invalidation["incident invalidation rotates immediately"]
```

Production deployments must not treat the experimental TLS helper surfaces as a
complete X.509 verifier. PQ deployments need an explicit issuer rotation and
invalidation plan before carrying real traffic.

## Incident Response

```mermaid
flowchart TD
    alert["Alert or report"] --> classify{"Classify"}
    classify --> crypto["crypto / key material"]
    classify --> protocol["protocol behavior"]
    classify --> ops["deployment / resource"]

    crypto --> rotate["rotate ticket issuer material"]
    crypto --> disablepq["disable PQ preview if implicated"]
    protocol --> drain["drain affected listeners"]
    protocol --> patch["patch and rerun matrix"]
    ops --> scale["adjust capacity or config"]

    rotate --> report["record evidence"]
    disablepq --> report
    drain --> report
    patch --> report
    scale --> report
```

Document the exact build flags, zcrypto version, zquic commit, failing evidence,
and validation commands used to clear the incident.
