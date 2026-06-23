# TLS And Key Lifecycle

ZQUIC uses zcrypto primitives for packet protection and keeps broader TLS 1.3
work clearly separated by maturity. Production certificate-chain and hostname
validation are not claimed by the experimental comprehensive TLS scaffold.

## QUIC Key Lifecycle

```mermaid
flowchart TD
    INITIAL["Initial secrets\nversion + DCID"] --> HANDSHAKE["Handshake keys"]
    HANDSHAKE --> ONE_RTT["1-RTT application keys"]
    ONE_RTT --> UPDATE["Key update\nnew phase"]
    UPDATE --> OVERLAP["Old keys retained\nbounded overlap"]
    OVERLAP --> DISCARD["Old keys discarded"]

    ONE_RTT -. 0-RTT ticket .-> EARLY["0-RTT early data"]
    EARLY --> POLICY["ALPN + app policy\nremembered transport params"]
    POLICY --> ACCEPT["Accept"]
    POLICY --> REJECT["Reject before anti-replay"]
```

## Handshake Validation

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant TP as Transport Parameters
    participant Keys as Packet Protection

    Client->>Server: Initial + ClientHello
    Server->>Client: Handshake + TLS messages
    Server->>TP: validate role, IDs, stream limits, migration
    TP-->>Server: accepted or rejected
    Server->>Keys: derive handshake and 1-RTT keys
    Client->>Server: Finished
    Server->>Keys: install application keys
```

## Maturity Boundaries

| Surface | Status | Notes |
|---------|--------|-------|
| QUIC packet protection helpers | Supported default | Covered by key update and negative decrypt tests |
| Transport parameter encode/decode | Supported default | Interop-style fixtures and validation tests |
| 0-RTT ticket policy | Supported helper | Binds ALPN, application policy, and remembered transport parameters |
| Raw Ed25519 public-key verification | Bounded helper | Caller supplies the trusted public key |
| DER/X.509 validation | Not supported | Fails closed in `comprehensive_tls.zig` |
| PQ/hybrid TLS | Experimental | Requires both PQ build flags |

See [RFC 9001 Crypto Audit](../features/rfc9001-crypto-audit.md) and
[Crypto Maturity](../features/crypto-maturity.md).
