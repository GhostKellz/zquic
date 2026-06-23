# State Machines

This page documents the state transitions that matter when reading zquic core,
HTTP/3 shutdown, stream lifecycle, and crypto update code. It is a map of the
current implementation posture, not a complete RFC conformance claim.

## Connection Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Initial
    Initial --> Handshaking: first Initial packet
    Handshaking --> Connected: handshake keys installed
    Connected --> Draining: initiateShutdown() / CONNECTION_CLOSE
    Connected --> Closing: fatal transport error
    Draining --> Closed: drain timeout or close confirmation
    Closing --> Closed: close frame flushed
    Closed --> [*]

    Handshaking --> Closing: TLS / transport violation
    Initial --> Closing: unsupported version or malformed required field
```

## Stream Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Open: new stream event
    Open --> HalfClosedRemote: peer FIN
    Open --> HalfClosedLocal: local FIN
    HalfClosedRemote --> Closed: local FIN
    HalfClosedLocal --> Closed: peer FIN
    Open --> Reset: RESET_STREAM / STOP_SENDING
    HalfClosedRemote --> Reset
    HalfClosedLocal --> Reset
    Reset --> Closed: cleanup
    Closed --> [*]
```

## Event Queue Ownership

```mermaid
sequenceDiagram
    participant Producer as Packet/Frame path
    participant Queue as Pending stream events
    participant Conn as Core connection
    participant H3 as HTTP/3 or DoQ

    Producer->>Queue: queueStreamEvent()
    H3->>Conn: processPendingStreamEvents()
    Conn->>Conn: mutate stream table
    Conn-->>H3: open stream IDs and borrowed pointers
    H3->>H3: accept once by stream ID
    H3->>Conn: stream remains core-owned
```

The protocol layer does not own stream memory. It tracks IDs, request state,
and borrowed stream pointers that must not outlive the connection.

## Key Phase Lifecycle

```mermaid
stateDiagram-v2
    [*] --> CurrentPhase
    CurrentPhase --> PendingUpdate: initiateKeyUpdate()
    PendingUpdate --> CurrentPhase: reject overlapping update
    PendingUpdate --> NextPhase: completeKeyUpdate()
    NextPhase --> CurrentPhase: next update window

    CurrentPhase: decrypt current phase
    PendingUpdate: retain current + pending keys
    NextPhase: old phase discarded
```

Key update tests cover overlapping update rejection, old-key discard,
packet-number continuity, rollback rejection, and wrong-key decrypt failures.

## Advanced HTTP/3 Shutdown

```mermaid
stateDiagram-v2
    [*] --> Accepting
    Accepting --> GracefulShutdown: beginGracefulShutdown()
    GracefulShutdown --> GoawaySent: send GOAWAY
    GoawaySent --> DrainingStreams: reject new streams
    DrainingStreams --> Closed: all streams closed
    DrainingStreams --> ForceClose: shutdown timeout
    ForceClose --> Closed: CONNECTION_CLOSE sent
```

Shutdown stops new work first, then attempts to drain active streams. Timeout
paths release connection context and close transport state predictably.

## PQ Preview Reuse Gate

```mermaid
flowchart TD
    request["Pool reuse request"] --> capable{"PQ capable?"}
    capable -->|no| reject["reject reuse"]
    capable -->|yes| established{"handshake established?"}
    established -->|no| reject
    established -->|yes| ticket{"ticket present and authentic?"}
    ticket -->|no| reject
    ticket -->|yes| binder{"binder and policy match?"}
    binder -->|no| reject
    binder -->|yes| migration{"migration required?"}
    migration -->|yes| migok{"connection supports migration?"}
    migration -->|no| zerortt{"0-RTT policy allowed?"}
    migok -->|no| reject
    migok -->|yes| zerortt
    zerortt -->|mismatch| reject
    zerortt -->|match| reuse["reuse allowed"]
```

PQ pooling remains preview-grade. The reuse gate exists to fail closed on
issuer, ticket, MAC, binder, migration, or early-data policy mismatch.
