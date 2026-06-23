# Packet Flow

This page shows how bytes move through zquic from UDP datagrams to application
protocol handlers and back out.

## Inbound Path

```mermaid
flowchart LR
    UDP["UDP datagram"] --> SYS["src/net/sys.zig\nerrno mapping"]
    SYS --> SOCK["UdpSocket\nreceiveFrom / tryReceiveFrom"]
    SOCK --> MUX["Multiplexer\nconnection ID routing"]
    MUX --> PKT["Packet parser\nheader + payload"]
    PKT --> CONN["Connection\npacket number spaces"]
    CONN --> CRYPTO["Packet protection\nremove header/body protection"]
    CRYPTO --> STREAM["Stream table\nread buffers"]
    STREAM --> APP["HTTP/3, DoQ, or service handler"]
```

## Outbound Path

```mermaid
flowchart LR
    APP["HTTP/3 response\nDoQ response\nservice bytes"] --> STREAM["Stream write buffer"]
    STREAM --> CONN["Connection\nframe scheduling"]
    CONN --> CRYPTO["Packet protection\nAEAD + header protection"]
    CRYPTO --> PKT["Packet builder"]
    PKT --> MUX["Multiplexer\nsocket selection"]
    MUX --> SOCK["UdpSocket sendTo"]
    SOCK --> UDP["UDP datagram"]
```

## Stream Acceptance

```mermaid
sequenceDiagram
    participant Core as Core Connection
    participant Events as Stream Event Queue
    participant Table as Stream Table
    participant H3 as Advanced HTTP/3

    Core->>Events: queueStreamEvent(new_stream/data/closed)
    H3->>Core: processPendingStreamEvents()
    Core->>Table: create or update stream
    H3->>Core: collectOpenStreams()
    Core-->>H3: stream pointers owned by connection
    H3->>H3: accept once by stream ID
```

## Operational Notes

- `src/net/sys.zig` normalizes Linux `EPERM` and `EACCES` socket failures into
  ordinary permission errors so restricted test environments can skip cleanly.
- Batch receive/send posture is documented through deterministic UDP tests even
  when live socket permissions are unavailable.
- Streams remain owned by the connection; HTTP/3 and DoQ only track borrowed
  pointers and stream IDs.
