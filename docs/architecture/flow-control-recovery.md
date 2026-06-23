# Flow Control And Recovery

This page describes the moving parts that keep streams bounded and packets
recoverable. The tests are deterministic and local; external RTT, loss, and
congestion evidence is tracked through the interop and release-validation docs.

## Data Movement

```mermaid
flowchart LR
    appwrite["Application write"] --> sendbuf["Stream send buffer"]
    sendbuf --> swin{"stream window?"}
    swin -->|blocked| blocksend["Block writer"]
    swin -->|available| connwin{"connection window?"}
    connwin -->|blocked| blockconn["Queue until MAX_DATA"]
    connwin -->|available| frames["STREAM frames"]
    frames --> packet["Packetization"]
    packet --> recovery["Recovery tracking"]
    recovery --> udp["UDP send"]
```

## Receive Backpressure

```mermaid
flowchart TD
    packet["Incoming protected packet"] --> decrypt["Decrypt and parse"]
    decrypt --> stream["STREAM frame"]
    stream --> recvbuf{"receive buffer capacity?"}
    recvbuf -->|space| buffer["append data"]
    recvbuf -->|full| blocked["mark flow-control blocked"]
    buffer --> appread["application reads"]
    appread --> credit["window update available"]
    credit --> maxstream["emit MAX_STREAM_DATA"]
    credit --> maxdata["emit MAX_DATA"]
```

Receive-window tests cover a slow reader filling the receive buffer, then
recovering after the application drains unread data.

## Packet Recovery Loop

```mermaid
sequenceDiagram
    participant Conn as Connection
    participant Space as Packet space
    participant Recovery as Loss recovery
    participant Peer

    Conn->>Space: record sent packet
    Space->>Recovery: arm loss timer
    Peer-->>Conn: ACK ranges
    Conn->>Space: remove acknowledged packets
    Recovery->>Space: detect timeout/loss
    Space-->>Conn: retransmission candidates
    Conn->>Peer: retransmit frames
```

## Loss Timer Decision Tree

```mermaid
flowchart TD
    timer["Loss detection timer fires"] --> ack{"ACK received?"}
    ack -->|yes| ranges["process ACK ranges"]
    ack -->|no| pto{"PTO expired?"}
    ranges --> lost{"packet deemed lost?"}
    lost -->|yes| retransmit["queue retransmission"]
    lost -->|no| done["return"]
    pto -->|yes| probe["send probe packet"]
    pto -->|no| arm["re-arm timer"]
```

## Current Guarantees

| Area | Current coverage | Notes |
|------|------------------|-------|
| Send flow control | blocked writer waits for window update | deterministic stream tests |
| Receive flow control | slow reader recovery after drain | deterministic stream tests |
| Packet loss | retransmission candidates removed after timeout | integration tests |
| Key phase + packet number | wrong packet number and old keys reject decrypt | crypto tests |
| External network behavior | planned through interop harness | not claimed as broad production evidence |

## Debugging Map

```mermaid
flowchart LR
    symptom{"Symptom"} --> sendblock["writer blocked"]
    symptom --> recvblock["reader pressure"]
    symptom --> retrans["retransmits"]
    symptom --> decrypt["decrypt failure"]

    sendblock --> stream["src/core/stream.zig"]
    recvblock --> stream
    retrans --> recovery["src/core/recovery.zig<br/>src/core/packet_space.zig"]
    decrypt --> crypto["src/core/crypto.zig"]

    stream --> tests["stream tests"]
    recovery --> itests["handshake integration tests"]
    crypto --> ctests["crypto tests"]
```
