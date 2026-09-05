# Core API Reference

This page maps the supported public entry points exported by `src/root.zig`.
The Zig declarations remain the authoritative signature reference.

## Module Map

```mermaid
flowchart TD
    root["@import(\"zquic\")"] --> connection["Connection module"]
    root --> packet["Packet module"]
    root --> stream["Stream module"]
    root --> crypto["PacketCrypto and TLS helpers"]
    root --> protocols["Http3 / DoQ"]
    root --> runtime["UDP / transport / async runtime"]

    connection --> wrapper["Connection.Connection"]
    connection --> engine["Connection.SuperConnection"]
    packet --> header["PacketHeader / ConnectionId"]
    stream --> streamtype["Stream.Stream / StreamType"]
    crypto --> tlsleaf["Tls13Messages / Tls13KeySchedule"]
    crypto --> probeid["Tls13Identity probe fixtures"]
    protocols --> h3probe["Http3.MinimalInterop probe subset"]
```

`Connection`, `Packet`, `Stream`, `FlowControl`, and `Congestion` are module
exports. Their concrete types are nested below them; for example,
`zquic.Connection.Connection` is the compatibility wrapper and
`zquic.Connection.SuperConnection` is the lower-level orchestration type.

## Connection and Streams

Create the compatibility connection wrapper with a role and
`ConnectionParams`:

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

The wrapper exposes stream lookup/creation, queued stream-event processing,
statistics, negotiated peer transport parameters, and shutdown state. The
lower-level `SuperConnection` additionally owns protected raw-packet queues,
packet-number spaces, ACK/loss recovery, CRYPTO scheduling/reassembly, and the
bounded Comprehensive TLS bridge used by the interop probe.

Advanced raw-packet methods include:

- `queueIncomingRawPacket()` and `drainOutgoingRawPackets()` for owned datagram
  handoff;
- `sendProtectedRawPacket()` and `scheduleFramesAsProtectedRawPacket()` for
  packet emission;
- `schedulePendingCryptoAsProtectedRawPacket()` and
  `retransmitRetainedCryptoAsProtectedRawPacket()` for CRYPTO flight handling;
- `schedulePendingAckFrames()` and `pollLossRecovery()` for recovery; and
- `processNextIncomingInitialCryptoAndScheduleServerFlightWithComprehensiveTls()`
  for the strict probe handshake path.

These are connection-loop primitives, not a stable high-level server accept
API.

## Packet Types

The `zquic.Packet` module exports:

- `ConnectionId`, limited to 20 bytes;
- `PacketHeader` parsing and serialization;
- `VersionNegotiationPacket`, `RetryPacket`, and `StatelessReset` helpers;
- `PacketType` and `PacketNumberSpace`; and
- packet-number truncation/reconstruction helpers.

Short-header parsing currently assumes the probe's negotiated eight-byte
destination connection ID. Callers using another CID length need their own
connection-aware short-header boundary.

## Packet Protection

`zquic.PacketCrypto` is the packet-protection facade. It accepts an
`EnhancedTlsContext`, installs directional Initial, Handshake, and application
keys, and protects or processes constrained raw packets.

The RFC 9001 key installers are:

- `installRfc9001ServerInitialKeys()`;
- `installRfc9001ClientInitialKeys()`;
- `installRfc9001HandshakeKeys()`; and
- `installRfc9001ApplicationKeys()`.

Handshake and application installers take distinct local and remote key sets.
Installed RFC key levels are pinned so compatibility refreshes cannot replace
them.

## Bounded TLS Helpers

`zquic.ComprehensiveTls` is an experimental engine, not a production-complete
TLS stack. Its strict server path supports the interop probe's bounded TLS 1.3
profile and withholds application keys until peer Finished authentication.

- `Tls13Messages` parses ClientHello and constructs ServerHello for the
  supported profile.
- `Tls13KeySchedule` provides SHA-256 TLS 1.3 and RFC 9001 derivation helpers.
- `Tls13Identity` creates ephemeral self-signed Ed25519 and ECDSA P-256
  identities for tests and interop only.

Configured signing keys are checked against the leaf certificate. The
ephemeral identities do not provide trust, rotation, persistence, or production
certificate policy.

## HTTP/3 and DoQ

When enabled, `zquic.Http3` exports server, request, response, router, frame,
and QPACK modules. `Http3.Http3Client.supported` is `false` and its initializer
fails closed with `NotSupported`.

`Http3.MinimalInterop` is a separate bounded wire subset for the live external
probe. It accepts only the static-QPACK `GET /` profile and returns a fixed 200
response. It is not the general HTTP/3 server API.

`zquic.DoQ` exports DNS-over-QUIC message, client, server, and resolver helpers
when DoQ is enabled.

## Feature-Gated Exports

Build options are `-Dhttp3`, `-Ddoq`, `-Dservices`, `-Dvpn`,
`-Dmonitoring`, `-Dpost-quantum`, and `-Dexperimental-crypto`. The public
`build_config` constants report the compiled feature set.

Post-quantum code requires both `-Dpost-quantum=true` and
`-Dexperimental-crypto=true`. It remains experimental and is not a production
default.

## Error Handling and Ownership

Fallible core paths use `zquic.Error.ZquicError`. Owned values document their
cleanup method; connections, packet crypto contexts, TLS contexts, generated
identities, and processed raw packets must be deinitialized by their owners.
Slices returned from drain/collection methods are caller-owned unless the
declaration says otherwise.

For maturity and security boundaries, see
[Crypto Module Maturity](../features/crypto-maturity.md) and
[RFC 9001 Crypto Audit](../features/rfc9001-crypto-audit.md).
