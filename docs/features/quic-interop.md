# QUIC Interop Plan

This page defines the v0.9.16 interop posture for zquic. It is a test plan and
evidence log, not a claim that zquic is broadly interoperable with every QUIC
deployment.

The evidence ladder, qlog event taxonomy, and Docker architecture diagrams live
in `docs/interop/methodology.md`.

## Scope

The first interop target is repeatable smoke coverage against maintained QUIC
implementations:

| Stack | Role | Initial target | Status |
|-------|------|----------------|--------|
| quiche | External client and server | HTTP/3 request/response, version negotiation, close paths | Live packet probe receives Initial packets; full handshake pending |
| ngtcp2/nghttp3 | External client and server | HTTP/3 request/response, SETTINGS, GOAWAY, reset paths | Live packet probe decrypts external Initial CRYPTO through Debian `gtlsclient`; full handshake pending |
| MsQuic | External client and server | Transport handshake, connection close, stateless reset posture | Planned |
| aioquic | External client and server | Python-driven HTTP/3, QPACK, malformed-input cases | Live packet probe decrypts an external Initial, observes CRYPTO, sends protected server Initial CRYPTO, and sends encrypted Initial CONNECTION_CLOSE; full handshake pending |
| Maintained Zig QUIC projects | External client and server | Package/API compatibility and packet traces where available | Discovery needed |

Interop checks should run only when the external tool is installed and an
endpoint or command has been provided. Missing tools are skips, not failures,
unless the caller opts into strict mode.

## Next Raw Packet Target

The next external target is a raw-packet smoke against `aioquic` or
`ngtcp2/nghttp3` that exercises:

- Initial long-header packet protection and header unprotection;
- CRYPTO frame delivery through the per-level reassembly path;
- packet-number reconstruction from truncated packet numbers;
- transition from Initial/Handshake keys to 1-RTT packet protection.

Current in-tree coverage validates constrained short-header raw packets,
long-header Initial and Handshake CRYPTO packets, 0-RTT raw packet protection,
variable-length packet numbers, UDP multiplexer queue ownership, and protected
datagram egress flushing through owned connection queues. It also validates
connection-level scheduling of flow-control frames and PTO PING probes into
protected raw datagrams, ACK feedback into packet spaces, stream write-buffer
egress, native protected Handshake-space CRYPTO scheduling, and localhost UDP
loopback routing into the peer raw queue. External evidence currently stops at
Initial-space decrypt/frame/response behavior; live external Handshake-space
flight, handshake confirmation, and HTTP/3 request/response success are still
pending.

## Harness

`dev/interop_smoke.sh` is the entry point for local interop runs. It supports
three operating modes:

- tool discovery, which reports available quiche, ngtcp2, MsQuic, and aioquic
  commands;
- external-client checks, where those clients connect to a zquic endpoint; and
- external-server checks, where a supplied zquic client command connects to an
  external endpoint.

Useful environment variables:

| Variable | Purpose |
|----------|---------|
| `ZQUIC_INTEROP_TARGET_URL` | URL for external clients to request from a zquic HTTP/3 endpoint. |
| `ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL` | URL for external clients to use in unsupported-version/version-negotiation checks. Defaults to `ZQUIC_INTEROP_TARGET_URL`. |
| `ZQUIC_INTEROP_EXTERNAL_SERVER_URL` | URL for zquic-as-client checks against an external server. |
| `ZQUIC_INTEROP_ZQUIC_CLIENT_CMD` | Command used for zquic-as-client checks. Required until the repo exposes a stable network client CLI. |
| `QUICHE_CLIENT_CMD` | Optional quiche client override. |
| `NGTCP2_H3CLIENT_CMD` | Optional ngtcp2/nghttp3 client override. |
| `AIOQUIC_CLIENT_CMD` | Optional aioquic client override. |
| `MSQUIC_CLIENT_CMD` | Optional MsQuic client override. |
| `QUICHE_VERSION_NEGOTIATION_CMD` | Exact quiche command prefix for unsupported-version checks. |
| `NGTCP2_VERSION_NEGOTIATION_CMD` | Exact ngtcp2 command prefix for unsupported-version checks. |
| `AIOQUIC_VERSION_NEGOTIATION_CMD` | Exact aioquic command prefix for unsupported-version checks. |
| `MSQUIC_VERSION_NEGOTIATION_CMD` | Exact MsQuic command prefix for unsupported-version checks. |
| `STATELESS_RESET_INTEROP_CMD` | Exact external command for stateless reset behavior. |
| `RETRY_INTEROP_CMD` | Exact external command for Retry behavior. |
| `CONNECTION_CLOSE_INTEROP_CMD` | Exact external command for CONNECTION_CLOSE behavior. |
| `DRAINING_INTEROP_CMD` | Exact external command for draining behavior. |
| `HTTP3_SETTINGS_INTEROP_CMD` | Exact external command for HTTP/3 SETTINGS behavior. |
| `HTTP3_REQUEST_INTEROP_CMD` | Exact external command for HTTP/3 request/response lifecycle. |
| `HTTP3_GOAWAY_INTEROP_CMD` | Exact external command for HTTP/3 GOAWAY behavior. |
| `HTTP3_CANCEL_INTEROP_CMD` | Exact external command for HTTP/3 cancellation behavior. |
| `HTTP3_MALFORMED_INTEROP_CMD` | Exact external command for HTTP/3 malformed-frame rejection. |
| `DOQ_LENGTH_INTEROP_CMD` | Exact external command for DoQ DNS message length framing. |
| `DOQ_PIPELINE_INTEROP_CMD` | Exact external command for DoQ pipelined query behavior. |
| `DOQ_RCODE_INTEROP_CMD` | Exact external command for DoQ NXDOMAIN/SERVFAIL behavior. |
| `DOQ_TIMEOUT_INTEROP_CMD` | Exact external command for DoQ timeout behavior. |
| `ZQUIC_INTEROP_REQUIRE_RUN=1` | Fail if every case is skipped. |
| `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1` | Fail unless at least one stateless-reset, Retry, CONNECTION_CLOSE, or draining command runs. |

The generic harness intentionally avoids starting background servers by
default. The dedicated Docker target
`./dev/docker_validate.sh interop-zquic-server` is the exception: it starts
`zquic-interop-probe-server`, runs Debian-packaged/source-built external
clients against it, requires qlog-style packet trace plus encrypted Initial
CONNECTION_CLOSE evidence, requires a decrypted CRYPTO frame, sends protected
server Initial CRYPTO by default, and removes its repo-local scratch log before
exit.

The external clients may still time out or report handshake failure in this
target. Those failures are expected until the production accept loop drives the
full TLS/QUIC handshake and application protocol response path; they are not
counted as passing HTTP/3 or full-handshake evidence.

Version-negotiation command flags differ by implementation, so the harness does
not guess them. Provide the exact command prefix for the installed client; the
harness appends `ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL`.

Stateless reset, Retry, connection close, and draining checks are also exposed
as exact-command hooks because external stacks package these scenarios
differently. Use `./dev/interop_smoke.sh --transport-close` for the focused
transport-close group, and set `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1` when a
release gate must fail unless at least one installed external implementation
actually runs. The deterministic in-tree tests validate zquic's wire helpers
and shutdown behavior; external evidence should be collected by setting one or
more of the command variables above.

HTTP/3 checks follow the same model. In-tree tests cover SETTINGS,
request/response lifecycle, GOAWAY, cancellation frame parsing, malformed frame
rejection, and router error mapping; external evidence should be collected with
the HTTP/3 command variables for an installed stack.

DoQ checks use JSON fixtures under `tests/fixtures/doq/` for length-prefixed
DNS messages, pipelined query buffers, NXDOMAIN/SERVFAIL response mapping, and
timeout policy. External evidence should be collected with the DoQ command
variables for an installed stack.

## Transport Cases

Required transport interop cases for v0.9.x maturity:

| Case | Expected evidence |
|------|-------------------|
| Initial packet protection | In-tree long-header Initial CRYPTO packets decrypt through owned queues; the Docker live interop probe decrypts at least one external client Initial, observes CRYPTO, sends protected server Initial CRYPTO, and sends encrypted Initial CONNECTION_CLOSE. |
| Handshake packet protection | In-tree long-header Handshake CRYPTO packets decrypt with handshake keys; external keys advance through handshake without packet-number rollback. |
| 0-RTT packet handling | In-tree 0-RTT raw packet protection/deprotection works at the packet boundary; full rejection/acceptance policy still depends on application policy and remembered transport parameters. |
| 1-RTT packet handling | In-tree short-header packets decrypt and dispatch STREAM frames through owned queues; ACK frames are generated and processed into packet spaces; stream write buffers can be scheduled into protected STREAM datagrams. External steady-state packets still need ACK/loss evidence after handshake confirmation. |
| Version negotiation | zquic distinguishes malformed packets from unsupported nonzero versions, can serialize version-negotiation responses with swapped client CIDs, and exposes external-client command hooks in `dev/interop_smoke.sh`. |
| Transport parameters | max data, stream limits, idle timeout, active connection ID limit, migration disablement, ACK delay exponent, and preferred address posture encode/decode across stacks. |
| Retry | In-tree Retry parsing validates original destination connection ID and retry source connection ID; Retry integrity tag computation uses the RFC 9001 QUIC v1 AES-GCM key/nonce and is pinned by `tests/fixtures/interop/retry-integrity.json`; external command hook is available. |
| Stateless reset | In-tree stateless reset token matching requires minimum packet length and exact token match; external command hook is available. |
| Connection close and draining | In-tree shutdown queues a parseable CONNECTION_CLOSE frame and enters draining; external command hook is available. |

## HTTP/3 Cases

Required HTTP/3 interop cases:

- SETTINGS exchange and unknown-setting tolerance;
- request/response lifecycle over bidirectional streams;
- GOAWAY ordering and new-stream rejection;
- stream cancellation and reset propagation;
- malformed frame rejection with the correct HTTP/3 error mapping; and
- response status and body handling under concurrent streams.

Current in-tree coverage exercises SETTINGS encode/decode, request/response
lifecycle, GOAWAY and CANCEL_PUSH frame parsing, malformed frame rejection, and
router error-to-500 mapping. Connection-level GOAWAY ordering, transport stream
reset propagation, and external implementation evidence still require a
configured interop command.

## QPACK Cases

Required QPACK interop fixtures:

- static table header hits;
- duplicate pseudo-header rejection;
- malformed header block rejection;
- header list size limit enforcement; and
- dynamic table disabled posture.

Current fixtures live under `tests/fixtures/qpack/` and replay through
`src/http3/qpack.zig`. They cover static-table-equivalent literal headers,
duplicate pseudo-header rejection, malformed/truncated blocks, configured
header count limits, and literal decode with dynamic table capacity set to zero.
They do not claim full RFC 9204 dynamic table interoperability yet.

## DoQ Cases

Required DNS-over-QUIC interop cases:

- RFC 9250 stream lifecycle;
- two-byte DNS message length framing;
- pipelined queries on one connection;
- NXDOMAIN and SERVFAIL response mapping; and
- timeout and cancellation cleanup.

Current fixtures replay length-prefixed stream messages and response codes
deterministically. Transport-level stream cancellation cleanup still needs a
live server/client interop command before it counts as external evidence.

## Packet Trace Fixtures

Trace fixtures should be deterministic and independent of wall-clock timing.
Each fixture should record:

- role, QUIC version, ALPN, cipher suite, and feature flags;
- source and destination connection IDs;
- packet number space and packet number;
- unprotected frame summary;
- protected packet bytes or a reproducible derivation seed; and
- expected accept/reject result with the target error code.

The initial fixture set should cover Initial, Handshake, 0-RTT, and 1-RTT
packet sequences. Secrets, ticket keys, and private keys must not be committed.

## Known Gaps

The table below is the v0.9.16 evidence ledger. Rows marked as fixture or
in-tree coverage are useful regression coverage, but they are not external
interop evidence until the corresponding harness command is run against an
installed implementation.

| Area | Current evidence | Target files | Remaining gap |
|------|------------------|--------------|---------------|
| External client/server smoke | Optional harness discovery and command hooks for quiche, ngtcp2/nghttp3, MsQuic, and aioquic. Per-category require flags can fail a run when external clients, version negotiation, servers, HTTP/3, DoQ, or transport-close checks are skipped. `interop-zquic-server` proves quiche, ngtcp2/gtlsclient, and aioquic can reach a live zquic UDP endpoint, and requires at least one external Initial decrypt, decrypted CRYPTO frame, protected server Initial CRYPTO transmission from the `SuperConnection` outgoing raw queue, and encrypted Initial CONNECTION_CLOSE transmission. | `dev/interop_smoke.sh`, `docker/interop-zquic-server-smoke.sh`, `examples/interop_probe_server.zig`, `src/core/connection.zig`, `docs/features/quic-interop.md`, `docs/interop/methodology.md` | Full client success still requires production accept-loop TLS orchestration, ALPN, HTTP/3 response handling, Handshake-space packet flight, and stricter success gates. |
| Packet trace replay | Deterministic JSON fixtures for Initial, Handshake, 0-RTT, and 1-RTT parser replay. | `tests/fixtures/interop/*.json`, `tests/packet_fuzz_test.zig` | Header and metadata replay only; protected-payload decryption fixtures remain pending. |
| Raw packet socket path | UDP multiplexer ingress queues full datagrams into owned connection raw queues, supports peer address migration updates, flushes connection-owned protected datagrams to the peer socket address, supports nonblocking receive routing, schedules flow-control/PTO/ACK/STREAM frames as protected datagrams, can turn an owned raw client Initial CRYPTO packet into a protected server Initial CRYPTO response through `SuperConnection`, and has native coverage for protected Handshake CRYPTO scheduling. These helpers are advanced connection/interop APIs, not the normal application request/response entry point. `dev/cli_smoke.sh` builds and runs local demo binaries as a non-network release smoke. | `src/net/multiplexer.zig`, `src/core/connection.zig`, `src/core/packet_crypto.zig`, `src/core/recovery.zig`, `src/core/flow_control.zig`, `tests/handshake_integration_test.zig`, `dev/cli_smoke.sh` | Needs a live external stack to observe a protected Handshake-space CRYPTO flight before this counts as external Handshake-space interop evidence. |
| Transport parameters | Encode/decode and validation coverage for limits, idle timeout, migration posture, ACK delay exponent, CID limits, preferred-address rejection, EncryptedExtensions parsing, and connection-level retention after handshake validation. | `src/core/transport_parameters.zig`, `src/crypto/comprehensive_tls.zig`, `tests/handshake_integration_test.zig` | Full live TLS handshake orchestration still needs to feed this policy from network packets end-to-end. |
| Version negotiation | Unsupported-version parsing, version-negotiation packet parse/serialize coverage, external command hooks, and live probe emission of a Version Negotiation packet when an external client sends an unsupported long-header version. | `src/core/packet.zig`, `tests/packet_fuzz_test.zig`, `examples/interop_probe_server.zig`, `dev/interop_smoke.sh` | Needs a strict external version-negotiation command before this becomes a release-blocking gate. |
| Stateless reset, Retry, close, draining | In-tree parsing/matching helpers, RFC 9001 Retry integrity vector, shutdown/CONNECTION_CLOSE/draining assertions, and a focused `--transport-close` external harness mode with `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1`. | `src/core/packet.zig`, `src/crypto/keys.zig`, `tests/fixtures/interop/retry-integrity.json`, `tests/handshake_integration_test.zig`, `dev/interop_smoke.sh` | Needs at least one external implementation run before the task can be marked complete. |
| HTTP/3 | SETTINGS, request/response, GOAWAY/CANCEL_PUSH parsing, malformed frame rejection, and error mapping tests. | `src/http3/frame.zig`, `tests/http3_integration_test.zig`, `dev/interop_smoke.sh` | Connection-level GOAWAY ordering, transport reset propagation, and live external stack evidence are still missing. |
| QPACK | JSON fixtures for static-equivalent literals, duplicate pseudo-headers, malformed blocks, header-list limits, and dynamic-table-disabled posture. | `src/http3/qpack.zig`, `tests/fixtures/qpack/*.json`, `tests/http3_integration_test.zig` | Fixtures intentionally avoid full RFC 9204 dynamic table interop. |
| DoQ | RFC 9250 length-prefix helpers, pipelined buffers, NXDOMAIN/SERVFAIL mapping, timeout policy, and external command hooks. | `src/doq/message.zig`, `src/doq/server.zig`, `tests/fixtures/doq/*.json`, `tests/doq_integration_test.zig` | Transport-level cancellation cleanup and live DoQ client/server evidence are still missing. |

- The current example binaries mostly exercise in-process flows rather than a
  stable networked QUIC CLI. `ZQUIC_INTEROP_ZQUIC_CLIENT_CMD` remains required
  for zquic-as-client checks until that changes.
- `dev/cli_smoke.sh` is local release evidence only; it does not replace
  external interop runs.
- Use `ZQUIC_INTEROP_REQUIRE_CLIENTS=1`,
  `ZQUIC_INTEROP_REQUIRE_VERSION_NEGOTIATION=1`,
  `ZQUIC_INTEROP_REQUIRE_SERVERS=1`, `ZQUIC_INTEROP_REQUIRE_HTTP3=1`,
  `ZQUIC_INTEROP_REQUIRE_DOQ=1`, and
  `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1` to prevent skipped groups from
  passing a required interop job.
- The harness does not yet manage certificates or start a local zquic HTTP/3
  endpoint.
- External version-negotiation checks require implementation-specific client
  command overrides until the installed tools expose a common flag shape.
- Stateless reset, Retry, connection close, and draining checks require
  implementation-specific command overrides before they count as external
  interop evidence.
- HTTP/3 external evidence requires implementation-specific command overrides
  for SETTINGS, request/response, GOAWAY, cancellation, and malformed frame
  checks.
- DoQ external evidence requires implementation-specific command overrides for
  length framing, pipelining, response-code mapping, timeout, and cancellation
  cleanup checks.
- DoQ interop needs either a dedicated external DoQ client command or a small
  fixture runner before it can be part of the smoke harness.
- MsQuic binary names vary by installation, so the harness requires
  `MSQUIC_CLIENT_CMD` unless a local wrapper is installed.
