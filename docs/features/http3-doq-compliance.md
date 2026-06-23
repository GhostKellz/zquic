# HTTP/3 And DoQ Compliance Notes

This page records the release posture for zquic's higher-level protocol layers.
It is an implementation audit aid, not a standards certification claim.

## HTTP/3

Reference: RFC 9114.

| Area | Status | Notes |
|------|--------|-------|
| Request routing | Implemented | Router supports method/path dispatch, middleware, 404, and 405 with `allow`. |
| Request bodies | Implemented | Integration coverage verifies POST body handling. |
| Concurrent streams | Implemented | Integration coverage checks independent stream state. |
| QPACK static headers | Partial | Literal static-equivalent fixtures exist; dynamic table posture remains disabled/conservative. |
| Header validation | Implemented | Malformed header names and oversized header blocks are rejected. |
| SETTINGS | Partial | Frame encode/decode and interop fixture coverage exist; external negotiation tests remain future work. |
| GOAWAY | Partial | Frame parse coverage exists; connection-level ordering/new-stream scenarios remain future work. |
| Request cancellation | Partial | Transport stream cancellation scenarios need broader coverage. |
| Error mapping | Partial | Router errors map to HTTP 500 in tests; QUIC application error mapping needs continued audit. |

## DNS-over-QUIC

Reference: RFC 9250.

| Area | Status | Notes |
|------|--------|-------|
| DNS message parsing | Implemented | Header, question, answer, authority, and additional sections parse with allocator cleanup. |
| Compression pointers | Implemented | Valid compressed names parse; malformed pointers are rejected. |
| Message bounds | Implemented | Oversized messages and excessive record counts are rejected. |
| Concurrent queries | Implemented | Deterministic tests parse independent query messages. |
| Resolver errors | Implemented | NXDOMAIN and SERVFAIL response helpers are tested. |
| Stream lifecycle | Partial | Server handles per-stream query/response flow; length-prefixed fixture replay exists; cancellation scenarios need transport-level tests. |
| Query pipelining | Partial | Length-prefixed pipelined message buffers are tested; full stream scheduling remains future work. |

## Release Rule

Stable docs should say "implemented" only where code and tests exist. Partial
items can ship in `0.9.x`, but they must stay visible until covered by
deterministic tests.
