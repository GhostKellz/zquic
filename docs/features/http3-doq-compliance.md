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
| QPACK static headers | Partial | Static table and validation paths exist; dynamic table posture remains conservative. |
| Header validation | Implemented | Malformed header names and oversized header blocks are rejected. |
| SETTINGS | Partial | Covered as frame/data structures; deeper negotiation tests remain future work. |
| GOAWAY | Partial | Should stay tracked as an RFC 9114 gap until connection-level scenarios are complete. |
| Request cancellation | Partial | Transport stream cancellation scenarios need broader coverage. |
| Error mapping | Partial | Existing app errors map through response status; QUIC application error mapping needs continued audit. |

## DNS-over-QUIC

Reference: RFC 9250.

| Area | Status | Notes |
|------|--------|-------|
| DNS message parsing | Implemented | Header, question, answer, authority, and additional sections parse with allocator cleanup. |
| Compression pointers | Implemented | Valid compressed names parse; malformed pointers are rejected. |
| Message bounds | Implemented | Oversized messages and excessive record counts are rejected. |
| Concurrent queries | Implemented | Deterministic tests parse independent query messages. |
| Resolver errors | Implemented | NXDOMAIN and SERVFAIL response helpers are tested. |
| Stream lifecycle | Partial | Server handles per-stream query/response flow; cancellation scenarios need transport-level tests. |
| Query pipelining | Partial | Message-level concurrency is tested; full stream scheduling remains future work. |

## Release Rule

Stable docs should say "implemented" only where code and tests exist. Partial
items can ship in `0.9.x`, but they must stay visible until covered by
deterministic tests.
