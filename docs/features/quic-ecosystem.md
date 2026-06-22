# QUIC Ecosystem Notes

This page tracks zquic's positioning work against established QUIC
implementations. It is not a compatibility claim.

## Reference Implementations To Watch

| Project | Language | Useful comparison point |
|---------|----------|-------------------------|
| [quiche](https://github.com/cloudflare/quiche) | Rust | Low-level QUIC + HTTP/3 API with application-owned I/O, timers, and connection configuration. Its README calls out application responsibility for sockets, event loop, timers, and flow-control configuration. |
| [ngtcp2](https://github.com/ngtcp2/ngtcp2) | C/C++ examples | RFC 9000-focused transport library with separate TLS backend integration and HTTP/3 via nghttp3. Its README describes libngtcp2 as independent of external libraries while examples require TLS backends and HTTP/3 dependencies. |
| [MsQuic](https://github.com/microsoft/msquic) | C, C++, C#, Rust interop | Production-oriented, cross-platform Microsoft QUIC stack with async I/O, UDP coalescing, RSS, XDP-related optimization, diagnostics, and performance dashboard culture. |
| [aioquic](https://github.com/aiortc/aioquic) | Python | Embeddable Python QUIC/HTTP/3 stack with minimal TLS 1.3, bring-your-own-I/O design, qlog/key logging, migration/NAT rebinding, and regular interop testing. |

## zquic Direction

zquic should compete by being a Zig-native library rather than a thin wrapper:

- keep packet, stream, recovery, flow-control, HTTP/3, DoQ, and crypto surfaces
  testable as library modules
- keep I/O boundaries explicit enough for custom event loops and embedded uses
- maintain deterministic tests for malformed frames, packets, transcripts, and
  crypto inputs
- keep experimental PQC opt-in until transcript binding, vectors, replay tests,
  interop traces, and independent review are complete
- make Docker/Valgrind and `/opt/zig-dev/zig` validation part of release
  discipline, not an afterthought

## Gaps To Keep Closing

- qlog/trace export compatible with common QUIC tooling
- interop-runner style scenarios for handshake, stream transfer, loss,
  connection close, version negotiation, and migration
- richer pacing and congestion tests against NewReno, CUBIC, and BBR behavior
- cleaner public API examples for application-owned I/O and timer integration
- well-scoped PQC traces that can be replayed without network timing
