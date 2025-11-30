# zcrypto Integration Guide

ZQUIC leans on [`zcrypto`](https://github.com/ghostkellz/zcrypto) for TLS 1.3, hybrid ML-KEM-768 + X25519 key exchange, SLH-DSA signatures, and VPN primitives. This document captures the most common toggles when embedding ZQUIC into your own application.

## Build Flags
`build.zig` forwards feature flags straight into `zcrypto`:
- `-Dpost-quantum=true` (default) enables ML-KEM-768 key exchange + SLH-DSA signatures.
- `-Dvpn=true` pulls in the VPN helpers and ghostmesh packet router.

Example:
```bash
zig build -Dpost-quantum=true -Dvpn=true -Dmonitoring=true
```

## TLS Profiles
Use the `zquic.Crypto` helpers to swap TLS behavior:
```zig
const pq_suite = zquic.PQCipherSuite{
    .kem = .ml_kem_768,
    .sig = .slh_dsa_sha2_128f,
};
try zquic.Crypto.configureHybridTls(server_conn, pq_suite);
```
Fall back to classical curves by toggling `enable_post_quantum` inside your HTTP/3 or DoQ config when you need compatibility with legacy clients.

## VPN Helpers
The VPN module currently uses zcrypto to derive shared keys and authenticate peers. Even though the QUIC VPN is experimental, the primitives are real; swap in your own key derivation like so:
```zig
var key_material: [32]u8 = undefined;
try zcrypto.kdf.hkdfSha256(&key_material, shared_secret, salt, info);
```

## Roadmap
- Document SLH-DSA key rotation flows.
- Publish PQ-enabled client interoperability notes.
- Capture best practices for GPU-backed zcrypto builds (CUDA/NVIDIA runtime).

If you discover tuning combinations that improve handshake latency or VPN throughput, open an issue so we can fold it back into this doc.
