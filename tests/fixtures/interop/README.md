# QUIC Interop Packet Fixtures

These fixtures are deterministic packet-trace seeds for the v0.9.15 interop
work. They are intentionally small and do not contain private keys, ticket keys,
or live deployment secrets.

Each fixture records:

- role and protocol metadata;
- QUIC version, ALPN, cipher suite, and feature flags;
- packet number space and expected packet type;
- source and destination connection IDs;
- packet number metadata;
- an unprotected frame summary; and
- packet bytes encoded as hex.

The current replay test validates metadata against zquic's packet header parser.
It does not decrypt payloads yet; protected packet bytes and crypto material
should be added only through reproducible test seeds that are safe to commit.

