# DoQ Interop Fixtures

These fixtures cover deterministic DNS-over-QUIC message behavior for v0.9.15.
They use RFC 9250 two-octet stream length prefixes around DNS wire messages.

Fixture result values:

- `accept`: parse the length-prefixed DNS message stream and validate message IDs/names.
- `rcode`: parse one response and validate the DNS response code.
- `timeout`: validate timeout metadata against the server timeout helper.

The fixtures do not claim live network interop by themselves; external DoQ
client/server evidence still needs a configured command in `dev/interop_smoke.sh`.

