# Docker Verification

Clean Linux environment for ZQUIC verification using host Zig and valgrind.
The verification image is pinned to Alpine 3.24.1.
The heavier external-tool image is pinned to Debian trixie slim.

## Requirements

- Host Zig at `/opt/zig-dev` (or set `HOST_ZIG_PATH`)
- Docker with compose
- Linux host

## Usage

Interactive shell:

```bash
docker compose -f docker/compose.yml run --rm zquic-verify bash
```

Full verification suite:

```bash
docker compose -f docker/compose.yml run --rm zquic-verify bash docker/run-verify.sh
# or
./dev/docker_validate.sh release
```

Custom Zig path:

```bash
HOST_ZIG_PATH=/path/to/zig docker compose -f docker/compose.yml run --rm zquic-verify bash
```

Valgrind check:

```bash
docker compose -f docker/compose.yml run --rm zquic-verify bash docker/valgrind-check.sh
# or
./dev/docker_validate.sh valgrind
```

Optional interop smoke from the same clean container:

```bash
./dev/docker_validate.sh interop
```

Debian packaged-tool interop smoke:

```bash
./dev/docker_validate.sh interop-debian
./dev/docker_validate.sh interop-debian --list
```

Audit installed interop packages and command entrypoints:

```bash
docker compose -f docker/compose.yml run --rm zquic-verify bash docker/interop-tools.sh
./dev/docker_validate.sh interop-tools
```

Smoke source-built interop commands in the Debian image:

```bash
./dev/docker_validate.sh interop-source-tools
```

Run external clients against the live zquic UDP interop probe:

```bash
./dev/docker_validate.sh interop-zquic-server
```

The wrapper rebuilds the selected Compose image before each run so Dockerfile
user and home-directory changes cannot be hidden by a stale local image. Zig is
invoked normally and uses its default caches.

Compile/link smoke for the installed QUIC libraries:

```bash
./dev/docker_validate.sh interop-libs
```

The interop variant uses `dev/interop_smoke.sh`; it skips external clients or
servers that are not installed in the image. `dev/docker_validate.sh` forwards
the `ZQUIC_INTEROP_*`, `*_INTEROP_CMD`, and external client command variables
into the container, so exact-command hooks can be supplied from the host:

```bash
ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1 \
STATELESS_RESET_INTEROP_CMD='external-stateless-reset-check --target https://127.0.0.1:4433/' \
./dev/docker_validate.sh interop
```

The image installs Alpine packages for `py3-aioquic`, `ngtcp2`,
`ngtcp2-dev`, `ngtcp2-gnutls`, `nghttp3`, `nghttp3-dev`, `libmsquic`, and
`libmsquic-dev`. The repo provides `docker/bin/aioquic-client`, a small HTTP/3
smoke client backed by Alpine's `py3-aioquic` package, and puts it on the
container PATH. `docker/interop-library-smoke.sh` compiles and links minimal
probes against ngtcp2, ngtcp2-gnutls, nghttp3, and MsQuic using repo-local
scratch that is removed before exit.

Alpine does not currently ship `quiche-client`, `h3client`, `ngtcp2-client`,
or `quicinterop` command entrypoints in this image. Mount or source-build those
tools and pass exact command variables before using those stacks as external
release evidence. With `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1`, the interop
variant fails unless at least one stateless-reset, Retry, CONNECTION_CLOSE, or
draining command actually runs.

The Debian `zquic-interop` image installs distro-packaged `ngtcp2-client`,
`ngtcp2-server`, `python3-aioquic`, `libngtcp2-dev`,
`libngtcp2-crypto-gnutls-dev`, and `libnghttp3-dev`. Debian provides
`gtlsclient` through `ngtcp2-client`; `dev/interop_smoke.sh` detects it and
invokes it as `HOST PORT URI`. The image also source-builds pinned quiche and
MsQuic tools into `/usr/local/bin`, including `quiche-client`, `quiche-server`,
`quicinterop`, `quicinteropserver`, and `quicsample`.
`quicinterop` is audited as an installed MsQuic interop tool; set an explicit
`MSQUIC_CLIENT_CMD` before counting MsQuic target-URL client evidence.
`./dev/docker_validate.sh interop-zquic-server` starts
`zquic-interop-probe-server`, runs the Debian external clients against it, and
requires qlog-style evidence that zquic received real UDP Initial packets,
decrypted at least one external Initial, observed a decrypted CRYPTO frame, sent
a protected server Initial packet, and reached a terminal outcome — either
`handshake_keys_installed` or an encrypted Initial CONNECTION_CLOSE.

The probe keeps per-connection state between datagrams, answers an accepted
ClientHello with a complete ephemeral Ed25519 or ECDSA P-256 TLS 1.3 server
flight, verifies the peer Finished, and then installs directional RFC 9001
application keys.
Its bounded HTTP/3 path exchanges SETTINGS and serves a fixed `GET /` response.
Opt-in gates assert progressively stronger outcomes:
`ZQUIC_INTEROP_REQUIRE_CLIENT_HELLO_ACCEPTED=1`,
`ZQUIC_INTEROP_REQUIRE_HANDSHAKE_KEYS=1`, and
`ZQUIC_INTEROP_REQUIRE_CONNECTION_STATE_REUSED=1`, plus
`ZQUIC_INTEROP_REQUIRE_SERVER_HANDSHAKE_FLIGHT=1`,
`ZQUIC_INTEROP_REQUIRE_HANDSHAKE_CONFIRMED=1`, and
`ZQUIC_INTEROP_REQUIRE_APPLICATION_DECRYPT=1`. Add
`ZQUIC_INTEROP_REQUIRE_HTTP3_RESPONSE=1` to require the HTTP/3 qlog boundary and
an exact body decoded by ngtcp2/gtlsclient. The evidence levels and diagrams are
in `docs/interop/methodology.md`. Use
`ZQUIC_INTEROP_REQUIRE_AIOQUIC_HTTP3_RESPONSE=1` for the independent aioquic
status and exact-body gate, and `ZQUIC_INTEROP_REQUIRE_QUICHE_HTTP3_RESPONSE=1`
for the independent quiche status/header/exact-body gate.

Variant summary:

| Variant | Command | Purpose |
|---------|---------|---------|
| Release | `./dev/docker_validate.sh release` | Build/test/PQ/integration/release validation |
| Valgrind | `./dev/docker_validate.sh valgrind` | Memory-check the verification binary path |
| Interop libraries | `./dev/docker_validate.sh interop-libs` | Compile/link probes for installed QUIC libraries |
| Interop | `./dev/docker_validate.sh interop` | Optional external QUIC/HTTP3/DoQ smoke checks |
| Debian interop | `./dev/docker_validate.sh interop-debian` | Optional external smoke using Debian packaged clients |
| Debian tool audit | `./dev/docker_validate.sh interop-tools` | Audit Debian packaged interop tools |
| Source tool smoke | `./dev/docker_validate.sh interop-source-tools` | Smoke source-built quiche and MsQuic commands |
| ZQUIC server probe | `./dev/docker_validate.sh interop-zquic-server` | Run external clients against the live zquic UDP packet probe |
| Shell | `./dev/docker_validate.sh shell` | Interactive container for debugging |

## Verification Steps

1. Stable build
2. Stable tests
3. PQ build
4. PQ tests
5. Integration tests
6. Release validation
7. Valgrind memory check

## Root-Owned Output Cleanup

Docker runs can leave root-owned `.zig-cache`, `zig-cache`, or `zig-out` files
when the daemon maps container writes as root. Clean them from the host with:

```bash
sudo chown -R "$(id -u):$(id -g)" .zig-cache zig-cache zig-out 2>/dev/null || true
```

Validation uses Zig's normal repo-local `.zig-cache` and `zig-out` paths.
