# Docker Verification

Clean Linux environment for ZQUIC verification using host Zig and valgrind.

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

The interop variant uses `dev/interop_smoke.sh`; it skips external clients or
servers that are not installed in the image. `dev/docker_validate.sh` forwards
the `ZQUIC_INTEROP_*`, `*_INTEROP_CMD`, and external client command variables
into the container, so exact-command hooks can be supplied from the host:

```bash
ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1 \
STATELESS_RESET_INTEROP_CMD='external-stateless-reset-check --target https://127.0.0.1:4433/' \
./dev/docker_validate.sh interop
```

Install quiche, ngtcp2, MsQuic, or aioquic tools into the image before using
this as release evidence. With `ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1`, the
interop variant fails unless at least one stateless-reset, Retry,
CONNECTION_CLOSE, or draining command actually runs.

Variant summary:

| Variant | Command | Purpose |
|---------|---------|---------|
| Release | `./dev/docker_validate.sh release` | Build/test/PQ/integration/release validation |
| Valgrind | `./dev/docker_validate.sh valgrind` | Memory-check the verification binary path |
| Interop | `./dev/docker_validate.sh interop` | Optional external QUIC/HTTP3/DoQ smoke checks |
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

The project validation scripts also support using `/tmp` cache directories to
avoid touching the working tree:

```bash
env ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache \
    ZIG_LOCAL_CACHE_DIR=/tmp/zquic-zig-cache \
    /opt/zig-dev/zig build test --summary all
```
