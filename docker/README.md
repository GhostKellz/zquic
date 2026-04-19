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
```

Custom Zig path:

```bash
HOST_ZIG_PATH=/path/to/zig docker compose -f docker/compose.yml run --rm zquic-verify bash
```

Valgrind check:

```bash
docker compose -f docker/compose.yml run --rm zquic-verify bash docker/valgrind-check.sh
```

## Verification Steps

1. Stable build
2. Stable tests
3. PQ build
4. PQ tests
5. Integration tests
6. Release validation
7. Valgrind memory check
