#!/usr/bin/env bash
set -euo pipefail

echo "=== zquic docker verification ==="
echo "zig: $(zig version)"
echo

run_step() {
    local label="$1"
    shift
    echo "$label"
    "$@"
    echo
}

run_step "[1/7] Stable build" \
    zig build -Dpost-quantum=false

run_step "[2/7] Stable tests" \
    zig build test --summary all -Dpost-quantum=false

run_step "[3/7] PQ build" \
    zig build -Dpost-quantum=true -Dexperimental-crypto=true

run_step "[4/7] PQ tests" \
    zig build test --summary all -Dpost-quantum=true -Dexperimental-crypto=true

run_step "[5/7] Integration tests" \
    zig build integration-tests -Dpost-quantum=true -Dexperimental-crypto=true

run_step "[6/7] Release validation" \
    bash ./dev/validate.sh

run_step "[7/7] Valgrind memory check" \
    bash docker/valgrind-check.sh

echo "=== verification complete ==="
