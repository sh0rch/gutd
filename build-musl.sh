#!/usr/bin/env bash
# Build fully static musl binary for gutd using Docker
#
# Cross-compilation approach (HOST=glibc, TARGET=musl):
#   - build.rs (libbpf-cargo) runs on HOST glibc -> BPF skeletons OK
#   - Proc-macros compile for HOST (glibc) -> works
#   - Final binary links against musl -> fully static
#   - musl-compiled libelf.a extracted from Alpine
#
# Usage:
#   ./build-musl.sh                 # build release (source mounted via volume)
#   ./build-musl.sh verify          # build + verify static + smoke test
#   ./build-musl.sh --rebuild       # force toolchain image rebuild
#   ./build-musl.sh verify --rebuild
set -euo pipefail

TARGET="${RUST_TARGET:-x86_64-unknown-linux-musl}"
BIN="target/musl/gutd"
PROJECT_ROOT="$(pwd)"
VERIFY=0
FORCE_REBUILD=0

for arg in "$@"; do
    case "$arg" in
        verify)
            VERIFY=1
            ;;
        --rebuild|-r)
            FORCE_REBUILD=1
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: ./build-musl.sh [verify] [--rebuild|-r]"
            exit 2
            ;;
    esac
done

IMAGE_TAG_SAFE="${TARGET//[^a-zA-Z0-9_.-]/-}"
IMAGE="gutd-toolchain:${IMAGE_TAG_SAFE}"

# Docker may need sudo
DOCKER_CMD=(docker)
if ! docker info &>/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
fi

DOCKER_CONFIG_DIR=""
LOG_FILE=""

cleanup() {
    if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
    fi
    if [ -n "$DOCKER_CONFIG_DIR" ] && [ -d "$DOCKER_CONFIG_DIR" ]; then
        rm -rf "$DOCKER_CONFIG_DIR"
    fi
}
trap cleanup EXIT

docker_exec() {
    if [ -n "$DOCKER_CONFIG_DIR" ]; then
        DOCKER_CONFIG="$DOCKER_CONFIG_DIR" "${DOCKER_CMD[@]}" "$@"
    else
        "${DOCKER_CMD[@]}" "$@"
    fi
}

echo "Building static musl binary in Docker (volume-mount, target=$TARGET)..."

if [ "$FORCE_REBUILD" -eq 1 ] || ! docker_exec image inspect "$IMAGE" >/dev/null 2>&1; then
    LOG_FILE="$(mktemp)"
    if ! docker_exec build --build-arg RUST_TARGET="$TARGET" --target toolchain -t "$IMAGE" -f docker/Dockerfile . 2>&1 | tee "$LOG_FILE"; then
        if grep -Eiq 'error getting credentials|docker-credential|credstore|credhelpers|desktop\.exe|exec format error' "$LOG_FILE"; then
            echo ""
            echo "Detected broken Docker credential helper in current Docker config."
            echo "Retrying build with isolated DOCKER_CONFIG (anonymous pulls for public images)..."
            DOCKER_CONFIG_DIR="$(mktemp -d)"
            printf '{}\n' > "$DOCKER_CONFIG_DIR/config.json"
            docker_exec build --build-arg RUST_TARGET="$TARGET" --target toolchain -t "$IMAGE" -f docker/Dockerfile .
        else
            exit 1
        fi
    fi
else
    echo "Reusing existing Docker image: $IMAGE"
fi

# Build from mounted source (no COPY of codebase into image)
mkdir -p target/musl
docker_exec run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$PROJECT_ROOT:/work" \
    -w /work \
    -e RUST_TARGET="$TARGET" \
    -e RUSTUP_HOME=/usr/local/rustup \
    -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    -e CARGO_HOME=/work/target/.cargo-home \
    -e CARGO_TARGET_DIR=/work/target \
    "$IMAGE" \
    bash -c 'set -euo pipefail; mkdir -p "$CARGO_HOME" target/musl; cargo build --release --target "$RUST_TARGET"; cp "target/${RUST_TARGET}/release/gutd" target/musl/gutd; if command -v upx >/dev/null 2>&1; then upx --best --lzma target/musl/gutd || true; fi'
chmod +x "$BIN"
BIN_ABS="$PROJECT_ROOT/$BIN"

echo ""
echo "=== Build result ==="
ls -lh "$BIN"
file "$BIN"

# -- Verify (optional) ------------------------------------------
if [ "$VERIFY" -eq 1 ]; then
    echo ""
    echo "=== Verifying static binary ==="
    if readelf -d "$BIN" 2>/dev/null | grep -q NEEDED; then
        echo "[FAIL] Binary has dynamic dependencies:"
        readelf -d "$BIN" | grep NEEDED
        exit 1
    fi
    echo "[ok] Fully static -- no dynamic dependencies"

    echo ""
    echo "=== Smoke test in Alpine container ==="
    docker_exec run --rm -v "$BIN_ABS:/gutd:ro" alpine:3.21 /gutd version
    docker_exec run --rm -v "$BIN_ABS:/gutd:ro" alpine:3.21 /gutd genkey
    echo "[ok] Smoke test passed"
fi

echo ""
echo "Static binary: $BIN"
