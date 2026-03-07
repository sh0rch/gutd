#!/usr/bin/env bash
# docker/build-multiarch.sh — Build a multi-arch gutd runtime image.
#
# What it does:
#   1. Builds static gutd binaries for each requested platform using `cross`
#      (x86_64 is built via the project's own Dockerfile build stage).
#   2. Places them in dist/ with TARGETARCH-based names expected by Dockerfile.run.
#   3. Calls `docker buildx build --platform ... -f docker/Dockerfile.run` to
#      assemble and optionally push a multi-arch manifest.
#
# Usage:
#   bash docker/build-multiarch.sh [OPTIONS]
#
# Options:
#   --tag  <image:tag>      Image tag to build  [default: gutd:latest]
#   --push                  Push to registry (requires `docker login`)
#   --load                  Load single-arch image into local Docker daemon
#                           (cannot be combined with multi-arch --push)
#   --platforms <list>      Comma-separated platform list
#                           [default: linux/amd64,linux/arm64]
#                           Supported: linux/amd64  linux/arm64  linux/arm/v7
#                                      linux/mips   linux/mipsle
#   --no-build              Skip cross-compilation; use existing dist/ binaries
#   -h, --help              Show this help
#
# Examples:
#   # Build amd64 + arm64 (MikroTik AX3), push to Docker Hub
#   bash docker/build-multiarch.sh --tag myuser/gutd:v2.0.0 --push
#
#   # Build all 5 platforms (slow, requires cross + QEMU)
#   bash docker/build-multiarch.sh \
#     --platforms linux/amd64,linux/arm64,linux/arm/v7,linux/mips,linux/mipsle \
#     --tag myuser/gutd:latest --push
#
#   # Local test on current machine only (no push)
#   bash docker/build-multiarch.sh --platforms linux/amd64 --load --tag gutd:test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST="${REPO_ROOT}/dist"

# ── defaults ──────────────────────────────────────────────────────────────────
TAG="gutd:latest"
PLATFORMS="linux/amd64,linux/arm64"
PUSH=false
LOAD=false
SKIP_BUILD=false

# ── arg parse ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)       TAG="$2";       shift 2 ;;
        --push)      PUSH=true;      shift ;;
        --load)      LOAD=true;      shift ;;
        --platforms) PLATFORMS="$2"; shift 2 ;;
        --no-build)  SKIP_BUILD=true; shift ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if $PUSH && $LOAD; then
    echo "Error: --push and --load are mutually exclusive" >&2
    exit 1
fi

# ── platform → Rust target mapping ───────────────────────────────────────────
declare -A RUST_TARGET=(
    [linux/amd64]="x86_64-unknown-linux-musl"
    [linux/arm64]="aarch64-unknown-linux-musl"
    [linux/arm/v7]="armv7-unknown-linux-musleabihf"
    [linux/mips]="mips-unknown-linux-musl"
    [linux/mipsle]="mipsel-unknown-linux-musl"
)

# docker TARGETARCH values (what Dockerfile.run uses in COPY dist/gutd-${TARGETARCH})
declare -A DOCKER_ARCH=(
    [linux/amd64]="amd64"
    [linux/arm64]="arm64"
    [linux/arm/v7]="arm"
    [linux/mips]="mips"
    [linux/mipsle]="mipsle"
)

# ── collect requested platforms ───────────────────────────────────────────────
IFS=',' read -ra PLATFORM_LIST <<< "$PLATFORMS"

echo "=== gutd multi-arch builder ==="
echo "Tag:       ${TAG}"
echo "Platforms: ${PLATFORMS}"
echo ""

mkdir -p "${DIST}"

# ── step 1: build binaries ────────────────────────────────────────────────────
if ! $SKIP_BUILD; then
    command -v cross >/dev/null 2>&1 || {
        echo "Error: 'cross' is not installed." >&2
        echo "  cargo install cross --git https://github.com/cross-rs/cross" >&2
        exit 1
    }

    for platform in "${PLATFORM_LIST[@]}"; do
        rust_target="${RUST_TARGET[$platform]:-}"
        docker_arch="${DOCKER_ARCH[$platform]:-}"

        if [[ -z "$rust_target" || -z "$docker_arch" ]]; then
            echo "Error: unsupported platform '$platform'" >&2
            echo "  Supported: ${!RUST_TARGET[*]}" >&2
            exit 1
        fi

        dest="${DIST}/gutd-${docker_arch}"
        echo "── Building ${platform} (${rust_target}) ──"

        if [[ "$rust_target" == "x86_64-unknown-linux-musl" ]]; then
            # x86_64: build inside the project's own Docker build stage
            docker build \
                --platform linux/amd64 \
                -t gutd-builder-amd64 \
                -f "${SCRIPT_DIR}/Dockerfile.x86_64" \
                "${REPO_ROOT}"
            CID=$(docker create gutd-builder-amd64)
            docker cp "${CID}:/out/gutd" "${dest}"
            docker rm "${CID}" >/dev/null
        else
            (cd "${REPO_ROOT}" && cross build --release --target "${rust_target}")
            cp "${REPO_ROOT}/target/${rust_target}/release/gutd" "${dest}"
        fi

        # Strip debug symbols if strip is available for the target
        if command -v strip >/dev/null 2>&1 && [[ "$rust_target" == "x86_64-unknown-linux-musl" ]]; then
            strip "${dest}" 2>/dev/null || true
        fi

        echo "  → ${dest} ($(du -sh "${dest}" | cut -f1))"
    done
else
    echo "(Skipping build — using existing dist/ binaries)"
    for platform in "${PLATFORM_LIST[@]}"; do
        docker_arch="${DOCKER_ARCH[$platform]:-}"
        dest="${DIST}/gutd-${docker_arch}"
        if [[ ! -f "$dest" ]]; then
            echo "Error: ${dest} not found. Run without --no-build first." >&2
            exit 1
        fi
        echo "  Using ${dest} ($(du -sh "${dest}" | cut -f1))"
    done
fi

echo ""

# ── step 2: ensure buildx builder with multi-arch support ─────────────────────
BUILDER="gutd-multiarch"
if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
    echo "── Creating buildx builder '${BUILDER}' ──"
    docker buildx create --name "${BUILDER}" --driver docker-container --use
else
    docker buildx use "${BUILDER}"
fi

# ── step 3: docker buildx build ───────────────────────────────────────────────
echo "── Building multi-arch image: ${TAG} ──"
BUILDX_ARGS=(
    buildx build
    --platform "${PLATFORMS}"
    --tag "${TAG}"
    --file "${SCRIPT_DIR}/Dockerfile.run"
    "${REPO_ROOT}"
)
if $PUSH; then
    BUILDX_ARGS+=(--push)
    echo "    (will push to registry)"
elif $LOAD; then
    BUILDX_ARGS+=(--load)
    echo "    (will load into local daemon)"
else
    echo "    (dry run — add --push or --load to deploy)"
fi

docker "${BUILDX_ARGS[@]}"

echo ""
echo "Done.  Image: ${TAG}"
if $PUSH; then
    echo "Verify: docker manifest inspect ${TAG}"
    echo ""
    echo "Pull on AX3 (arm64):"
    echo "  docker pull --platform linux/arm64 ${TAG}"
    echo "Pull on x86_64:"
    echo "  docker pull --platform linux/amd64 ${TAG}"
fi
