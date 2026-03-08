#!/usr/bin/env bash
# Create a Docker image archive (docker save format) suitable for RouterOS Container import.
# Usage: bash docker/make-ros-tar.sh <binary> <output.tar>
# Example: bash docker/make-ros-tar.sh dist/gutd-arm64 gutd-arm64-ros.tar
set -euo pipefail

BINARY="${1:?Usage: $0 <binary> <output.tar>}"
OUTPUT="${2:?Usage: $0 <binary> <output.tar>}"
ARCH="${ARCH:-arm64}"   # docker architecture string

TMPDIR=$(mktemp -d)
trap "rm -rf '$TMPDIR'" EXIT

# ── layer.tar: just the binary as /gutd ──────────────────────────
mkdir -p "$TMPDIR/rootfs"
cp "$BINARY" "$TMPDIR/rootfs/gutd"
chmod 0755 "$TMPDIR/rootfs/gutd"
tar cf "$TMPDIR/layer.tar" -C "$TMPDIR/rootfs" gutd

LAYER_HASH=$(sha256sum "$TMPDIR/layer.tar" | cut -c1-64)
mkdir -p "$TMPDIR/image/$LAYER_HASH"
cp "$TMPDIR/layer.tar" "$TMPDIR/image/$LAYER_HASH/layer.tar"
printf '1.0' > "$TMPDIR/image/$LAYER_HASH/VERSION"

printf '{"id":"%s","created":"2026-01-01T00:00:00Z","container_config":{"Cmd":[]}}' \
    "$LAYER_HASH" > "$TMPDIR/image/$LAYER_HASH/json"

# ── image config ─────────────────────────────────────────────────
printf '{"architecture":"%s","os":"linux","config":{"Entrypoint":["/gutd"],"Cmd":[]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
    "$ARCH" "$LAYER_HASH" > "$TMPDIR/config.json"

CONFIG_HASH=$(sha256sum "$TMPDIR/config.json" | cut -c1-64)
cp "$TMPDIR/config.json" "$TMPDIR/image/${CONFIG_HASH}.json"

# ── manifest.json ────────────────────────────────────────────────
printf '[{"Config":"%s.json","RepoTags":["gutd:latest"],"Layers":["%s/layer.tar"]}]' \
    "$CONFIG_HASH" "$LAYER_HASH" > "$TMPDIR/image/manifest.json"

printf '{"gutd":{"latest":"%s"}}' "$LAYER_HASH" > "$TMPDIR/image/repositories"

# ── package — explicit filenames, no ./ prefix (RouterOS requirement) ────────
# RouterOS parser requires paths like "manifest.json", not "./manifest.json"
OUTABS="$(cd "$(dirname "$OUTPUT")" && pwd)/$(basename "$OUTPUT")"
cd "$TMPDIR/image"
tar cf "$OUTABS" \
    manifest.json \
    repositories \
    "${CONFIG_HASH}.json" \
    "${LAYER_HASH}/json" \
    "${LAYER_HASH}/VERSION" \
    "${LAYER_HASH}/layer.tar"
cd "$OLDPWD"

echo "=== $OUTPUT ==="
tar tf "$OUTPUT"
echo ""
ls -lh "$OUTPUT"
