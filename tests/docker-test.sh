#!/bin/bash
# tests/docker-test.sh — gutd + WireGuard end-to-end test using two Docker containers
#
# Reproduces the RouterOS container environment locally:
#   --cap-add NET_ADMIN,SYS_ADMIN,NET_RAW  (same as RouterOS add-caps)
#   -v /sys/fs/bpf:/sys/fs/bpf
#
# Architecture:
#
#   [wg_client alpine]────WG UDP────▶[gut0: 10.99.0.2] gutd_relay [eth0: 10.88.0.11]
#       (shares gutd_relay netns)          │ gutd encrypted UDP on 10.88.0.0/24
#                                          ▼
#   [wg_server alpine]◀───WG UDP────[gut0: 10.99.0.1] gutd_server [eth0: 10.88.0.10]
#       (shares gutd_server netns)
#
#   WireGuard topology: 10.200.0.1 (server) ↔ 10.200.0.2 (client)
#   WG endpoint: wg_client → 10.99.0.1:51820 (through gut tunnel)
#
# Usage:
#   sudo bash tests/docker-test.sh            # explicit caps (RouterOS simulation)
#   sudo bash tests/docker-test.sh --privileged  # privileged mode (baseline)
#   sudo bash tests/docker-test.sh --rebuild     # force rebuild of image
#
# Requires:
#   docker, wg (wireguard-tools), xxd
#   wireguard kernel module on host (modprobe wireguard)
#   BPF filesystem mounted at /sys/fs/bpf

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${GUTD_IMAGE:-gutd:test}"
NET="gut_test"
PORTS="${GUTD_PORTS:-41000,41001}"
WG_PORT=51820

# ── Terminal colors ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()    { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"; }
step()   { echo -e "\n${CYAN}══ $* ══${NC}"; }
error()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()     { echo -e "${GREEN}  ✓${NC} $*"; }
fail()   { echo -e "${RED}  ✗${NC} $*"; }

# ── Argument parsing ─────────────────────────────────────────────
PRIVILEGED=0
REBUILD=0
CI_MODE=0
for arg in "$@"; do
    case $arg in
        --privileged) PRIVILEGED=1 ;;
        --rebuild)    REBUILD=1 ;;
        --ci)         CI_MODE=1 ;;
    esac
done

# ── Cleanup ───────────────────────────────────────────────────────
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    docker stop wg_client wg_server gutd_relay gutd_server 2>/dev/null || true
    docker rm   wg_client wg_server gutd_relay gutd_server 2>/dev/null || true
    docker network rm "$NET" 2>/dev/null || true
    rm -f /tmp/wg-docker-server.conf /tmp/wg-docker-client.conf
}
trap cleanup EXIT

# Run cleanup at start too (stale containers from previous run)
cleanup 2>/dev/null || true

# ── Check prerequisites ───────────────────────────────────────────
step "Checking prerequisites"
MISSING=0
for cmd in docker wg xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        error "Missing command: $cmd"
        MISSING=1
    fi
done
[[ $MISSING -eq 1 ]] && exit 1

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    warn "/sys/fs/bpf is not mounted. Attempting to mount..."
    mount -t bpf bpf /sys/fs/bpf || { error "Cannot mount /sys/fs/bpf"; exit 1; }
fi

# Load wireguard kernel module for the wg containers
modprobe wireguard 2>/dev/null || warn "Could not load wireguard module (may already be built-in)"

log "Prerequisites OK"

# ── Build image ───────────────────────────────────────────────────
build_image() {
    step "Building gutd x86_64 image"
    log "Stage 1: building binary via Dockerfile.x86_64 ..."
    docker build -t gutd-build-tmp -f "$ROOT/docker/Dockerfile.x86_64" "$ROOT"
    mkdir -p "$ROOT/dist"
    CID=$(docker create gutd-build-tmp)
    docker cp "$CID:/gutd" "$ROOT/dist/gutd-amd64"
    docker rm "$CID"
    docker rmi gutd-build-tmp 2>/dev/null || true
    log "Binary extracted to dist/gutd-amd64"

    log "Stage 2: building runtime image via Dockerfile.run ..."
    docker build \
        --build-arg TARGETARCH=amd64 \
        --platform linux/amd64 \
        -t "$IMAGE" \
        -f "$ROOT/docker/Dockerfile.run" \
        "$ROOT"
    log "Image $IMAGE ready"
}

if [[ $REBUILD -eq 1 ]] || ! docker image inspect "$IMAGE" &>/dev/null; then
    build_image
else
    log "Using existing image $IMAGE  (pass --rebuild to force rebuild)"
fi

# ── Generate keys ─────────────────────────────────────────────────
step "Generating keys"
GUTD_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
WG_SRV_PRIV=$(wg genkey)
WG_SRV_PUB=$(echo "$WG_SRV_PRIV" | wg pubkey)
WG_CLI_PRIV=$(wg genkey)
WG_CLI_PUB=$(echo "$WG_CLI_PRIV" | wg pubkey)
log "gutd shared key : ${GUTD_KEY:0:16}..."
log "WG server pubkey: $WG_SRV_PUB"
log "WG client pubkey: $WG_CLI_PUB"

# ── Docker bridge network ─────────────────────────────────────────
step "Creating Docker network"
docker network create --subnet 10.88.0.0/24 "$NET"
log "Bridge gut_test: 10.88.0.0/24"

# ── Capability flags ──────────────────────────────────────────────
if [[ $PRIVILEGED -eq 1 ]]; then
    CAPS=(--privileged)
    warn "Mode: --privileged  (not a realistic RouterOS simulation)"
else
    CAPS=(--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW)
    log "Mode: explicit caps  NET_ADMIN + SYS_ADMIN + NET_RAW  (RouterOS simulation)"
fi

BPF_ARGS=(-v /sys/fs/bpf:/sys/fs/bpf)

# ── Start gutd_server ─────────────────────────────────────────────
step "Starting gutd_server (10.88.0.10 / gut0=10.99.0.1/30)"
docker run -d --name gutd_server \
    --network "$NET" --ip 10.88.0.10 \
    "${CAPS[@]}" "${BPF_ARGS[@]}" \
    -e GUTD_PEER_IP=10.88.0.11 \
    -e GUTD_BIND_IP=0.0.0.0 \
    -e GUTD_ADDRESS=10.99.0.1/30 \
    -e GUTD_PORTS="$PORTS" \
    -e GUTD_KEY="$GUTD_KEY" \
    -e GUTD_NIC=eth0 \
    "$IMAGE"

# ── Start gutd_relay ──────────────────────────────────────────────
step "Starting gutd_relay (10.88.0.11 / gut0=10.99.0.2/30)"
docker run -d --name gutd_relay \
    --network "$NET" --ip 10.88.0.11 \
    "${CAPS[@]}" "${BPF_ARGS[@]}" \
    -e GUTD_PEER_IP=10.88.0.10 \
    -e GUTD_BIND_IP=0.0.0.0 \
    -e GUTD_ADDRESS=10.99.0.2/30 \
    -e GUTD_PORTS="$PORTS" \
    -e GUTD_KEY="$GUTD_KEY" \
    -e GUTD_NIC=eth0 \
    "$IMAGE"

# ── Wait for gutd to be ready ─────────────────────────────────────
wait_ready() {
    local name=$1
    log "Waiting for $name to be ready..."
    for i in $(seq 1 30); do
        local out
        out=$(docker logs "$name" 2>&1)
        if echo "$out" | grep -qiE "TC eBPF mode activated|ready|gut0 up|Loaded config"; then
            ok "$name is ready"
            return 0
        fi
        if echo "$out" | grep -qiE "^Error:|Fatal|panic"; then
            error "$name failed to start:"
            echo "$out" >&2
            return 1
        fi
        sleep 1
    done
    warn "$name did not signal ready after 30s — showing logs:"
    docker logs "$name" >&2
    # Don't treat as hard failure — it might still be initializing
    return 0
}

step "Waiting for gutd containers"
wait_ready gutd_server
wait_ready gutd_relay

log "=== gutd_server logs ==="
docker logs gutd_server 2>&1 | sed 's/^/  /'
log "=== gutd_relay logs ==="
docker logs gutd_relay 2>&1 | sed 's/^/  /'

# ── Check for errors ──────────────────────────────────────────────
step "Checking startup status"
for name in gutd_server gutd_relay; do
    if docker logs "$name" 2>&1 | grep -qiE "^Error:|Failed to create|failed:"; then
        fail "$name has errors in logs (see above)"
        # Continue to show what error we get
    else
        ok "$name: no startup errors detected"
    fi
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "unknown")
    if [[ "$STATE" == "running" ]]; then
        ok "$name: container state = running"
    else
        fail "$name: container state = $STATE"
    fi
done

# ── WireGuard config files ────────────────────────────────────────
step "Configuring WireGuard"
cat > /tmp/wg-docker-server.conf <<EOF
[Interface]
PrivateKey = $WG_SRV_PRIV
ListenPort = $WG_PORT

[Peer]
PublicKey = $WG_CLI_PUB
AllowedIPs = 10.200.0.2/32
EOF

cat > /tmp/wg-docker-client.conf <<EOF
[Interface]
PrivateKey = $WG_CLI_PRIV
ListenPort = $WG_PORT

[Peer]
PublicKey = $WG_SRV_PUB
Endpoint = 10.99.0.1:$WG_PORT
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 5
EOF

log "WireGuard configs written"

# WireGuard setup script (runs inside alpine sharing gutd netns)
WG_SETUP='
set -e
apk add --no-cache wireguard-tools >/dev/null 2>&1
ip link add wg0 type wireguard
wg setconf wg0 /etc/wg/wg0.conf
ip addr add $WG_ADDR dev wg0
ip link set wg0 up
echo "wg0 up: $WG_ADDR"
'

# ── Start wg_server (inside gutd_server netns) ────────────────────
step "Starting wg_server (10.200.0.1) inside gutd_server network namespace"
docker run -d --name wg_server \
    --network "container:gutd_server" \
    --cap-add NET_ADMIN \
    -v /tmp/wg-docker-server.conf:/etc/wg/wg0.conf:ro \
    --entrypoint sh alpine \
    -c "apk add --no-cache wireguard-tools iperf3 >/dev/null 2>&1 &&
        ip link add wg0 type wireguard &&
        wg setconf wg0 /etc/wg/wg0.conf &&
        ip addr add 10.200.0.1/24 dev wg0 &&
        ip link set wg0 up &&
        echo 'wg_server: wg0 up (10.200.0.1)' &&
        iperf3 -s -1 --daemon 2>/dev/null || iperf3 -s &
        tail -f /dev/null"

# ── Start wg_client (inside gutd_relay netns) ─────────────────────
step "Starting wg_client (10.200.0.2) inside gutd_relay network namespace"
docker run -d --name wg_client \
    --network "container:gutd_relay" \
    --cap-add NET_ADMIN \
    -v /tmp/wg-docker-client.conf:/etc/wg/wg0.conf:ro \
    --entrypoint sh alpine \
    -c "apk add --no-cache wireguard-tools iperf3 >/dev/null 2>&1 &&
        ip link add wg0 type wireguard &&
        wg setconf wg0 /etc/wg/wg0.conf &&
        ip addr add 10.200.0.2/24 dev wg0 &&
        ip link set wg0 up &&
        echo 'wg_client: wg0 up (10.200.0.2)' &&
        tail -f /dev/null"

# ── Wait for WireGuard handshake ──────────────────────────────────
step "Waiting for WireGuard handshake"
WG_READY=0
for i in $(seq 1 20); do
    if docker exec wg_client wg show wg0 2>/dev/null | grep -q "latest handshake"; then
        WG_READY=1
        ok "WireGuard handshake established (attempt $i)"
        break
    fi
    # Check if wg_client is still alive
    if [[ "$(docker inspect --format='{{.State.Status}}' wg_client 2>/dev/null)" != "running" ]]; then
        error "wg_client container died"
        docker logs wg_client >&2
        break
    fi
    sleep 1
done

log "=== wg_server: wg show ==="
docker exec wg_server wg show 2>/dev/null | sed 's/^/  /' || docker logs wg_server 2>&1 | tail -5 | sed 's/^/  /'
log "=== wg_client: wg show ==="
docker exec wg_client wg show 2>/dev/null | sed 's/^/  /' || docker logs wg_client 2>&1 | tail -5 | sed 's/^/  /'

# ── WireGuard ping test ───────────────────────────────────────────
step "Testing WireGuard connectivity (10.200.0.2 → 10.200.0.1)"
WG_PING_OK=0
if docker exec wg_client ping -c 5 -W 2 10.200.0.1 &>/dev/null; then
    ok "WireGuard ping through gutd: PASS"
    WG_PING_OK=1
else
    fail "WireGuard ping failed"
    log "=== wg_client logs ==="
    docker logs wg_client 2>&1 | tail -20 | sed 's/^/  /'
    log "=== gutd_relay logs ==="
    docker logs gutd_relay 2>&1 | tail -10 | sed 's/^/  /'
    log "=== gutd_server logs ==="
    docker logs gutd_server 2>&1 | tail -10 | sed 's/^/  /'
fi

# ── iperf3 bandwidth test ─────────────────────────────────────────
if [[ $WG_PING_OK -eq 1 ]]; then
    step "iperf3 bandwidth test (WireGuard through gutd)"
    # Start iperf3 server in wg_server container
    docker exec -d wg_server iperf3 -s 2>/dev/null || true
    sleep 1
    IPERF_OUT=$(docker exec wg_client iperf3 -c 10.200.0.1 -t 5 -f m 2>&1 || true)
    MBPS=$(echo "$IPERF_OUT" | grep -oP '\d+(?:\.\d+)?\s+Mbits/sec' | tail -1 | grep -oP '[\d.]+' || echo "N/A")
    if [[ "$MBPS" != "N/A" ]]; then
        ok "Throughput: ${MBPS} Mbps"
    else
        warn "iperf3 output:"
        echo "$IPERF_OUT" | sed 's/^/  /'
    fi
fi

# ── Summary ───────────────────────────────────────────────────────
step "Test Summary"
CAPS_MODE="explicit (NET_ADMIN + SYS_ADMIN + NET_RAW)"
[[ $PRIVILEGED -eq 1 ]] && CAPS_MODE="--privileged"

echo ""
echo "  Capabilities mode : $CAPS_MODE"
echo "  gutd image        : $IMAGE"
echo ""
echo "  Container layout:"
echo "    gutd_server  10.88.0.10   gut0=10.99.0.1/30"
echo "    gutd_relay   10.88.0.11   gut0=10.99.0.2/30"
echo "    wg_server    10.200.0.1   (shares gutd_server netns)"
echo "    wg_client    10.200.0.2   (shares gutd_relay netns)"
echo ""

for name in gutd_server gutd_relay; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
    MATCHED=$(docker logs "$name" 2>&1 | grep -nE "^Error:|Failed|failed:" || true)
    ERRORS=$(echo "$MATCHED" | grep -c . || true)
    if [[ "$STATE" == "running" && "$ERRORS" -eq 0 ]]; then
        ok "$name: running, no errors"
    else
        fail "$name: state=$STATE, error lines=$ERRORS"
        echo "$MATCHED" | sed 's/^/    >> /'
    fi
done

[[ $WG_PING_OK -eq 1 ]] && ok "WireGuard through gutd: PASS" || fail "WireGuard through gutd: FAIL"

if [[ $CI_MODE -eq 1 ]]; then
    log "CI mode: tearing down..."
    if [[ $WG_PING_OK -eq 1 ]]; then
        exit 0
    else
        exit 1
    fi
fi

echo ""
log "Containers are still running. Attach to inspect:"
log "  docker logs gutd_server"
log "  docker logs gutd_relay"
log "  docker exec wg_client wg show"
log "  docker run --rm --network container:gutd_relay alpine sh"
log ""
log "Press Ctrl-C to tear down, or run: docker stop gutd_server gutd_relay wg_server wg_client"
echo ""

# ── Keep containers alive for manual inspection ───────────────────
# Wait for user to Ctrl-C (cleanup runs via trap)
wait
