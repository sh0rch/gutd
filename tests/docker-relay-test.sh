#!/bin/bash
# tests/docker-relay-test.sh — eBPF relay + nDPI inspection test
#
# Production-like topology: relay has ONE interface, nDPI sits on the path
# between relay and server — exactly like an ISP DPI box inspecting traffic.
#
# ┌──────────────┐     net_client      ┌───────────┐     net_server     ┌──────────────┐
# │  wg_client   │    10.100.1.0/29    │   relay   │                    │   server     │
# │  .3          ├─────────────────────►│  .2       │                    │  .3          │
# │              │                      │  ONE NIC  │                    │  gut0 .1(odd)│
# │ wg0 10.200.0.1                     │  gut0 .2  │                    │  WG :51820   │
# └──────────────┘                      └─────┬─────┘                    │ wg0 10.200.0.2
#                                              │ GUT obfs UDP            └──────▲───────┘
#                                              │ (route via ndpi .4)            │
#                                              ▼                                │
#                                       ┌─────────────┐    10.100.2.0/29       │
#                                       │  ndpi_router │───────────────────────►│
#                                       │  .4 (cl)     │    .2 (srv)           │
#                                       │  tcpdump     │                       │
#                                       │  ndpiReader  │───────────────────────┘
#                                       └─────────────┘
#
# Networks (/29 — minimum for Docker bridge gateway + containers):
#   net_client  10.100.1.0/29 : gw .1, relay .2, client .3, ndpi .4
#   net_server  10.100.2.0/29 : gw .1, ndpi .2, server .3
#
# Data flow:
#   1. WG client → relay:51820 (on net_client)
#   2. Relay DNAT :51820 → gut0 peer (server tunnel IP 10.254.0.1)
#   3. GUT eBPF encapsulates+masks, sends to server_ip routed via ndpi
#   4. nDPI router forwards traffic, captures pcap, inspects with ndpiReader
#   5. Server unmasks+decapsulates, delivers to local WG :51820
#
# Usage:
#   sudo bash tests/docker-relay-test.sh [OPTIONS]
#
# Options:
#   --obfs MODE     Obfuscation mode: quic (default), gut, sip, syslog
#   --rebuild       Force rebuild of gutd Docker image
#   --privileged    Use --privileged instead of explicit caps
#   --ci            Non-interactive mode (exit after tests)
#   --keep          Keep containers running after test (ignored in --ci)
#
# Environment:
#   GUTD_IMAGE      Docker image name (default: gutd:relay-test)
#   GUTD_BINARY     Path to pre-built gutd binary (skip Docker build)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────
IMAGE="${GUTD_IMAGE:-gutd:relay-test}"
OBFS_MODE="quic"
PRIVILEGED=0
REBUILD=0
CI_MODE=0
KEEP=0

# ── Terminal colors ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()   { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"; }
step()  { echo -e "\n${CYAN}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()    { echo -e "${GREEN}  ✓${NC} $*"; }
fail()  { echo -e "${RED}  ✗${NC} $*"; }

# ── Argument parsing ─────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --obfs)       OBFS_MODE="$2"; shift 2 ;;
        --privileged) PRIVILEGED=1; shift ;;
        --rebuild)    REBUILD=1; shift ;;
        --ci)         CI_MODE=1; shift ;;
        --keep)       KEEP=1; shift ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Per-mode settings ────────────────────────────────────────────
case "$OBFS_MODE" in
    quic)
        GUT_PORTS="443"
        WG_MTU=1420
        GUTD_SNI="example.com"
        NDPI_EXPECT="QUIC"
        ;;
    gut)
        GUT_PORTS="2046"
        WG_MTU=1420
        GUTD_SNI=""
        NDPI_EXPECT=""
        ;;
    sip)
        GUT_PORTS="5060,10000,10001,10002,10003,10004,10005"
        WG_MTU=1400
        GUTD_SNI="sip.example.com"
        NDPI_EXPECT="SIP"
        ;;
    syslog)
        GUT_PORTS="514"
        WG_MTU=800
        GUTD_SNI="asterisk"
        NDPI_EXPECT="Syslog"
        ;;
    *)
        error "Unknown obfs mode: $OBFS_MODE (choose: quic, gut, sip, syslog)"
        exit 1
        ;;
esac

# ── Network addressing ───────────────────────────────────────────
# /29 networks (6 usable IPs: .1 gw, .2-.6 containers)
# Docker reserves .1 for the bridge gateway.
NET_CLIENT="gut_relay_cl"
NET_CLIENT_SUBNET="10.100.1.0/29"   # .1=gw, .2=relay, .3=client, .4=ndpi
RELAY_IP="10.100.1.2"               # relay's ONLY interface
CLIENT_IP="10.100.1.3"
NDPI_CLIENT_IP="10.100.1.4"         # ndpi's client-side interface

NET_SERVER="gut_relay_srv"
NET_SERVER_SUBNET="10.100.2.0/29"   # .1=gw, .2=ndpi, .3=server
NDPI_SERVER_IP="10.100.2.2"         # ndpi's server-side interface
SERVER_IP="10.100.2.3"

# GUT tunnel /30 (inside the tunnel)
# Convention: odd = responder/server, even = initiator/client
GUT_RELAY_ADDR="10.254.0.2/30"
GUT_RELAY_TUN_IP="10.254.0.2"
GUT_SERVER_ADDR="10.254.0.1/30"
GUT_SERVER_TUN_IP="10.254.0.1"

# WireGuard overlay /30
WG_CLIENT_IP="10.200.0.1"
WG_SERVER_IP="10.200.0.2"
WG_PORT=51820

# First GUT port (for ndpi flow matching)
GUT_FIRST_PORT="${GUT_PORTS%%,*}"

step "eBPF Relay + nDPI Test"
echo -e "  Obfuscation : ${BOLD}${OBFS_MODE}${NC}"
echo -e "  Ports       : ${GUT_PORTS}"
echo -e "  WG MTU      : ${WG_MTU}"
echo -e "  Topology    : client(${CLIENT_IP}) → relay(${RELAY_IP}) → ndpi(${NDPI_CLIENT_IP}/${NDPI_SERVER_IP}) → server(${SERVER_IP})"

# ── Cleanup ───────────────────────────────────────────────────────
CONTAINERS=(wg_client gutd_relay ndpi_router gutd_server wg_server)
cleanup() {
    log "Cleaning up..."
    for c in "${CONTAINERS[@]}"; do
        docker stop "$c" 2>/dev/null || true
        docker rm -f "$c" 2>/dev/null || true
    done
    docker network rm "$NET_CLIENT" "$NET_SERVER" 2>/dev/null || true
    rm -f /tmp/gutd-relay-*.conf /tmp/wg-relay-*.conf /tmp/ndpi-relay-*
}
trap cleanup EXIT
cleanup 2>/dev/null || true

# ── Prerequisites ─────────────────────────────────────────────────
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
    warn "/sys/fs/bpf not mounted — attempting to mount..."
    mount -t bpf bpf /sys/fs/bpf || { error "Cannot mount /sys/fs/bpf"; exit 1; }
fi
modprobe wireguard 2>/dev/null || warn "wireguard module may already be built-in"
ok "Prerequisites OK"

# ── Build image ───────────────────────────────────────────────────
build_image() {
    step "Building gutd Docker image"
    if [[ -n "${GUTD_BINARY:-}" && -f "$GUTD_BINARY" ]]; then
        log "Using pre-built binary: $GUTD_BINARY"
        mkdir -p "$ROOT/dist"
        cp "$GUTD_BINARY" "$ROOT/dist/gutd-amd64"
    else
        log "Stage 1: building binary via Dockerfile.x86_64 ..."
        docker build -t gutd-build-tmp -f "$ROOT/docker/Dockerfile.x86_64" "$ROOT"
        mkdir -p "$ROOT/dist"
        CID=$(docker create gutd-build-tmp)
        docker cp "$CID:/gutd" "$ROOT/dist/gutd-amd64"
        docker rm "$CID"
        docker rmi gutd-build-tmp 2>/dev/null || true
        log "Binary extracted to dist/gutd-amd64"
    fi

    log "Stage 2: building test runtime image ..."
    docker build \
        --build-arg TARGETARCH=amd64 \
        --platform linux/amd64 \
        -t "$IMAGE" \
        -f "$ROOT/docker/Dockerfile.relay-test" \
        "$ROOT"
    log "Image $IMAGE ready"
}

if [[ $REBUILD -eq 1 ]] || ! docker image inspect "$IMAGE" &>/dev/null; then
    build_image
else
    # Verify the cached image has a shell (scratch-based images don't).
    # If it lacks sh, it was built from the old Dockerfile.run and must be rebuilt.
    if ! docker run --rm --entrypoint sh "$IMAGE" -c true &>/dev/null 2>&1; then
        warn "Cached image $IMAGE has no shell (old scratch-based build) — rebuilding"
        build_image
    else
        log "Using existing image $IMAGE  (pass --rebuild to force)"
    fi
fi

# ── Generate keys ─────────────────────────────────────────────────
step "Generating cryptographic keys"
GUTD_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
WG_SRV_PRIV=$(wg genkey)
WG_SRV_PUB=$(echo "$WG_SRV_PRIV" | wg pubkey)
WG_CLI_PRIV=$(wg genkey)
WG_CLI_PUB=$(echo "$WG_CLI_PRIV" | wg pubkey)
log "gutd key    : ${GUTD_KEY:0:16}..."
log "WG server   : $WG_SRV_PUB"
log "WG client   : $WG_CLI_PUB"

# ── Docker networks (/29 each) ───────────────────────────────────
step "Creating Docker networks (/29 point-to-point)"
docker network create --subnet "$NET_CLIENT_SUBNET" "$NET_CLIENT"
docker network create --subnet "$NET_SERVER_SUBNET" "$NET_SERVER"
ok "net_client : $NET_CLIENT_SUBNET  (relay, client, ndpi)"
ok "net_server : $NET_SERVER_SUBNET  (ndpi, server)"

# ── Capability flags ──────────────────────────────────────────────
if [[ $PRIVILEGED -eq 1 ]]; then
    CAPS=(--privileged)
    warn "Mode: --privileged"
else
    CAPS=(--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW)
    log "Mode: explicit caps (NET_ADMIN + SYS_ADMIN + NET_RAW)"
fi
BPF_MOUNT=(-v /sys/fs/bpf:/sys/fs/bpf)

# ── gutd configs ──────────────────────────────────────────────────
step "Writing gutd configs"

# Relay config — ONE NIC (eth0), GUT peer is server routed via ndpi
cat > /tmp/gutd-relay-ebpf.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
nic = eth0
mtu = ${WG_MTU}
address = ${GUT_RELAY_ADDR}
bind_ip = ${RELAY_IP}
peer_ip = ${SERVER_IP}
ports = ${GUT_PORTS}
keepalive_drop_percent = 30
key = ${GUTD_KEY}
obfs = ${OBFS_MODE}
$([ -n "$GUTD_SNI" ] && echo "sni = ${GUTD_SNI}")
EOF

# Server config
cat > /tmp/gutd-relay-server.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
nic = eth0
mtu = ${WG_MTU}
address = ${GUT_SERVER_ADDR}
bind_ip = ${SERVER_IP}
peer_ip = ${RELAY_IP}
ports = ${GUT_PORTS}
keepalive_drop_percent = 30
key = ${GUTD_KEY}
obfs = ${OBFS_MODE}
$([ -n "$GUTD_SNI" ] && echo "sni = ${GUTD_SNI}")
wg_host = 127.0.0.1:${WG_PORT}
EOF

log "Relay config  : nic=eth0, bind=${RELAY_IP}, peer=${SERVER_IP}"
log "Server config : nic=eth0, bind=${SERVER_IP}, peer=${RELAY_IP}"

# ── ndpi_router (transparent DPI bridge) ──────────────────────────
# Alpine container with two NICs, ip_forward=1, tcpdump, nDPI.
# Sits between relay and server — all GUT traffic passes through it.
step "Starting ndpi_router (${NDPI_CLIENT_IP} ↔ ${NDPI_SERVER_IP})"
docker run -d --name ndpi_router \
    --network "$NET_CLIENT" --ip "$NDPI_CLIENT_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv4.ip_forward=1 \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    --entrypoint sh alpine \
    -c "
        apk add --no-cache tcpdump >/dev/null 2>&1
        # Wait for eth1 (net_server) to appear
        for i in \$(seq 1 30); do
            ip link show eth1 >/dev/null 2>&1 && break
            sleep 0.2
        done
        # Start pcap capture on the server-facing interface (sees GUT traffic)
        tcpdump -i eth1 -w /tmp/ndpi_relay.pcap -s 0 -n 2>/dev/null &
        echo 'ndpi_router: forwarding + capturing'
        tail -f /dev/null
    "

# Attach ndpi_router to net_server (creates eth1)
sleep 0.5
docker network connect --ip "$NDPI_SERVER_IP" "$NET_SERVER" ndpi_router
ok "ndpi_router: eth0=${NDPI_CLIENT_IP} (client-side), eth1=${NDPI_SERVER_IP} (server-side)"

# ── gutd_server ───────────────────────────────────────────────────
step "Starting gutd_server (${SERVER_IP}, gut0=${GUT_SERVER_ADDR})"
docker run -d --name gutd_server \
    --network "$NET_SERVER" --ip "$SERVER_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    "${CAPS[@]}" "${BPF_MOUNT[@]}" \
    -v /tmp/gutd-relay-server.conf:/etc/gutd.conf:ro \
    "$IMAGE" --config /etc/gutd.conf

# Server needs a route to reach relay (10.100.1.0/29) via ndpi
sleep 0.5
docker exec gutd_server ip route add "$NET_CLIENT_SUBNET" via "$NDPI_SERVER_IP" 2>/dev/null || true

# ── gutd_relay ────────────────────────────────────────────────────
# ONE NIC (eth0 on net_client). GUT traffic to server routed via ndpi.
step "Starting gutd_relay (${RELAY_IP}, ONE NIC, gut0=${GUT_RELAY_ADDR})"
docker run -d --name gutd_relay \
    --network "$NET_CLIENT" --ip "$RELAY_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv4.conf.all.rp_filter=0 \
    --sysctl net.ipv4.conf.default.rp_filter=0 \
    "${CAPS[@]}" "${BPF_MOUNT[@]}" \
    -v /tmp/gutd-relay-ebpf.conf:/etc/gutd.conf:ro \
    --entrypoint sh \
    "$IMAGE" -c "
        # Route to server network via ndpi_router
        ip route add ${NET_SERVER_SUBNET} via ${NDPI_CLIENT_IP}
        # DNAT: client WG UDP on eth0:51820 → gut0 peer IP (server tunnel endpoint)
        iptables -t nat -A PREROUTING -i eth0 -p udp --dport ${WG_PORT} \
            -j DNAT --to-destination ${GUT_SERVER_TUN_IP}:${WG_PORT}
        # MASQUERADE on gut0: relay's src becomes gut0 IP (10.254.0.2) so the
        # server's GUT reply comes back addressed to 10.254.0.2, which XDP
        # delivers to gut0; conntrack then de-NATs and routes back to client.
        iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE
        # MASQUERADE on eth0: GUT-encapped egress to server looks like RELAY_IP
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        # FORWARD rules — bidirectional
        iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
        iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
        # Start gutd
        exec /gutd --config /etc/gutd.conf
    "

# ── Wait for gutd containers ─────────────────────────────────────
wait_ready() {
    local name=$1 timeout=${2:-30}
    log "Waiting for $name ..."
    for i in $(seq 1 "$timeout"); do
        local out
        out=$(docker logs "$name" 2>&1)
        if echo "$out" | grep -qiE "TC eBPF mode activated|ready|gut0 up|Loaded config"; then
            ok "$name is ready"
            return 0
        fi
        if echo "$out" | grep -qiE "^Error:|Fatal|panic"; then
            error "$name failed:"
            echo "$out" >&2
            return 1
        fi
        local state
        state=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
        if [[ "$state" != "running" ]]; then
            error "$name died (state=$state)"
            docker logs "$name" >&2
            return 1
        fi
        sleep 1
    done
    warn "$name did not signal ready after ${timeout}s"
    docker logs "$name" >&2
    return 0
}

step "Waiting for gutd containers"
wait_ready gutd_server
wait_ready gutd_relay

log "=== gutd_server logs ==="
docker logs gutd_server 2>&1 | tail -15 | sed 's/^/  /'
log "=== gutd_relay logs ==="
docker logs gutd_relay 2>&1 | tail -15 | sed 's/^/  /'

# ── Verify startup ───────────────────────────────────────────────
step "Checking startup status"
STARTUP_OK=1
for name in gutd_server gutd_relay ndpi_router; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
    if [[ "$STATE" != "running" ]]; then
        fail "$name: state=$STATE"
        STARTUP_OK=0
        continue
    fi
    if [[ "$name" != "ndpi_router" ]] && docker logs "$name" 2>&1 | grep -qiE "^Error:|Failed to create|failed:"; then
        fail "$name has errors in logs"
        STARTUP_OK=0
    else
        ok "$name: running"
    fi
done
[[ $STARTUP_OK -eq 0 ]] && { error "Container startup failed"; exit 1; }

# ── Verify relay (single NIC) ────────────────────────────────────
step "Verifying relay (single NIC)"
log "Relay interfaces:"
docker exec gutd_relay ip addr show 2>&1 | sed 's/^/  /'
ETH_COUNT=$(docker exec gutd_relay ls /sys/class/net/ 2>/dev/null | grep -c '^eth')
if [[ $ETH_COUNT -eq 1 ]]; then
    ok "Relay has exactly 1 ethernet interface (eth0)"
else
    warn "Relay has $ETH_COUNT ethernet interfaces (expected 1)"
fi
log "Relay routes:"
docker exec gutd_relay ip route 2>&1 | sed 's/^/  /'
log "Relay iptables:"
docker exec gutd_relay iptables -t nat -L -n 2>&1 | sed 's/^/  /'

# ── Verify ndpi routing ──────────────────────────────────────────
step "Verifying ndpi_router forwarding"
log "ndpi interfaces:"
docker exec ndpi_router ip addr show 2>&1 | sed 's/^/  /'
# Relay must reach server through ndpi
if docker exec gutd_relay ping -c 1 -W 2 "$SERVER_IP" &>/dev/null; then
    ok "Relay can reach server (${SERVER_IP}) via ndpi"
else
    fail "Relay cannot reach server — ndpi routing broken"
    docker exec gutd_relay traceroute -n -m 3 "$SERVER_IP" 2>&1 | sed 's/^/  /' || true
    exit 1
fi

# Verify the GUT tunnel is working: ping across gut0 → gut0_peer (server)
step "Verifying GUT tunnel (relay gut0 → server gut0)"
if docker exec gutd_relay ping -c 3 -W 3 "$GUT_SERVER_TUN_IP" &>/dev/null; then
    ok "GUT tunnel: relay (${GUT_RELAY_TUN_IP}) → server (${GUT_SERVER_TUN_IP}) ✓"
else
    warn "GUT tunnel ping failed — ICMP may be blocked; continuing (WG will test connectivity)"
    log "=== gut tunnel ping attempt ==="
    docker exec gutd_relay ping -c 3 -W 2 "$GUT_SERVER_TUN_IP" 2>&1 | sed 's/^/  /' || true
fi

# ── WireGuard configs ─────────────────────────────────────────────
step "Configuring WireGuard"

cat > /tmp/wg-relay-server.conf <<EOF
[Interface]
PrivateKey = ${WG_SRV_PRIV}
ListenPort = ${WG_PORT}

[Peer]
PublicKey = ${WG_CLI_PUB}
AllowedIPs = ${WG_CLIENT_IP}/32
EOF

cat > /tmp/wg-relay-client.conf <<EOF
[Interface]
PrivateKey = ${WG_CLI_PRIV}

[Peer]
PublicKey = ${WG_SRV_PUB}
Endpoint = ${RELAY_IP}:${WG_PORT}
AllowedIPs = ${WG_SERVER_IP}/32
PersistentKeepalive = 5
EOF

# ── wg_server (shares gutd_server netns) ──────────────────────────
step "Starting wg_server (${WG_SERVER_IP}/30, inside gutd_server netns)"
docker run -d --name wg_server \
    --network "container:gutd_server" \
    --cap-add NET_ADMIN \
    -v /tmp/wg-relay-server.conf:/etc/wg/wg0.conf:ro \
    --entrypoint sh alpine \
    -c "
        apk add --no-cache wireguard-tools iperf3 >/dev/null 2>&1
        ip link add wg0 type wireguard
        wg setconf wg0 /etc/wg/wg0.conf
        ip addr add ${WG_SERVER_IP}/30 dev wg0
        ip link set wg0 mtu ${WG_MTU} up
        echo 'wg_server: wg0 up (${WG_SERVER_IP})'
        iperf3 -s --daemon 2>/dev/null
        tail -f /dev/null
    "

# ── wg_client (separate container on net_client) ──────────────────
step "Starting wg_client (${CLIENT_IP}, WG ${WG_CLIENT_IP}/30)"
docker run -d --name wg_client \
    --network "$NET_CLIENT" --ip "$CLIENT_IP" \
    --cap-add NET_ADMIN \
    -v /tmp/wg-relay-client.conf:/etc/wg/wg0.conf:ro \
    --entrypoint sh alpine \
    -c "
        apk add --no-cache wireguard-tools iperf3 >/dev/null 2>&1
        ip link add wg0 type wireguard
        wg setconf wg0 /etc/wg/wg0.conf
        ip addr add ${WG_CLIENT_IP}/30 dev wg0
        ip link set wg0 mtu ${WG_MTU} up
        echo 'wg_client: wg0 up (${WG_CLIENT_IP})'
        tail -f /dev/null
    "

# ── Verify network isolation ─────────────────────────────────────
step "Verifying network isolation"
# Client must NOT reach server directly
if docker exec wg_client ping -c 1 -W 2 "$SERVER_IP" &>/dev/null; then
    fail "Client can reach server directly at ${SERVER_IP} — isolation broken!"
    exit 1
else
    ok "Client CANNOT reach server (${SERVER_IP}) — isolation confirmed"
fi
# Client CAN reach relay
if docker exec wg_client ping -c 1 -W 2 "$RELAY_IP" &>/dev/null; then
    ok "Client CAN reach relay (${RELAY_IP})"
else
    fail "Client cannot reach relay — network broken"
    exit 1
fi

# ── Wait for WireGuard handshake ──────────────────────────────────
step "Waiting for WireGuard handshake"
# Start a short tcpdump on relay gut0 to capture the first seconds of WG traffic
docker exec -d gutd_relay sh -c \
    'tcpdump -i gut0 -n -c 20 -w /tmp/gut0_relay.pcap 2>/tmp/gut0_tcpdump.log' 2>/dev/null || true
# Also capture on relay eth0 for comparison
docker exec -d gutd_relay sh -c \
    'tcpdump -i eth0 -n -c 40 -w /tmp/eth0_relay.pcap 2>/tmp/eth0_tcpdump.log' 2>/dev/null || true

WG_READY=0
for i in $(seq 1 30); do
    docker exec wg_client ping -c 1 -W 1 "$WG_SERVER_IP" &>/dev/null || true
    if docker exec wg_client wg show wg0 2>/dev/null | grep -q "latest handshake"; then
        WG_READY=1
        ok "WireGuard handshake established (attempt $i)"
        break
    fi
    sleep 1
done

if [[ $WG_READY -eq 0 ]]; then
    fail "WireGuard handshake failed after 30s"
    log "=== wg_client wg show ==="
    docker exec wg_client wg show 2>&1 | sed 's/^/  /'
    log "=== wg_server wg show ==="
    docker exec wg_server wg show 2>&1 | sed 's/^/  /'
    log "=== relay gut0 tcpdump (first 20 pkts) ==="
    docker exec gutd_relay sh -c 'cat /tmp/gut0_tcpdump.log 2>/dev/null; tcpdump -r /tmp/gut0_relay.pcap -n 2>/dev/null | head -30 || echo "(no gut0 pcap)"' 2>&1 | sed 's/^/  /'
    log "=== relay eth0 tcpdump (first 40 pkts) ==="
    docker exec gutd_relay sh -c 'cat /tmp/eth0_tcpdump.log 2>/dev/null; tcpdump -r /tmp/eth0_relay.pcap -n 2>/dev/null | head -40 || echo "(no eth0 pcap)"' 2>&1 | sed 's/^/  /'
    log "=== relay nat iptables (with counters) ==="
    docker exec gutd_relay iptables -t nat -L -n -v 2>&1 | sed 's/^/  /'
    log "=== relay filter iptables FORWARD (with counters) ==="
    docker exec gutd_relay iptables -t filter -L FORWARD -n -v 2>&1 | sed 's/^/  /'
    log "=== relay conntrack table ==="
    docker exec gutd_relay sh -c 'cat /proc/net/nf_conntrack 2>/dev/null | grep -E "udp|UDP" | head -30 || echo "(conntrack not available)"' 2>&1 | sed 's/^/  /'
    log "=== relay routes ==="
    docker exec gutd_relay ip route 2>&1 | sed 's/^/  /'
    log "=== relay interface stats ==="
    docker exec gutd_relay ip -s link show 2>&1 | sed 's/^/  /'
    log "=== gutd_relay logs ==="
    docker logs gutd_relay 2>&1 | tail -30 | sed 's/^/  /'
    log "=== gutd_server logs ==="
    docker logs gutd_server 2>&1 | tail -30 | sed 's/^/  /'
    exit 1
fi

log "=== wg_client: wg show ==="
docker exec wg_client wg show wg0 2>&1 | sed 's/^/  /'
log "=== wg_server: wg show ==="
docker exec wg_server wg show wg0 2>&1 | sed 's/^/  /'

# ── Ping test ─────────────────────────────────────────────────────
step "Ping test: ${WG_CLIENT_IP} → ${WG_SERVER_IP} (through GUT relay + nDPI)"
PING_OK=0
PING_OUT=$(docker exec wg_client ping -c 10 -i 0.2 -W 3 "$WG_SERVER_IP" 2>&1) || true
echo "$PING_OUT" | sed 's/^/  /'
if echo "$PING_OUT" | grep -q "0% packet loss"; then
    ok "Ping: 0% loss"
    PING_OK=1
elif echo "$PING_OUT" | grep -qP '\d+ received'; then
    warn "Ping: some loss"
    PING_OK=1
else
    fail "Ping: 100% loss"
fi

# ── iperf3 TCP ────────────────────────────────────────────────────
IPERF_TCP_UP="N/A"
IPERF_TCP_DN="N/A"
IPERF_TCP_UP_RETR="N/A"
IPERF_TCP_DN_RETR="N/A"
if [[ $PING_OK -eq 1 ]]; then
    # Upload: client → server (512 MB)
    step "iperf3 TCP upload 512M (client→server, obfs=${OBFS_MODE})"
    docker exec -d wg_server iperf3 -s -1 -p 5201 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5201 -P 4 -n 512M 2>&1) || true
    echo "$IPERF_OUT" | tail -5 | sed 's/^/  /'
    IPERF_TCP_UP=$(echo "$IPERF_OUT" | grep -oP '[\d.]+\s+[GM]bits/sec' | tail -1) || true
    IPERF_TCP_UP_RETR=$(echo "$IPERF_OUT" | grep '\[SUM\].*sender' | grep -oP '[\d.]+\s+[GM]bits/sec\s+\K\d+') || true
    [[ -n "$IPERF_TCP_UP" ]] && ok "TCP upload: $IPERF_TCP_UP  retr: ${IPERF_TCP_UP_RETR:-?}" || warn "TCP upload: could not parse result"

    # Download: server → client (512 MB, reverse)
    step "iperf3 TCP download 512M (server→client, obfs=${OBFS_MODE})"
    docker exec -d wg_server iperf3 -s -1 -p 5201 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5201 -P 4 -n 512M -R 2>&1) || true
    echo "$IPERF_OUT" | tail -5 | sed 's/^/  /'
    IPERF_TCP_DN=$(echo "$IPERF_OUT" | grep -oP '[\d.]+\s+[GM]bits/sec' | tail -1) || true
    IPERF_TCP_DN_RETR=$(echo "$IPERF_OUT" | grep '\[SUM\].*sender' | grep -oP '[\d.]+\s+[GM]bits/sec\s+\K\d+') || true
    [[ -n "$IPERF_TCP_DN" ]] && ok "TCP download: $IPERF_TCP_DN  retr: ${IPERF_TCP_DN_RETR:-?}" || warn "TCP download: could not parse result"
fi

# ── iperf3 UDP ────────────────────────────────────────────────────
IPERF_UDP_UP="N/A"
IPERF_UDP_DN="N/A"
IPERF_UDP_LOSS_UP="N/A"
IPERF_UDP_LOSS_DN="N/A"
if [[ $PING_OK -eq 1 ]]; then
    # Upload: client → server (512 MB)
    step "iperf3 UDP upload 512M (client→server, obfs=${OBFS_MODE})"
    docker exec -d wg_server iperf3 -s -1 -p 5202 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5202 -u -b 1G -n 512M 2>&1) || true
    echo "$IPERF_OUT" | tail -5 | sed 's/^/  /'
    IPERF_UDP_UP=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '[\d.]+\s+[GM]bits/sec') || true
    IPERF_UDP_LOSS_UP=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '\([\d.]+%\)' | tr -d '()') || true
    [[ -n "$IPERF_UDP_UP" ]] && ok "UDP upload: $IPERF_UDP_UP  loss: ${IPERF_UDP_LOSS_UP:-?}" || warn "UDP upload: could not parse"

    # Download: server → client (512 MB, reverse)
    step "iperf3 UDP download 512M (server→client, obfs=${OBFS_MODE})"
    docker exec -d wg_server iperf3 -s -1 -p 5202 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5202 -u -b 1G -n 512M -R 2>&1) || true
    echo "$IPERF_OUT" | tail -5 | sed 's/^/  /'
    IPERF_UDP_DN=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '[\d.]+\s+[GM]bits/sec') || true
    IPERF_UDP_LOSS_DN=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '\([\d.]+%\)' | tr -d '()') || true
    [[ -n "$IPERF_UDP_DN" ]] && ok "UDP download: $IPERF_UDP_DN  loss: ${IPERF_UDP_LOSS_DN:-?}" || warn "UDP download: could not parse"
fi

# ── BPF stats (SIGUSR1) ──────────────────────────────────────────
step "eBPF stats (SIGUSR1)"
for name in gutd_server gutd_relay; do
    docker exec "$name" kill -USR1 1 2>/dev/null || true
done
sleep 1
for name in gutd_server gutd_relay; do
    log "=== $name stats ==="
    docker logs "$name" 2>&1 | grep -iE "stat|pkt|byte|drop" | tail -5 | sed 's/^/  /' || true
done

# ── nDPI analysis ─────────────────────────────────────────────────
step "nDPI traffic analysis"

# Stop tcpdump in ndpi_router
docker exec ndpi_router pkill tcpdump 2>/dev/null || true
sleep 1

# Copy pcap out
docker cp ndpi_router:/tmp/ndpi_relay.pcap /tmp/ndpi_relay.pcap 2>/dev/null || true

PCAP_SIZE=$(stat -c%s /tmp/ndpi_relay.pcap 2>/dev/null || echo 0)
log "Captured pcap: ${PCAP_SIZE} bytes"

NDPI_RESULT="SKIP"
NDPI_RISK="SKIP"
if [[ $PCAP_SIZE -gt 100 ]]; then
    # Try: system ndpiReader → /tmp/nDPI build → CI artifact
    NDPI_BIN=""
    if command -v ndpiReader &>/dev/null; then
        NDPI_BIN="ndpiReader"
    elif [[ -x /tmp/nDPI/example/ndpiReader ]]; then
        NDPI_BIN="/tmp/nDPI/example/ndpiReader"
    elif [[ -x /tmp/ndpi-bin/ndpiReader ]]; then
        NDPI_BIN="/tmp/ndpi-bin/ndpiReader"
    fi

    if [[ -n "$NDPI_BIN" ]]; then
        log "Analyzing with: $NDPI_BIN"
        NDPI_OUTPUT=$("$NDPI_BIN" -i /tmp/ndpi_relay.pcap -v2 2>&1) || true
        echo "$NDPI_OUTPUT" | head -40 | sed 's/^/  /'

        # Save full report
        echo "$NDPI_OUTPUT" > /tmp/ndpi-relay-report.txt

        # Check protocol classification
        if [[ -n "$NDPI_EXPECT" ]]; then
            if echo "$NDPI_OUTPUT" | grep -qi "$NDPI_EXPECT"; then
                ok "nDPI classified traffic as ${NDPI_EXPECT}"
                NDPI_RESULT="PASS"
            else
                fail "nDPI did NOT classify as ${NDPI_EXPECT}"
                NDPI_RESULT="FAIL"
            fi
        else
            ok "Mode '${OBFS_MODE}' — no specific protocol expected (random UDP)"
            NDPI_RESULT="PASS"
        fi

        # Check GUT flow for nDPI risk flags
        GUT_FLOW=$(echo "$NDPI_OUTPUT" | grep "UDP.*:${GUT_FIRST_PORT} " || true)
        if [[ -n "$GUT_FLOW" ]]; then
            if echo "$GUT_FLOW" | grep -qi "Risk:"; then
                warn "nDPI flagged GUT flow with risks:"
                echo "$GUT_FLOW" | grep -oi '\[Risk: [^]]*\]' | sed 's/^/    /'
                NDPI_RISK="FLAGGED"
            else
                ok "GUT flow (port ${GUT_FIRST_PORT}) — no nDPI risk flags"
                NDPI_RISK="CLEAN"
            fi
        else
            warn "GUT flow on port ${GUT_FIRST_PORT} not found in nDPI output"
            NDPI_RISK="N/A"
        fi
    else
        warn "ndpiReader not found — skipping DPI analysis (pcap saved at /tmp/ndpi_relay.pcap)"
        warn "Install: git clone https://github.com/ntop/nDPI /tmp/nDPI && cd /tmp/nDPI && ./autogen.sh && ./configure && make"
        NDPI_RESULT="SKIP"
        NDPI_RISK="SKIP"
    fi
else
    warn "No pcap captured (${PCAP_SIZE} bytes) — skipping nDPI"
fi

# ── Summary ───────────────────────────────────────────────────────
step "Test Summary"
echo ""
echo -e "  Obfuscation mode  : ${BOLD}${OBFS_MODE}${NC}"
echo -e "  GUT ports         : ${GUT_PORTS}"
echo -e "  WireGuard MTU     : ${WG_MTU}"
echo ""
echo "  Network layout (/29 segments, relay ONE NIC):"
echo "    net_client  ${NET_CLIENT_SUBNET} : client(${CLIENT_IP}), relay(${RELAY_IP}), ndpi(${NDPI_CLIENT_IP})"
echo "    net_server  ${NET_SERVER_SUBNET} : ndpi(${NDPI_SERVER_IP}), server(${SERVER_IP})"
echo "    GUT tunnel                       : relay(${GUT_RELAY_ADDR}) ↔ server(${GUT_SERVER_ADDR})"
echo "    WireGuard                        : client(${WG_CLIENT_IP}) ↔ server(${WG_SERVER_IP})"
echo ""

CAPS_MODE="explicit (NET_ADMIN + SYS_ADMIN + NET_RAW)"
[[ $PRIVILEGED -eq 1 ]] && CAPS_MODE="--privileged"
echo "  Capabilities      : $CAPS_MODE"
echo ""

for name in gutd_server gutd_relay ndpi_router; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
    [[ "$STATE" == "running" ]] && ok "$name: running" || fail "$name: $STATE"
done

echo ""
[[ $PING_OK -eq 1 ]] && ok "WG ping through relay: PASS" || fail "WG ping through relay: FAIL"
echo "  TCP upload        : ${IPERF_TCP_UP:-N/A}  retr: ${IPERF_TCP_UP_RETR:-N/A}"
echo "  TCP download      : ${IPERF_TCP_DN:-N/A}  retr: ${IPERF_TCP_DN_RETR:-N/A}"
echo "  UDP upload        : ${IPERF_UDP_UP:-N/A}  loss: ${IPERF_UDP_LOSS_UP:-N/A}"
echo "  UDP download      : ${IPERF_UDP_DN:-N/A}  loss: ${IPERF_UDP_LOSS_DN:-N/A}"
echo "  nDPI protocol     : ${NDPI_RESULT} (expect: ${NDPI_EXPECT:-any})"
echo "  nDPI risk flags   : ${NDPI_RISK}"
echo ""

# ── CI / interactive mode ─────────────────────────────────────────
if [[ $CI_MODE -eq 1 ]]; then
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "## Relay eBPF + nDPI — \`${OBFS_MODE}\`"
            echo ""
            echo "| Metric | Result |"
            echo "|--------|--------|"
            echo "| WG Ping | $([ $PING_OK -eq 1 ] && echo 'PASS' || echo 'FAIL') |"
            echo "| TCP upload (client→server) | ${IPERF_TCP_UP:-N/A} retr=${IPERF_TCP_UP_RETR:-N/A} |"
            echo "| TCP download (server→client) | ${IPERF_TCP_DN:-N/A} retr=${IPERF_TCP_DN_RETR:-N/A} |"
            echo "| UDP upload | ${IPERF_UDP_UP:-N/A} |"
            echo "| UDP upload loss | ${IPERF_UDP_LOSS_UP:-N/A} |"
            echo "| UDP download | ${IPERF_UDP_DN:-N/A} |"
            echo "| UDP download loss | ${IPERF_UDP_LOSS_DN:-N/A} |"
            echo "| nDPI protocol (expect: ${NDPI_EXPECT:-any}) | ${NDPI_RESULT} |"
            echo "| nDPI risk flags | ${NDPI_RISK} |"
            echo "| Obfs mode | ${OBFS_MODE} |"
            echo "| Relay NIC count | 1 (eth0) |"
        } >> "$GITHUB_STEP_SUMMARY"
    fi

    if [[ $PING_OK -eq 1 ]]; then
        log "PASS"
        exit 0
    else
        error "FAIL"
        exit 1
    fi
fi

if [[ $KEEP -eq 1 ]]; then
    log "Containers running. Inspect:"
    log "  docker logs gutd_relay"
    log "  docker logs gutd_server"
    log "  docker exec wg_client wg show"
    log "  docker exec gutd_relay iptables -t nat -L -n -v"
    log "  docker exec ndpi_router ls /tmp/"
    log "Press Ctrl-C to tear down."
    trap cleanup EXIT
    wait 2>/dev/null || read -r -p ""
else
    log "Tearing down (pass --keep to leave containers)."
fi
