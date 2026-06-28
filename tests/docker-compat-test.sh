#!/bin/bash
# tests/docker-compat-test.sh — BPF ↔ Userspace protocol compatibility test
#
# Verifies that the BPF (TC/XDP) and userspace implementations of the GUT
# obfuscation protocol can decode each other's packets.  Three scenarios:
#
#   bpf-us  : BPF relay  (initiator) ↔ Userspace server (responder)
#   us-bpf  : Userspace relay (initiator) ↔ BPF server (responder)
#             Note: SNAT is applied for non-SIP modes so that BPF server
#             can reply to the correct port (BPF always uses configured port
#             as dst; SNAT rewrites the ephemeral src → GUT_PORT before the
#             packet leaves the relay, conntrack reverses on the way back).
#   us-us   : Userspace relay ↔ Userspace server (endpoint roaming handles
#             the ephemeral ext-socket port automatically)
#
#   bpf-bpf : Baseline (same as docker-relay-test.sh) — useful for comparison
#
# Topology (identical to docker-relay-test.sh; relay has ONE NIC):
#
# ┌──────────────┐  net_client        ┌───────────┐  net_server   ┌──────────────┐
# │  wg_client   │  10.100.1.0/29     │   relay   │               │   server     │
# │  .3          ├────────────────────►│  .2       │               │  .3          │
# │  wg0         │                    │  ONE NIC  │               │  gut0 .1     │
# │  10.200.0.1  │                    │  gut0 .2  │               │  WG :51820   │
# └──────────────┘                    └─────┬─────┘               │  10.200.0.2  │
#                                           │ GUT obfs UDP         └──────▲───────┘
#                                           │ (via ndpi .4)                │
#                                           ▼                              │
#                                    ┌─────────────┐  10.100.2.0/29       │
#                                    │ ndpi_router │─────────────────────►│
#                                    │ .4 (cl)     │  .2 (srv)            │
#                                    │ tcpdump     │                      │
#                                    │ ndpiReader  │─────────────────────►│
#                                    └─────────────┘
#
# Usage:
#   sudo bash tests/docker-compat-test.sh [OPTIONS]
#
# Options:
#   --scenario SCEN  bpf-us | us-bpf | us-us | bpf-bpf (default: bpf-us)
#   --obfs MODE      quic (default) | gut | sip | syslog
#   --rebuild        Force rebuild of gutd Docker image
#   --privileged     Use --privileged instead of explicit caps
#   --ci             Non-interactive (exit after tests)
#   --keep           Keep containers running after test (ignored in --ci)
#
# Environment:
#   GUTD_IMAGE       Docker image name (default: gutd:relay-test)
#   GUTD_BINARY      Path to pre-built gutd binary (skips Docker build)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────
IMAGE="${GUTD_IMAGE:-gutd:relay-test}"
SCENARIO="bpf-us"
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

# ── Argument parsing ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)  SCENARIO="$2";  shift 2 ;;
        --obfs)      OBFS_MODE="$2"; shift 2 ;;
        --privileged) PRIVILEGED=1;  shift   ;;
        --rebuild)   REBUILD=1;      shift   ;;
        --ci)        CI_MODE=1;      shift   ;;
        --keep)      KEEP=1;         shift   ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Scenario → relay/server mode flags ───────────────────────────
# RELAY_US=1 → relay runs gutd in userspace mode (no gut0 TUN)
# SERVER_US=1 → server runs gutd in userspace mode
case "$SCENARIO" in
    bpf-us)  RELAY_US=0; SERVER_US=1 ;;
    us-bpf)  RELAY_US=1; SERVER_US=0 ;;
    us-us)   RELAY_US=1; SERVER_US=1 ;;
    bpf-bpf) RELAY_US=0; SERVER_US=0 ;;
    *)
        error "Unknown scenario: $SCENARIO"
        error "Valid: bpf-us | us-bpf | us-us | bpf-bpf"
        exit 1
        ;;
esac

RELAY_TAG=$([[ $RELAY_US -eq 1 ]] && echo "userspace" || echo "BPF")
SERVER_TAG=$([[ $SERVER_US -eq 1 ]] && echo "userspace" || echo "BPF")

# ── Per-mode settings ─────────────────────────────────────────────
case "$OBFS_MODE" in
    quic)
        GUT_PORTS="443";  WG_MTU=1420; GUTD_SNI="example.com"
        NDPI_EXPECT="QUIC"
        ;;
    gut)
        GUT_PORTS="2046"; WG_MTU=1420; GUTD_SNI=""
        NDPI_EXPECT=""
        ;;
    sip)
        # MAX_PORTS=6 in BPF build — keep exactly 6 SIP ports so BPF server handles all of them
        GUT_PORTS="5060,10000,10001,10002,10003,10004"
        WG_MTU=1400; GUTD_SNI="sip.example.com"
        NDPI_EXPECT="SIP"
        ;;
    syslog)
        GUT_PORTS="514"; WG_MTU=800; GUTD_SNI="asterisk"
        NDPI_EXPECT="Syslog"
        ;;
    *)
        error "Unknown obfs mode: $OBFS_MODE (choose: quic, gut, sip, syslog)"
        exit 1
        ;;
esac

GUT_FIRST_PORT="${GUT_PORTS%%,*}"

# ── Network addressing ────────────────────────────────────────────
NET_CLIENT="gut_compat_cl"
NET_CLIENT_SUBNET="10.100.1.0/29"  # .1=gw, .2=relay, .3=client, .4=ndpi
RELAY_IP="10.100.1.2"
CLIENT_IP="10.100.1.3"
NDPI_CLIENT_IP="10.100.1.4"

NET_SERVER="gut_compat_srv"
NET_SERVER_SUBNET="10.100.2.0/29"  # .1=gw, .2=ndpi, .3=server
NDPI_SERVER_IP="10.100.2.2"
SERVER_IP="10.100.2.3"

# GUT tunnel /30  (odd=responder=server, even=initiator=relay)
GUT_RELAY_ADDR="10.254.0.2/30"
GUT_RELAY_TUN_IP="10.254.0.2"
GUT_SERVER_ADDR="10.254.0.1/30"
GUT_SERVER_TUN_IP="10.254.0.1"

# WireGuard overlay
WG_CLIENT_IP="10.200.0.1"
WG_SERVER_IP="10.200.0.2"
WG_PORT=51820

step "BPF ↔ Userspace Compatibility Test"
echo -e "  Scenario    : ${BOLD}${SCENARIO}${NC}  (relay=${RELAY_TAG}, server=${SERVER_TAG})"
echo -e "  Obfuscation : ${BOLD}${OBFS_MODE}${NC}"
echo -e "  Ports       : ${GUT_PORTS}"
echo -e "  WG MTU      : ${WG_MTU}"
echo -e "  Topology    : client(${CLIENT_IP}) → relay(${RELAY_IP}) → ndpi → server(${SERVER_IP})"

# ── Cleanup ───────────────────────────────────────────────────────
CONTAINERS=(wg_client gutd_relay ndpi_router gutd_server wg_server)

# In CI mode, save docker logs to files before containers are removed so the
# workflow artifact upload step can still collect them after cleanup.
save_logs() {
    if [[ $CI_MODE -eq 1 ]]; then
        mkdir -p /tmp/compat-logs
        docker logs gutd_relay  > /tmp/compat-logs/gutd_relay.log  2>&1 || true
        docker logs gutd_server > /tmp/compat-logs/gutd_server.log 2>&1 || true
        docker logs ndpi_router > /tmp/compat-logs/ndpi_router.log 2>&1 || true
        docker logs wg_client   > /tmp/compat-logs/wg_client.log   2>&1 || true
        docker logs wg_server   > /tmp/compat-logs/wg_server.log   2>&1 || true
    fi
}

cleanup() {
    save_logs
    log "Cleaning up..."
    for c in "${CONTAINERS[@]}"; do
        docker stop  "$c" 2>/dev/null || true
        docker rm -f "$c" 2>/dev/null || true
    done
    docker network rm "$NET_CLIENT" "$NET_SERVER" 2>/dev/null || true
    rm -f /tmp/gutd-compat-*.conf /tmp/wg-compat-*.conf \
          /tmp/ndpi_compat.pcap /tmp/ndpi-compat-report.txt
}
trap cleanup EXIT
cleanup 2>/dev/null || true

# ── Prerequisites ─────────────────────────────────────────────────
step "Checking prerequisites"
MISSING=0
for cmd in docker wg xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        error "Missing command: $cmd"; MISSING=1
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
    if ! docker run --rm --entrypoint sh "$IMAGE" -c true &>/dev/null 2>&1; then
        warn "Cached image $IMAGE has no shell — rebuilding"
        build_image
    else
        log "Using existing image $IMAGE  (pass --rebuild to force)"
    fi
fi

# ── Generate keys ─────────────────────────────────────────────────
step "Generating cryptographic keys"
GUTD_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
WG_SRV_PRIV=$(wg genkey); WG_SRV_PUB=$(echo "$WG_SRV_PRIV" | wg pubkey)
WG_CLI_PRIV=$(wg genkey); WG_CLI_PUB=$(echo "$WG_CLI_PRIV" | wg pubkey)
log "gutd key  : ${GUTD_KEY:0:16}..."
log "WG server : $WG_SRV_PUB"
log "WG client : $WG_CLI_PUB"

# ── Docker networks ───────────────────────────────────────────────
step "Creating Docker networks (/29)"
docker network create --subnet "$NET_CLIENT_SUBNET" "$NET_CLIENT"
docker network create --subnet "$NET_SERVER_SUBNET" "$NET_SERVER"
ok "net_client : $NET_CLIENT_SUBNET"
ok "net_server : $NET_SERVER_SUBNET"

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
step "Writing gutd configs (scenario=${SCENARIO}, obfs=${OBFS_MODE})"

# Relay config
# address=10.254.0.2/30 → last octet even → responder=false (initiator/relay role)
# For US relay: wg_host = RELAY_IP:WG_PORT  → local_socket binds here;
#               wg_client (separate container) connects to RELAY_IP:WG_PORT directly.
# For BPF relay: wg_host unused (BPF intercepts on gut0, DNAT handles WG from client).
RELAY_USO_LINE=$([[ $RELAY_US -eq 1 ]] && echo "userspace_only = true" || echo "")
RELAY_WGHOST_LINE=$([[ $RELAY_US -eq 1 ]] && echo "wg_host = ${RELAY_IP}:${WG_PORT}" || echo "")

cat > /tmp/gutd-compat-relay.conf <<EOF
[global]
${RELAY_USO_LINE}
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
${RELAY_WGHOST_LINE}
EOF

# Server config
# address=10.254.0.1/30 → last octet odd → responder=true (server role) — auto-inferred
# wg_host: used by both BPF (ignored) and US (forwards decapped WG to wg_server)
SERVER_USO_LINE=$([[ $SERVER_US -eq 1 ]] && echo "userspace_only = true" || echo "")

cat > /tmp/gutd-compat-server.conf <<EOF
[global]
${SERVER_USO_LINE}
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

log "Relay  : ${RELAY_TAG}, nic=eth0, bind=${RELAY_IP}, peer=${SERVER_IP}"
log "Server : ${SERVER_TAG}, nic=eth0, bind=${SERVER_IP}, peer=${RELAY_IP}"

# ── ndpi_router ───────────────────────────────────────────────────
step "Starting ndpi_router (${NDPI_CLIENT_IP} ↔ ${NDPI_SERVER_IP})"
docker run -d --name ndpi_router \
    --network "$NET_CLIENT" --ip "$NDPI_CLIENT_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    --entrypoint sh alpine \
    -c "
        apk add --no-cache tcpdump >/dev/null 2>&1
        for i in \$(seq 1 30); do
            ip link show eth1 >/dev/null 2>&1 && break
            sleep 0.2
        done
        tcpdump -i eth1 -w /tmp/ndpi_compat.pcap -s 0 -n 2>/dev/null &
        echo 'ndpi_router: forwarding + capturing'
        tail -f /dev/null
    "

sleep 0.5
docker network connect --ip "$NDPI_SERVER_IP" "$NET_SERVER" ndpi_router
ok "ndpi_router: ${NDPI_CLIENT_IP} (client-side) / ${NDPI_SERVER_IP} (server-side)"

# ── gutd_server ───────────────────────────────────────────────────
# Route to net_client must be set BEFORE gutd starts so BPF ARP resolves
# the relay peer MAC via ndpi, not the Docker default gateway.
step "Starting gutd_server (${SERVER_TAG}, ${SERVER_IP}, gut0=${GUT_SERVER_ADDR})"

SERVER_MOUNTS=()
[[ $SERVER_US -eq 0 ]] && SERVER_MOUNTS+=("${BPF_MOUNT[@]}")

docker run -d --name gutd_server \
    --network "$NET_SERVER" --ip "$SERVER_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    "${CAPS[@]}" "${SERVER_MOUNTS[@]}" \
    -v /tmp/gutd-compat-server.conf:/etc/gutd.conf:ro \
    --entrypoint sh \
    "$IMAGE" -c "
        ip route add ${NET_CLIENT_SUBNET} via ${NDPI_SERVER_IP}
        exec /gutd --config /etc/gutd.conf
    "

# ── gutd_relay ────────────────────────────────────────────────────
step "Starting gutd_relay (${RELAY_TAG}, ${RELAY_IP}, ONE NIC)"

RELAY_MOUNTS=()
[[ $RELAY_US -eq 0 ]] && RELAY_MOUNTS+=("${BPF_MOUNT[@]}")

if [[ $RELAY_US -eq 0 ]]; then
    # ── BPF relay (same as docker-relay-test.sh) ──────────────────
    # DNAT: wg_client WG UDP on eth0:51820 → gut0 peer IP (server tunnel endpoint).
    # MASQUERADE on gut0 so the server's GUT reply is addressed to GUT_RELAY_TUN_IP,
    # which XDP delivers to gut0; conntrack then de-NATs back to wg_client.
    docker run -d --name gutd_relay \
        --network "$NET_CLIENT" --ip "$RELAY_IP" \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv4.conf.all.rp_filter=0 \
        --sysctl net.ipv4.conf.default.rp_filter=0 \
        "${CAPS[@]}" "${RELAY_MOUNTS[@]}" \
        -v /tmp/gutd-compat-relay.conf:/etc/gutd.conf:ro \
        --entrypoint sh \
        "$IMAGE" -c "
            ip route add ${NET_SERVER_SUBNET} via ${NDPI_CLIENT_IP}
            iptables -t nat -A PREROUTING -i eth0 -p udp --dport ${WG_PORT} \
                -j DNAT --to-destination ${GUT_SERVER_TUN_IP}:${WG_PORT}
            # SNAT wg_client src to gut0_local:WG_PORT so US server always sees
            # enc_ports=(WG_PORT,WG_PORT) and conntrack can reverse the reply.
            # Use source-subnet match (not -o gut0) so the rule applies even before
            # gut0 is created by gutd.
            iptables -t nat -A POSTROUTING \
                -p udp -s ${NET_CLIENT_SUBNET} --dport ${WG_PORT} \
                -j SNAT --to-source ${GUT_RELAY_TUN_IP}:${WG_PORT}
            iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
            iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
            iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
            exec /gutd --config /etc/gutd.conf
        "
else
    # ── Userspace relay ───────────────────────────────────────────
    # No gut0 TUN.  gutd_relay local_socket binds on RELAY_IP:WG_PORT (= wg_host).
    # wg_client (separate container) connects directly to RELAY_IP:WG_PORT.
    # gutd_relay ext_socket is ephemeral (client/initiator mode).
    #
    # us-bpf non-SIP: BPF server always responds to the configured GUT_PORT regardless
    # of the source port it received.  SNAT rewrites the outgoing GUT src-port from
    # the ephemeral value to GUT_FIRST_PORT before the packet leaves the relay; Linux
    # conntrack automatically reverses this for replies, so the ephemeral ext_socket
    # still receives the BPF server's responses.
    #
    # us-us: no SNAT needed — US server uses endpoint-roaming (shared_peer_ext) to
    # learn and reply to the actual ephemeral source port.
    SNAT_CMD=""
    if [[ $SERVER_US -eq 0 && "$OBFS_MODE" != "sip" ]]; then
        # SIP mode skipped: client_needs_fixed_port=true for SIP, no mismatch.
        SNAT_CMD="iptables -t nat -A POSTROUTING -o eth0 -p udp \
            --dport ${GUT_FIRST_PORT} \
            -j SNAT --to-source ${RELAY_IP}:${GUT_FIRST_PORT};"
    fi

    docker run -d --name gutd_relay \
        --network "$NET_CLIENT" --ip "$RELAY_IP" \
        --sysctl net.ipv4.ip_forward=1 \
        "${CAPS[@]}" \
        -v /tmp/gutd-compat-relay.conf:/etc/gutd.conf:ro \
        --entrypoint sh \
        "$IMAGE" -c "
            ip route add ${NET_SERVER_SUBNET} via ${NDPI_CLIENT_IP}
            ${SNAT_CMD}
            exec /gutd --config /etc/gutd.conf
        "
fi

# ── Wait for gutd containers ──────────────────────────────────────
# BPF mode logs: "TC eBPF mode activated" / "gut0 up"
# US  mode logs: "Listening (ext) on" / "gutd-userspace proxy"
wait_ready() {
    local name=$1 timeout=${2:-35}
    log "Waiting for $name ..."
    for i in $(seq 1 "$timeout"); do
        local out
        out=$(docker logs "$name" 2>&1)
        if echo "$out" | grep -qiE \
            "TC eBPF mode activated|Listening .ext. on|gutd-userspace proxy|gut0 up|Loaded config"; then
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

log "=== gutd_server logs (last 10) ==="
docker logs gutd_server 2>&1 | tail -10 | sed 's/^/  /'
log "=== gutd_relay logs (last 10) ==="
docker logs gutd_relay  2>&1 | tail -10 | sed 's/^/  /'

# ── Verify startup ────────────────────────────────────────────────
step "Checking container startup status"
STARTUP_OK=1
for name in gutd_server gutd_relay ndpi_router; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
    if [[ "$STATE" != "running" ]]; then
        fail "$name: state=$STATE"; STARTUP_OK=0; continue
    fi
    if [[ "$name" != "ndpi_router" ]] && \
        docker logs "$name" 2>&1 | grep -qiE "^Error:|Failed to create|failed:"; then
        fail "$name has errors in logs"; STARTUP_OK=0
    else
        ok "$name: running"
    fi
done
[[ $STARTUP_OK -eq 0 ]] && { error "Container startup failed"; exit 1; }

# ── Verify relay interface ────────────────────────────────────────
step "Verifying relay interfaces and routing"
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
log "Relay iptables nat:"
docker exec gutd_relay iptables -t nat -L -n 2>&1 | sed 's/^/  /' || true

# ── Verify ndpi routing ───────────────────────────────────────────
step "Verifying ndpi_router forwarding path"
if docker exec gutd_relay ping -c 1 -W 2 "$SERVER_IP" &>/dev/null; then
    ok "Relay can reach server (${SERVER_IP}) via ndpi"
else
    fail "Relay cannot reach server — ndpi routing broken"
    docker exec gutd_relay sh -c "traceroute -n -m 3 ${SERVER_IP} 2>&1" | sed 's/^/  /' || true
    exit 1
fi

# ── GUT tunnel ping (BPF relay only — gut0 doesn't exist in US mode) ──
if [[ $RELAY_US -eq 0 ]]; then
    step "Verifying GUT tunnel (relay gut0 → server gut0)"
    if docker exec gutd_relay ping -c 3 -W 3 "$GUT_SERVER_TUN_IP" &>/dev/null; then
        ok "GUT tunnel: ${GUT_RELAY_TUN_IP} → ${GUT_SERVER_TUN_IP} ✓"
    else
        warn "GUT tunnel ping failed — ICMP may be filtered; WireGuard test will confirm"
        docker exec gutd_relay ping -c 3 -W 2 "$GUT_SERVER_TUN_IP" 2>&1 | sed 's/^/  /' || true
    fi
else
    step "GUT tunnel ping: skipped (US relay has no gut0 TUN)"
    log "Relay (US) ext socket connects directly to server via GUT UDP"
fi

# ── WireGuard configs ─────────────────────────────────────────────
step "Configuring WireGuard"

cat > /tmp/wg-compat-server.conf <<EOF
[Interface]
PrivateKey = ${WG_SRV_PRIV}
ListenPort = ${WG_PORT}

[Peer]
PublicKey = ${WG_CLI_PUB}
AllowedIPs = ${WG_CLIENT_IP}/32
EOF

# WG client endpoint:
# BPF relay: RELAY_IP:WG_PORT  →  iptables DNAT → GUT_SERVER_TUN_IP:WG_PORT
#            → BPF intercepts on gut0 → encaps → server
# US  relay: RELAY_IP:WG_PORT  →  gutd_relay local_socket receives directly
#            → encaps → GUT UDP → server
# Same endpoint in both cases — DNAT vs local_socket is transparent to wg_client.
cat > /tmp/wg-compat-client.conf <<EOF
[Interface]
PrivateKey = ${WG_CLI_PRIV}

[Peer]
PublicKey = ${WG_SRV_PUB}
Endpoint = ${RELAY_IP}:${WG_PORT}
AllowedIPs = ${WG_SERVER_IP}/32
PersistentKeepalive = 5
EOF

# ── wg_server (inside gutd_server netns) ──────────────────────────
step "Starting wg_server (${WG_SERVER_IP}/30, inside gutd_server netns)"
docker run -d --name wg_server \
    --network "container:gutd_server" \
    --cap-add NET_ADMIN \
    -v /tmp/wg-compat-server.conf:/etc/wg/wg0.conf:ro \
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
    -v /tmp/wg-compat-client.conf:/etc/wg/wg0.conf:ro \
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

# ── Verify network isolation ──────────────────────────────────────
step "Verifying network isolation"
if docker exec wg_client ping -c 1 -W 2 "$SERVER_IP" &>/dev/null; then
    fail "Client can reach server (${SERVER_IP}) directly — isolation broken!"
    exit 1
else
    ok "Client CANNOT reach server (${SERVER_IP}) directly"
fi
if docker exec wg_client ping -c 1 -W 2 "$RELAY_IP" &>/dev/null; then
    ok "Client CAN reach relay (${RELAY_IP})"
else
    fail "Client cannot reach relay — network broken"
    exit 1
fi

# ── Wait for WireGuard handshake ──────────────────────────────────
step "Waiting for WireGuard handshake (up to 30s)"

# Capture relay-side traffic for diagnostics
if [[ $RELAY_US -eq 0 ]]; then
    # BPF relay: capture on gut0 (WG before encap) and eth0 (GUT after encap)
    docker exec -d gutd_relay sh -c \
        'tcpdump -i gut0 -n -c 20 -w /tmp/gut0_compat.pcap 2>/dev/null' 2>/dev/null || true
fi
docker exec -d gutd_relay sh -c \
    'tcpdump -i eth0 -n -c 40 -w /tmp/eth0_compat.pcap 2>/dev/null' 2>/dev/null || true

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
    log "=== relay eth0 traffic (first 40 pkts) ==="
    docker exec gutd_relay sh -c \
        'tcpdump -r /tmp/eth0_compat.pcap -n 2>/dev/null | head -40 || echo "(no pcap)"' \
        2>&1 | sed 's/^/  /'
    if [[ $RELAY_US -eq 0 ]]; then
        log "=== relay gut0 traffic (first 20 pkts) ==="
        docker exec gutd_relay sh -c \
            'tcpdump -r /tmp/gut0_compat.pcap -n 2>/dev/null | head -20 || echo "(no gut0 pcap)"' \
            2>&1 | sed 's/^/  /'
    fi
    log "=== relay iptables nat (with counters) ==="
    docker exec gutd_relay iptables -t nat -L -n -v 2>&1 | sed 's/^/  /' || true
    log "=== relay conntrack ==="
    docker exec gutd_relay sh -c \
        'cat /proc/net/nf_conntrack 2>/dev/null | grep -Ei "udp" | head -20 \
         || echo "(unavailable)"' 2>&1 | sed 's/^/  /' || true
    log "=== gutd_relay logs (last 30) ==="
    docker logs gutd_relay 2>&1 | tail -30 | sed 's/^/  /'
    log "=== gutd_server logs (last 30) ==="
    docker logs gutd_server 2>&1 | tail -30 | sed 's/^/  /'
    exit 1
fi

log "=== wg_client: wg show wg0 ==="
docker exec wg_client wg show wg0 2>&1 | sed 's/^/  /'
log "=== wg_server: wg show wg0 ==="
docker exec wg_server wg show wg0 2>&1 | sed 's/^/  /'

# ── Ping test ─────────────────────────────────────────────────────
step "Ping: ${WG_CLIENT_IP} → ${WG_SERVER_IP} (through GUT tunnel + ndpi)"
PING_OK=0
PING_OUT=$(docker exec wg_client ping -c 10 -i 0.2 -W 3 "$WG_SERVER_IP" 2>&1) || true
echo "$PING_OUT" | sed 's/^/  /'
if echo "$PING_OUT" | grep -q "0% packet loss"; then
    ok "Ping: 0% loss"; PING_OK=1
elif echo "$PING_OUT" | grep -qP '\d+ received'; then
    warn "Ping: some loss"; PING_OK=1
else
    fail "Ping: 100% loss"
fi

# ── iperf3 TCP ────────────────────────────────────────────────────
IPERF_TCP_UP="N/A"; IPERF_TCP_DN="N/A"
IPERF_TCP_UP_RETR="N/A"; IPERF_TCP_DN_RETR="N/A"
if [[ $PING_OK -eq 1 ]]; then
    # TCP tests: time-bounded (-t 10) avoids the cwnd-collapse / control-socket
    # race that occurs with large byte-count tests (-n 256M) in CI environments.
    # Explicitly restart iperf3 server before each test: the daemon started at
    # container init may have failed silently (Alpine musl --daemon compat), so
    # we can't rely on it.  With -t 10 the result-exchange is quick and clean,
    # so -s -1 (one-shot server) no longer races against the client.
    step "iperf3 TCP upload 10s"
    docker exec wg_server pkill -f 'iperf3.*5201' 2>/dev/null || true
    docker exec -d wg_server iperf3 -s -1 -p 5201 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5201 -P 4 -t 10 2>&1) || true
    echo "$IPERF_OUT" | tail -4 | sed 's/^/  /'
    IPERF_TCP_UP=$(echo "$IPERF_OUT" | grep -oP '[\d.]+\s+[GM]bits/sec' | tail -1) || true
    IPERF_TCP_UP_RETR=$(echo "$IPERF_OUT" | grep '\[SUM\].*sender' \
        | grep -oP '[\d.]+\s+[GM]bits/sec\s+\K\d+') || true
    [[ -n "$IPERF_TCP_UP" ]] \
        && ok "TCP upload: $IPERF_TCP_UP  retr: ${IPERF_TCP_UP_RETR:-?}" \
        || warn "TCP upload: could not parse"

    step "iperf3 TCP download 10s"
    docker exec wg_server pkill -f 'iperf3.*5201' 2>/dev/null || true
    docker exec -d wg_server iperf3 -s -1 -p 5201 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client iperf3 -c "$WG_SERVER_IP" -p 5201 -P 4 -t 10 -R 2>&1) || true
    echo "$IPERF_OUT" | tail -4 | sed 's/^/  /'
    IPERF_TCP_DN=$(echo "$IPERF_OUT" | grep -oP '[\d.]+\s+[GM]bits/sec' | tail -1) || true
    IPERF_TCP_DN_RETR=$(echo "$IPERF_OUT" | grep '\[SUM\].*sender' \
        | grep -oP '[\d.]+\s+[GM]bits/sec\s+\K\d+') || true
    [[ -n "$IPERF_TCP_DN" ]] \
        && ok "TCP download: $IPERF_TCP_DN  retr: ${IPERF_TCP_DN_RETR:-?}" \
        || warn "TCP download: could not parse"
fi

# ── iperf3 UDP ──────────────────────────────────────────────────── 
IPERF_UDP_UP="N/A"; IPERF_UDP_DN="N/A"
IPERF_UDP_LOSS_UP="N/A"; IPERF_UDP_LOSS_DN="N/A"
if [[ $PING_OK -eq 1 ]]; then
    step "iperf3 UDP upload 128M"
    docker exec -d wg_server iperf3 -s -1 -p 5202 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client \
        iperf3 -c "$WG_SERVER_IP" -p 5202 -u -b 500M -n 128M 2>&1) || true
    echo "$IPERF_OUT" | tail -4 | sed 's/^/  /'
    IPERF_UDP_UP=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '[\d.]+\s+[GM]bits/sec') || true
    IPERF_UDP_LOSS_UP=$(echo "$IPERF_OUT" | grep "sender" \
        | grep -oP '\([\d.]+%\)' | tr -d '()') || true
    [[ -n "$IPERF_UDP_UP" ]] \
        && ok "UDP upload: $IPERF_UDP_UP  loss: ${IPERF_UDP_LOSS_UP:-?}" \
        || warn "UDP upload: could not parse"

    step "iperf3 UDP download 128M"
    docker exec -d wg_server iperf3 -s -1 -p 5202 2>/dev/null || true
    sleep 0.5
    IPERF_OUT=$(docker exec wg_client \
        iperf3 -c "$WG_SERVER_IP" -p 5202 -u -b 500M -n 128M -R 2>&1) || true
    echo "$IPERF_OUT" | tail -4 | sed 's/^/  /'
    IPERF_UDP_DN=$(echo "$IPERF_OUT" | grep "sender" | grep -oP '[\d.]+\s+[GM]bits/sec') || true
    IPERF_UDP_LOSS_DN=$(echo "$IPERF_OUT" | grep "sender" \
        | grep -oP '\([\d.]+%\)' | tr -d '()') || true
    [[ -n "$IPERF_UDP_DN" ]] \
        && ok "UDP download: $IPERF_UDP_DN  loss: ${IPERF_UDP_LOSS_DN:-?}" \
        || warn "UDP download: could not parse"
fi

# ── nDPI analysis ─────────────────────────────────────────────────
step "nDPI traffic analysis"

docker exec ndpi_router pkill tcpdump 2>/dev/null || true
sleep 1
docker cp ndpi_router:/tmp/ndpi_compat.pcap /tmp/ndpi_compat.pcap 2>/dev/null || true

PCAP_SIZE=$(stat -c%s /tmp/ndpi_compat.pcap 2>/dev/null || echo 0)
log "Captured pcap: ${PCAP_SIZE} bytes"

NDPI_RESULT="SKIP"
NDPI_RISK="SKIP"
if [[ $PCAP_SIZE -gt 100 ]]; then
    NDPI_BIN=""
    command -v ndpiReader &>/dev/null && NDPI_BIN="ndpiReader"
    [[ -z "$NDPI_BIN" && -x /tmp/nDPI/example/ndpiReader ]] \
        && NDPI_BIN="/tmp/nDPI/example/ndpiReader"
    [[ -z "$NDPI_BIN" && -x /tmp/ndpi-bin/ndpiReader ]] \
        && NDPI_BIN="/tmp/ndpi-bin/ndpiReader"

    if [[ -n "$NDPI_BIN" ]]; then
        NDPI_OUTPUT=$("$NDPI_BIN" -i /tmp/ndpi_compat.pcap -v2 2>&1) || true
        echo "$NDPI_OUTPUT" | sed 's/^/  /'
        echo "$NDPI_OUTPUT" > /tmp/ndpi-compat-report.txt

        if [[ -n "$NDPI_EXPECT" ]]; then
            if echo "$NDPI_OUTPUT" | grep -qi "$NDPI_EXPECT"; then
                ok "nDPI classified traffic as ${NDPI_EXPECT}"
                NDPI_RESULT="PASS"
            else
                fail "nDPI did NOT classify as ${NDPI_EXPECT}"
                NDPI_RESULT="FAIL"
            fi
        else
            ok "Mode '${OBFS_MODE}' — no specific protocol expected"
            NDPI_RESULT="PASS"
        fi

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
        warn "ndpiReader not found — skipping DPI analysis (pcap at /tmp/ndpi_compat.pcap)"
        NDPI_RESULT="SKIP"
        NDPI_RISK="SKIP"
    fi
else
    warn "No pcap captured (${PCAP_SIZE} bytes) — skipping nDPI"
fi

# ── Summary ───────────────────────────────────────────────────────
step "Test Summary"
echo ""
echo -e "  Scenario          : ${BOLD}${SCENARIO}${NC}  (relay=${RELAY_TAG}, server=${SERVER_TAG})"
echo -e "  Obfuscation mode  : ${BOLD}${OBFS_MODE}${NC}"
echo -e "  GUT ports         : ${GUT_PORTS}"
echo -e "  WireGuard MTU     : ${WG_MTU}"
echo ""
echo "  Network layout:"
echo "    net_client ${NET_CLIENT_SUBNET}: client(${CLIENT_IP}), relay(${RELAY_IP}), ndpi(${NDPI_CLIENT_IP})"
echo "    net_server ${NET_SERVER_SUBNET}: ndpi(${NDPI_SERVER_IP}), server(${SERVER_IP})"
echo ""

for name in gutd_server gutd_relay ndpi_router; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$name" 2>/dev/null || echo "gone")
    [[ "$STATE" == "running" ]] && ok "$name: running" || fail "$name: $STATE"
done

echo ""
[[ $PING_OK -eq 1 ]] \
    && ok  "WG ping through GUT tunnel: PASS" \
    || fail "WG ping through GUT tunnel: FAIL"
echo "  TCP upload   : ${IPERF_TCP_UP:-N/A}  retr=${IPERF_TCP_UP_RETR:-N/A}"
echo "  TCP download : ${IPERF_TCP_DN:-N/A}  retr=${IPERF_TCP_DN_RETR:-N/A}"
echo "  UDP upload   : ${IPERF_UDP_UP:-N/A}  loss=${IPERF_UDP_LOSS_UP:-N/A}"
echo "  UDP download : ${IPERF_UDP_DN:-N/A}  loss=${IPERF_UDP_LOSS_DN:-N/A}"
echo "  nDPI result  : ${NDPI_RESULT}  (expect: ${NDPI_EXPECT:-any})"
echo "  nDPI risks   : ${NDPI_RISK}"
echo ""

# ── CI mode: GitHub Step Summary + exit code ──────────────────────
if [[ $CI_MODE -eq 1 ]]; then
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "## Compat Test — \`${SCENARIO}\` / \`${OBFS_MODE}\`"
            echo ""
            echo "| | |"
            echo "|---|---|"
            echo "| Scenario | ${SCENARIO} (relay=${RELAY_TAG}, server=${SERVER_TAG}) |"
            echo "| Obfs mode | ${OBFS_MODE} |"
            echo "| WG handshake | $([ $WG_READY -eq 1 ] && echo 'PASS ✓' || echo 'FAIL ✗') |"
            echo "| WG ping | $([ $PING_OK -eq 1 ] && echo 'PASS' || echo 'FAIL') |"
            echo "| TCP upload | ${IPERF_TCP_UP:-N/A} retr=${IPERF_TCP_UP_RETR:-N/A} |"
            echo "| TCP download | ${IPERF_TCP_DN:-N/A} retr=${IPERF_TCP_DN_RETR:-N/A} |"
            echo "| UDP upload | ${IPERF_UDP_UP:-N/A} loss=${IPERF_UDP_LOSS_UP:-N/A} |"
            echo "| UDP download | ${IPERF_UDP_DN:-N/A} loss=${IPERF_UDP_LOSS_DN:-N/A} |"
            echo "| nDPI (expect: ${NDPI_EXPECT:-any}) | ${NDPI_RESULT} |"
            echo "| nDPI risk flags | ${NDPI_RISK} |"
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
    log "Containers running.  Inspect:"
    log "  docker exec wg_client wg show"
    log "  docker exec gutd_relay  ip addr; iptables -t nat -L -n -v"
    log "  docker logs gutd_relay"
    log "  docker logs gutd_server"
    log "Press Ctrl-C to tear down."
    trap cleanup EXIT
    wait 2>/dev/null || read -r -p ""
else
    log "Tearing down (pass --keep to leave containers)."
fi
