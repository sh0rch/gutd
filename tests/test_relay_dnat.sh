#!/bin/bash
set -e

# Integration test: WireGuard relay with DNAT + MASQUERADE (production-like)
#
# Topology:
#   relay_ns (WG client, wg0)
#       veth_relay 10.100.1.1/24
#           |
#   server_ns (gutd relay, gut0 10.254.0.1/30)
#       veth_server 10.100.1.2/24        ← "eth0" (client-facing)
#       veth_srv    10.100.2.2/24        ← "eth1" (server-facing)
#           |
#   host (gutd server, gut1 10.254.0.2/30, WG server wg_srv)
#       veth_host   10.100.2.1/24
#
# NAT on server_ns (matches production):
#   PREROUTING:  -i veth_server -p udp --dport 5050 -j DNAT --to-destination 10.254.0.2
#   POSTROUTING: -o veth_server -j MASQUERADE  (reply to client)
#   POSTROUTING: -o veth_srv    -j MASQUERADE  (traffic to GUT server)
#   POSTROUTING: -o gut0        -j MASQUERADE  (traffic into GUT tunnel)
#
# WG client endpoint: 10.100.1.2:5050 (relay's client-facing IP)
# WG server ListenPort: 5050

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/musl/gutd}"
GUT_PORTS_CSV="${GUT_PORTS_CSV:-41000,41001}"
WG_MTU="${WG_MTU:-1420}"
WG_PORT="${WG_PORT:-5050}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"; }
error(){ echo -e "${RED}[ERROR]${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

cleanup() {
    log "Cleaning up..."
    [ -n "${GUTD_RELAY_PID:-}" ]  && kill "$GUTD_RELAY_PID"  2>/dev/null || true
    [ -n "${GUTD_SERVER_PID:-}" ] && kill "$GUTD_SERVER_PID" 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true

    ip netns exec relay_ns ip link del wg0 2>/dev/null || true
    ip link del wg_srv 2>/dev/null || true
    ip link del gut1 2>/dev/null || true
    ip link del veth_host 2>/dev/null || true
    ip route del 10.100.1.0/24 via 10.100.2.2 2>/dev/null || true

    ip netns del relay_ns  2>/dev/null || true
    ip netns del server_ns 2>/dev/null || true
    log "Cleanup complete"
}
trap cleanup EXIT

# ── Check deps ────────────────────────────────────────────────────
for cmd in ip wg iperf3 tcpdump; do
    command -v "$cmd" &>/dev/null || { error "Missing: $cmd"; exit 1; }
done
[ -f "$GUTD_BINARY" ] || { error "gutd binary not found: $GUTD_BINARY"; exit 1; }

# ── Keys ──────────────────────────────────────────────────────────
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
GUTD_SHARED_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)

# ── Namespaces & veths ────────────────────────────────────────────
log "Setting up namespaces..."
ip netns del relay_ns 2>/dev/null || true
ip netns del server_ns 2>/dev/null || true
ip link del veth_host 2>/dev/null || true

ip netns add relay_ns
ip netns add server_ns

# relay_ns ↔ server_ns
ip link add veth_relay type veth peer name veth_server
ip link set veth_relay  netns relay_ns
ip link set veth_server netns server_ns

ip netns exec relay_ns  ip addr add 10.100.1.1/24 dev veth_relay
ip netns exec relay_ns  ip link set veth_relay up
ip netns exec relay_ns  ip link set lo up

ip netns exec server_ns ip addr add 10.100.1.2/24 dev veth_server
ip netns exec server_ns ip link set veth_server up
ip netns exec server_ns ip link set lo up

# server_ns ↔ host
ip link add veth_host type veth peer name veth_srv
ip link set veth_srv netns server_ns
ip addr add 10.100.2.1/24 dev veth_host
ip link set veth_host up

ip netns exec server_ns ip addr add 10.100.2.2/24 dev veth_srv
ip netns exec server_ns ip link set veth_srv up

# Routing
ip netns exec relay_ns  ip route add default via 10.100.1.2
ip netns exec server_ns ip route add default via 10.100.2.1
ip route replace 10.100.1.0/24 via 10.100.2.2

ip netns exec server_ns sysctl -w net.ipv4.ip_forward=1 > /dev/null
sysctl -w net.ipv4.ip_forward=1 > /dev/null

log "Namespaces ready"

# ── gutd ──────────────────────────────────────────────────────────
log "Starting gutd..."

cat > /tmp/gutd-relay-dnat.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
nic = veth_srv
mtu = 1420
address = 10.254.0.1/30
bind_ip = 10.100.2.2
peer_ip = 10.100.2.1
ports = $GUT_PORTS_CSV
keepalive_drop_percent = 75
key = $GUTD_SHARED_KEY
EOF

cat > /tmp/gutd-server-dnat.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut1
nic = veth_host
mtu = 1420
address = 10.254.0.2/30
bind_ip = 10.100.2.1
peer_ip = 10.100.2.2
ports = $GUT_PORTS_CSV
keepalive_drop_percent = 75
key = $GUTD_SHARED_KEY
EOF

"$GUTD_BINARY" --config /tmp/gutd-server-dnat.conf > /tmp/gutd-dnat-server.log 2>&1 &
GUTD_SERVER_PID=$!
sleep 2
kill -0 $GUTD_SERVER_PID 2>/dev/null || { error "gutd server died"; cat /tmp/gutd-dnat-server.log >&2; exit 1; }

ip netns exec server_ns "$GUTD_BINARY" --config /tmp/gutd-relay-dnat.conf > /tmp/gutd-dnat-relay.log 2>&1 &
GUTD_RELAY_PID=$!
sleep 2
kill -0 $GUTD_RELAY_PID 2>/dev/null || { error "gutd relay died"; cat /tmp/gutd-dnat-relay.log >&2; exit 1; }

log "gutd tunnel up"
echo "=== server log ===" >&2; head -20 /tmp/gutd-dnat-server.log >&2
echo "=== relay log ===" >&2;  head -20 /tmp/gutd-dnat-relay.log >&2

# ── iptables — production-like DNAT + MASQUERADE ──────────────────
log "Setting up iptables (DNAT + MASQUERADE)..."

# DNAT: relay_ns sends WG to server_ns:5050 → forward to gut0 peer (10.254.0.2)
ip netns exec server_ns iptables -t nat -A PREROUTING \
    -i veth_server -p udp --dport "$WG_PORT" \
    -j DNAT --to-destination 10.254.0.2

# MASQUERADE on all egress interfaces (exactly like production)
ip netns exec server_ns iptables -t nat -A POSTROUTING -o veth_server -j MASQUERADE
ip netns exec server_ns iptables -t nat -A POSTROUTING -o veth_srv    -j MASQUERADE
ip netns exec server_ns iptables -t nat -A POSTROUTING -o gut0        -j MASQUERADE

# FORWARD rules
ip netns exec server_ns iptables -A FORWARD \
    -i veth_server -o gut0 -p udp --dport "$WG_PORT" -j ACCEPT
ip netns exec server_ns iptables -A FORWARD \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

log "iptables set"
ip netns exec server_ns iptables -t nat -L -n -v >&2
ip netns exec server_ns iptables -L FORWARD -n -v >&2

# ── WireGuard ─────────────────────────────────────────────────────
log "Setting up WireGuard (client → relay DNAT → server)..."

# WG client: endpoint = relay's client-facing IP : WG_PORT
ip netns exec relay_ns ip link add wg0 type wireguard
ip netns exec relay_ns ip addr add 10.200.0.1/24 dev wg0
ip netns exec relay_ns ip link set wg0 mtu "$WG_MTU"

cat > /tmp/wg-client-dnat.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
ListenPort = 51820

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 10.100.1.2:$WG_PORT
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 25
EOF
ip netns exec relay_ns wg setconf wg0 /tmp/wg-client-dnat.conf
ip netns exec relay_ns ip link set wg0 up

# WG server: listens on WG_PORT on gut1 (10.254.0.2)
ip link add wg_srv type wireguard
ip addr add 10.200.0.2/24 dev wg_srv
ip link set wg_srv mtu "$WG_MTU"

cat > /tmp/wg-server-dnat.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = $WG_PORT

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.0.1/32
EOF
wg setconf wg_srv /tmp/wg-server-dnat.conf
ip link set wg_srv up

sleep 3

# ── Diagnostics ───────────────────────────────────────────────────
log "=== WireGuard status ==="
echo "Client:" >&2; ip netns exec relay_ns wg show wg0 >&2
echo "Server:" >&2; wg show wg_srv >&2

# ── Connectivity tests ────────────────────────────────────────────
log "Testing WG ping..."
if ip netns exec relay_ns ping -c 3 -W 2 10.200.0.2 > /dev/null 2>&1; then
    log "[ok] WG ping works"
else
    error "[FAIL] WG ping failed"
    ip netns exec relay_ns ping -c 3 10.200.0.2 >&2 || true

    log "=== Diagnostics ==="
    echo "conntrack:" >&2
    ip netns exec server_ns conntrack -L 2>/dev/null | head -20 >&2 || true
    echo "gut0 tcpdump:" >&2
    timeout 5 ip netns exec server_ns tcpdump -i gut0 -n -c 5 udp 2>&1 | head -10 >&2 || true
    exit 1
fi

# ── iperf3 throughput ─────────────────────────────────────────────
log "Testing iperf3 throughput..."
iperf3 -s -B 10.200.0.2 -p 5201 -D > /tmp/iperf3-dnat-server.log 2>&1
sleep 1

result_json=$(timeout 25 ip netns exec relay_ns iperf3 -c 10.200.0.2 -p 5201 -t 5 --connect-timeout 5000 -J 2>&1) || true

if [ -z "${result_json:-}" ] || ! echo "$result_json" | jq . >/dev/null 2>&1; then
    warn "iperf3 failed; raw output:"
    echo "$result_json" >&2
    result_json='{"end":{"sum_received":{"bits_per_second":0},"sum_sent":{"retransmits":0}}}'
fi

throughput=$(echo "$result_json" | jq -r '.end.sum_received.bits_per_second // 0')
retransmits=$(echo "$result_json" | jq -r '.end.sum_sent.retransmits // 0')
throughput_mbps=$(echo "scale=2; $throughput / 1000000" | bc)

log "Throughput: ${throughput_mbps} Mbps (retransmits: $retransmits)"

pkill -x iperf3 2>/dev/null || true

# ── Extended diagnostics if throughput is low ─────────────────────
if [ "$(echo "$throughput_mbps < 10" | bc)" = "1" ]; then
    error "Throughput critically low: ${throughput_mbps} Mbps"

    log "=== Extended diagnostics ==="

    echo "--- conntrack entries ---" >&2
    ip netns exec server_ns conntrack -L 2>/dev/null | head -30 >&2 || true

    echo "--- iptables counters ---" >&2
    ip netns exec server_ns iptables -t nat -L -n -v >&2
    ip netns exec server_ns iptables -L FORWARD -n -v >&2

    echo "--- interface stats ---" >&2
    echo "gut0:" >&2;       ip netns exec server_ns ip -s link show gut0 >&2
    echo "veth_server:" >&2; ip netns exec server_ns ip -s link show veth_server >&2
    echo "veth_srv:" >&2;    ip netns exec server_ns ip -s link show veth_srv >&2
    echo "gut1:" >&2;        ip -s link show gut1 >&2
    echo "veth_host:" >&2;   ip -s link show veth_host >&2
    echo "wg_srv:" >&2;      ip -s link show wg_srv >&2

    echo "--- gutd BPF stats ---" >&2
    kill -USR1 $GUTD_SERVER_PID 2>/dev/null || true
    kill -USR1 $GUTD_RELAY_PID  2>/dev/null || true
    sleep 1
    echo "Server:" >&2; tail -15 /tmp/gutd-dnat-server.log >&2
    echo "Relay:" >&2;  tail -15 /tmp/gutd-dnat-relay.log >&2

    echo "--- gut0 tcpdump (5 pkts) ---" >&2
    timeout 5 ip netns exec server_ns tcpdump -i gut0 -n -c 5 2>&1 | head -10 >&2 || true

    echo "--- veth_srv tcpdump (5 pkts, GUT ports) ---" >&2
    timeout 5 ip netns exec server_ns tcpdump -i veth_srv -n -c 5 udp 2>&1 | head -10 >&2 || true

    exit 1
fi

# ── BPF stats ─────────────────────────────────────────────────────
kill -USR1 $GUTD_SERVER_PID 2>/dev/null || true
kill -USR1 $GUTD_RELAY_PID  2>/dev/null || true
sleep 1

log "=== Final BPF stats ==="
echo "Server:" >&2; grep -A 5 "Statistics" /tmp/gutd-dnat-server.log | tail -10 >&2 || true
echo "Relay:" >&2;  grep -A 5 "Statistics" /tmp/gutd-dnat-relay.log | tail -10 >&2 || true

log "RELAY DNAT TEST PASSED: ${throughput_mbps} Mbps"
