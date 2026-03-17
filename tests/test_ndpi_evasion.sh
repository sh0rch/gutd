#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/debug/gutd}"
PCAP_FILE="/tmp/gutd_ndpi.pcap"
NDPI_DIR="/tmp/nDPI"
OBFS_MODE="${GUTD_OBFS:-sip}" # 'quic' or 'gost'/'noise'

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[*]${NC} $1"; }
err() { echo -e "${RED}[!]${NC} $1" >&2; exit 1; }

if [ "$EUID" -ne 0 ]; then
    err "Please run as root"
fi

if command -v apt-get &> /dev/null; then
    log "Installing required dependencies..."
    apt-get update && apt-get install -y tcpdump iptables iperf3 wireguard wireguard-tools iproute2 libnuma-dev librrd-dev libpcap-dev libtool-bin autoconf automake make gcc pkg-config
fi

# Ensure required tools
for cmd in ip wg iperf3 tcpdump make gcc autoconf automake libtool pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        err "$cmd could not be found, please install it."
    fi
done

# Ensure nDPI is installed or build it
if ! command -v ndpiReader &> /dev/null; then
    if [ ! -f "$NDPI_DIR/example/ndpiReader" ]; then
        log "ndpiReader not found. Building nDPI from source..."
        rm -rf $NDPI_DIR
        git clone --depth 1 https://github.com/ntop/nDPI.git $NDPI_DIR
        cd $NDPI_DIR
        ./autogen.sh
        ./configure
        make -j$(nproc)
        cd -
    fi
    export PATH="$NDPI_DIR/example:$PATH"
fi

if ! command -v ndpiReader &> /dev/null; then
    err "Failed to install/find ndpiReader"
fi

# Generate Keys
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
GUTD_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)

cleanup() {
    log "Cleaning up namespaces and processes..."
    ip netns del ndpi_client 2>/dev/null || true
    ip netns del ndpi_server 2>/dev/null || true
    kill $(jobs -p) 2>/dev/null || true
    rm -f /tmp/gutd_c.conf /tmp/gutd_s.conf
}
trap cleanup EXIT
cleanup

log "Setting up network namespaces..."
ip netns add ndpi_client
ip netns add ndpi_server

ip link add veth_c type veth peer name veth_s
ip link set veth_c netns ndpi_client
ip link set veth_s netns ndpi_server

ip netns exec ndpi_client ip addr add 10.0.0.1/24 dev veth_c
ip netns exec ndpi_client ip link set veth_c up
ip netns exec ndpi_client ip link set lo up

ip netns exec ndpi_server ip addr add 10.0.0.2/24 dev veth_s
ip netns exec ndpi_server ip link set veth_s up
ip netns exec ndpi_server ip link set lo up

RTP_PORTS=$(seq -s, 10000 11000)

log "Configuring gutd server..."
cat <<EOF > /tmp/gutd_s.conf
[global]
stats_interval = 0
userspace_only = true

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 10.0.0.1
ports = 5060, $RTP_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sip_domain = example.com
responder = true
wg_host = 127.0.0.1:51820
EOF

log "Configuring gutd client..."
cat <<EOF > /tmp/gutd_c.conf
[global]
stats_interval = 0
userspace_only = true

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 10.0.0.2
ports = 5060, $RTP_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sip_domain = example.com
responder = false
wg_host = 127.0.0.1:41001
EOF

log "Starting gutd..."
ip netns exec ndpi_server $GUTD_BINARY -c /tmp/gutd_s.conf > /tmp/gutd_s.log 2>&1 &
GUTD_S_PID=$!
sleep 1

ip netns exec ndpi_client $GUTD_BINARY -c /tmp/gutd_c.conf > /tmp/gutd_c.log 2>&1 &
GUTD_C_PID=$!
sleep 1

log "Configuring WireGuard..."

log "Starting packet capture..."
rm -f $PCAP_FILE
# Capture only UDP on ports 5060 (SIP) and 10000-11000 (RTP) + ICMP for debugging
ip netns exec ndpi_client tcpdump -i veth_c -w $PCAP_FILE -s 0 -n "udp portrange 5060-11000 or icmp" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

ip netns exec ndpi_server ip link add wg0 type wireguard
ip netns exec ndpi_server ip addr add 10.10.0.2/24 dev wg0
# Low MTU for GOST fragmentation evasion
ip netns exec ndpi_server ip link set mtu 500 dev wg0
ip netns exec ndpi_server wg set wg0 private-key <(echo "$SERVER_PRIV") listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.10.0.1/32
ip netns exec ndpi_server ip link set wg0 up

ip netns exec ndpi_client ip link add wg0 type wireguard
ip netns exec ndpi_client ip addr add 10.10.0.1/24 dev wg0
ip netns exec ndpi_client ip link set mtu 500 dev wg0
ip netns exec ndpi_client wg set wg0 private-key <(echo "$CLIENT_PRIV") listen-port 51820 peer "$SERVER_PUB" allowed-ips 10.10.0.2/32 endpoint 127.0.0.1:41001 persistent-keepalive 25
ip netns exec ndpi_client ip link set wg0 up

# Ping test to bring up tunnel
log "Testing WireGuard tunnel connectivity..."
ip netns exec ndpi_client ping -c 3 10.10.0.2 > /dev/null || err "WG Ping failed"

log "Starting iperf3 server..."
ip netns exec ndpi_server iperf3 -s -D

log "Generating ~200MB traffic via iperf3..."
ip netns exec ndpi_client iperf3 -c 10.10.0.2 -n 200M -Z > /dev/null


log "Stopping packet capture..."
kill $TCPDUMP_PID
sleep 1

log "Running ndpiReader analysis..."
RESULTS_FILE="/tmp/ndpi_results.txt"
ndpiReader -i $PCAP_FILE > $RESULTS_FILE

echo ""
echo "=== FULL nDPI REPORT ==="
cat $RESULTS_FILE

if grep -qi "WireGuard" $RESULTS_FILE; then
    err "nDPI successfully DETECTED WireGuard traffic! (Evasion failed)"
else
    log "Success: nDPI did NOT detect WireGuard in the pcap (Evasion successful)."
fi

exit 0
