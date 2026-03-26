#!/bin/bash
#set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/release/gutd}"
PCAP_FILE="/tmp/gutd_ndpi.pcap"
NDPI_DIR="/tmp/nDPI"
OBFS_MODE="${GUTD_OBFS:-sip}" # 'quic', 'gost', 'sip', 'syslog'
SNI_DOMAIN="${GUTD_SNI:-example.com}"
# For syslog mode, use a different default service name
if [[ "${OBFS_MODE}" == "syslog" ]]; then
    SNI_DOMAIN="${GUTD_SERVICE_NAME:-${GUTD_SNI:-asterisk}}"
fi
GUTD_US="${GUTD_US:-true}"
# Syslog expands entire payload via base64 — reduce WG MTU to avoid fragmentation.
# SIP uses RTP (raw GOST, no base64) for data — can use normal MTU.
if [[ "${OBFS_MODE}" == "syslog" ]]; then
    WG_MTU="${WG_MTU:-500}"
else
    WG_MTU="${WG_MTU:-1420}"
fi

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
    apt-get install -y tcpdump iptables iperf3 wireguard wireguard-tools iproute2 libnuma-dev librrd-dev libpcap-dev libtool-bin autoconf automake make gcc pkg-config
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
    ip netns exec ndpi_client ip link del gut0 2>/dev/null || true
    ip netns exec ndpi_server ip link del gut0 2>/dev/null || true
    ip netns del ndpi_client 2>/dev/null || true
    ip netns del ndpi_server 2>/dev/null || true
    kill $(jobs -p) 2>/dev/null || true
    rm -f /tmp/gutd_c.conf /tmp/gutd_s.conf
}
trap "cleanup" EXIT
cleanup

log "Setting up network namespaces..."
ip netns add ndpi_client
ip netns add ndpi_server

ip link add veth_c type veth peer name veth_s
ip link set veth_c netns ndpi_client
ip link set veth_s netns ndpi_server

# Disable offloads to ensure BPF sees individual segments at the set MTU
ip netns exec ndpi_client ethtool -K veth_c gso off gro off tso off
ip netns exec ndpi_server ethtool -K veth_s gso off gro off tso off

ip netns exec ndpi_client ip addr add 10.0.0.1/24 dev veth_c
ip netns exec ndpi_client ip link set veth_c up
ip netns exec ndpi_client ip link set lo up

ip netns exec ndpi_server ip addr add 10.0.0.2/24 dev veth_s
ip netns exec ndpi_server ip link set veth_s up
ip netns exec ndpi_server ip link set lo up

# Define target ports based on obfuscation mode
case "$OBFS_MODE" in
    "gost")
        GUTD_PORTS="2046"
        ;;
    "sip")
        GUTD_PORTS="5060, $(seq -s, 10000 10005)"
        ;;
    "syslog")
        GUTD_PORTS="514"
        ;;
    "quic")
        GUTD_PORTS="443"
        ;;
    *)
        GUTD_PORTS="55777"
        ;;
esac

log "Configuring gutd (mode: ${GUTD_US}=userspace)..."
if [ "$GUTD_US" = "true" ]; then
    cat <<EOF > /tmp/gutd_s.conf
[global]
stats_interval = 0
userspace_only = ${GUTD_US}

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 10.0.0.1
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = true
wg_host = 127.0.0.1:51820
bind_port = 51821
EOF
    cat <<EOF > /tmp/gutd_c.conf
[global]
stats_interval = 0
userspace_only = ${GUTD_US}

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = 10.0.0.2
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = false
wg_host = 127.0.0.1:41001
EOF
else
    cat <<EOF > /tmp/gutd_s.conf
[global]
stats_interval = 0

[peer]
name = gut0
nic = veth_s
address = 10.99.0.2/30
bind_ip = 10.0.0.2
peer_ip = 10.0.0.1
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = true
EOF
    cat <<EOF > /tmp/gutd_c.conf
[global]
stats_interval = 0

[peer]
name = gut0
nic = veth_c
address = 10.99.0.1/30
bind_ip = 10.0.0.1
peer_ip = 10.0.0.2
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = false
EOF
fi

log "Starting gutd..."
ip netns exec ndpi_server $GUTD_BINARY -c /tmp/gutd_s.conf > /tmp/gutd_s.log 2>&1 &
GUTD_S_PID=$!
sleep 1

ip netns exec ndpi_client $GUTD_BINARY -c /tmp/gutd_c.conf > /tmp/gutd_c.log 2>&1 &
GUTD_C_PID=$!
sleep 1

if [ "$GUTD_US" != "true" ]; then
    log "Waiting for gut eBPF interfaces..."
    for i in $(seq 1 20); do
        if ip netns exec ndpi_server ip link show gut0 >/dev/null 2>&1 && \
           ip netns exec ndpi_client ip link show gut0 >/dev/null 2>&1; then
            log "gut interfaces ready"
            break
        fi
        sleep 1
    done
    ip netns exec ndpi_server ip link show gut0 >/dev/null 2>&1 || err "gut0 not created in ndpi_server"
    ip netns exec ndpi_client ip link show gut0 >/dev/null 2>&1 || err "gut0 not created in ndpi_client"
fi

log "Configuring WireGuard..."

log "Starting packet capture..."
rm -f $PCAP_FILE
# Capture only UDP on ports 5060 (SIP) and 10000-11000 (RTP) + ICMP for debugging
ip netns exec ndpi_client tcpdump -i veth_c -w $PCAP_FILE -s 0 -n > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

ip netns exec ndpi_server ip link add wg0 type wireguard
ip netns exec ndpi_server ip addr add 10.10.0.2/24 dev wg0
# Low MTU for GOST fragmentation evasion
ip netns exec ndpi_server ip link set mtu $WG_MTU dev wg0
ip netns exec ndpi_server wg set wg0 private-key <(echo "$SERVER_PRIV") listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.10.0.1/32
ip netns exec ndpi_server ip link set wg0 up

ip netns exec ndpi_client ip link add wg0 type wireguard
ip netns exec ndpi_client ip addr add 10.10.0.1/24 dev wg0
ip netns exec ndpi_client ip link set mtu $WG_MTU dev wg0
if [ "$GUTD_US" = "true" ]; then
    WG_ENDPOINT="127.0.0.1:41001"
else
    WG_ENDPOINT="10.99.0.2:51820"
fi
ip netns exec ndpi_client wg set wg0 private-key <(echo "$CLIENT_PRIV") listen-port 51820 peer "$SERVER_PUB" allowed-ips 10.10.0.2/32 endpoint $WG_ENDPOINT persistent-keepalive 25
ip netns exec ndpi_client ip link set wg0 up

# Ping test to bring up tunnel
log "Testing WireGuard tunnel connectivity..."
ip netns exec ndpi_client ping -c 3 10.10.0.2 > /dev/null || err "WG Ping failed"

log "Starting iperf3 server..."
ip netns exec ndpi_server iperf3 -s -D

log "Generating ~1000MB traffic via iperf3..."
ip netns exec ndpi_client iperf3 -c 10.10.0.2 -n 1000M -Z > /dev/null


log "Stopping packet capture..."
kill $TCPDUMP_PID
sleep 1

log "Running ndpiReader analysis..."
RESULTS_FILE="/tmp/ndpi_results.txt"
ndpiReader -v2 -i $PCAP_FILE > $RESULTS_FILE

echo ""
echo "=== nDPI classification (mode: ${OBFS_MODE}) ==="
cat $RESULTS_FILE

# Verify nDPI classified traffic as the expected protocol
case "$OBFS_MODE" in
    quic)   EXPECT="QUIC" ;;
    sip)    EXPECT="SIP" ;;
    syslog) EXPECT="Syslog" ;;
    gost)   EXPECT="" ;;  # random UDP, no specific protocol expected
esac

if [ -n "$EXPECT" ]; then
    grep -qi "$EXPECT" "$RESULTS_FILE" || err "nDPI did not classify traffic as $EXPECT"
fi
