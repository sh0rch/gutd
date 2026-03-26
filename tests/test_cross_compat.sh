#!/bin/bash
# test_cross_compat.sh
# Tests cross-compatibility between Userspace and eBPF implementations in SIP mode.
# Usage: sudo ./test_cross_compat.sh [server_type] [client_type]
# server_type/client_type can be 'ebpf' or 'userspace'
set -e

SERVER_TYPE="${1:-ebpf}"
CLIENT_TYPE="${2:-userspace}"
OBFS_MODE="sip"
WG_MTU="500" # Safe MTU for SIP Base64

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/release/gutd}"
GUTD_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
SNI_DOMAIN="voip.example.com"

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

cleanup() {
    log "Cleaning up..."
    ip netns del gut_client 2>/dev/null || true
    ip netns del gut_server 2>/dev/null || true
    killall gutd 2>/dev/null || true
}
trap "cleanup" EXIT
cleanup

log "Setting up namespaces (Server: $SERVER_TYPE, Client: $CLIENT_TYPE)..."
ip netns add gut_client
ip netns add gut_server

ip link add veth_c type veth peer name veth_s
ip link set veth_c netns gut_client
ip link set veth_s netns gut_server

ip netns exec gut_client ip addr add 10.0.0.1/24 dev veth_c
ip netns exec gut_client ip link set veth_c up
ip netns exec gut_client ip link set lo up

ip netns exec gut_server ip addr add 10.0.0.2/24 dev veth_s
ip netns exec gut_server ip link set veth_s up
ip netns exec gut_server ip link set lo up

# Define target ports for SIP
GUTD_PORTS="5060,10000,10001,10002"

# Helper to generate config
gen_config() {
    local type=$1
    local role=$2 # true/false for responder
    local bind_ip=$3
    local peer_ip=$4
    local nic=$5
    
    if [ "$type" = "userspace" ]; then
        cat <<EOF
[global]
stats_interval = 1
userspace_only = true

[peer]
name = gut0
bind_ip = 0.0.0.0
peer_ip = $peer_ip
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = $role
wg_host = 127.0.0.1:51820
bind_port = $( [ "$role" = "true" ] && echo "51821" || echo "0" )
EOF
    else
        cat <<EOF
[global]
stats_interval = 1

[peer]
name = gut0
nic = $nic
address = $( [ "$role" = "true" ] && echo "10.99.0.2/30" || echo "10.99.0.1/30" )
bind_ip = $bind_ip
peer_ip = $peer_ip
ports = $GUTD_PORTS
key = $GUTD_KEY
obfs = $OBFS_MODE
sni = $SNI_DOMAIN
responder = $role
EOF
    fi
}

log "Generating configs..."
gen_config "$SERVER_TYPE" "true" "10.0.0.2" "10.0.0.1" "veth_s" > /tmp/gutd_s.conf
gen_config "$CLIENT_TYPE" "false" "10.0.0.1" "10.0.0.2" "veth_c" > /tmp/gutd_c.conf

log "Starting Gutd Server ($SERVER_TYPE)..."
ip netns exec gut_server $GUTD_BINARY -c /tmp/gutd_s.conf > /tmp/gutd_s.log 2>&1 &
sleep 2

log "Starting Gutd Client ($CLIENT_TYPE)..."
ip netns exec gut_client $GUTD_BINARY -c /tmp/gutd_c.conf > /tmp/gutd_c.log 2>&1 &
sleep 2

# WireGuard Setup
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

log "Configuring WireGuard over Gut..."
# Server WG
ip netns exec gut_server ip link add wg0 type wireguard
ip netns exec gut_server ip addr add 10.10.0.2/24 dev wg0
ip netns exec gut_server ip link set mtu $WG_MTU dev wg0
ip netns exec gut_server wg set wg0 private-key <(echo "$SERVER_PRIV") listen-port 51820 peer "$CLIENT_PUB" allowed-ips 10.10.0.1/32
ip netns exec gut_server ip link set wg0 up

# Client WG
ip netns exec gut_client ip link add wg0 type wireguard
ip netns exec gut_client ip addr add 10.10.0.1/24 dev wg0
ip netns exec gut_client ip link set mtu $WG_MTU dev wg0

if [ "$CLIENT_TYPE" = "userspace" ]; then
    ENDPOINT="127.0.0.1:41001"
else
    ENDPOINT="10.99.0.2:51820"
fi

ip netns exec gut_client wg set wg0 private-key <(echo "$CLIENT_PRIV") peer "$SERVER_PUB" allowed-ips 10.10.0.2/32 endpoint $ENDPOINT persistent-keepalive 10
ip netns exec gut_client ip link set wg0 up

log "Waiting for handshake..."
sleep 5

log "Testing connectivity (Ping 10.10.0.2)..."
if ip netns exec gut_client ping -c 3 10.10.0.2; then
    log "PING SUCCESSFUL!"
else
    log "PING FAILED!"
    echo "--- Server Log ---"
    tail -n 20 /tmp/gutd_s.log
    echo "--- Client Log ---"
    tail -n 20 /tmp/gutd_c.log
    exit 1
fi

log "Testing large packet (RTP emulation via ping -s 400)..."
if ip netns exec gut_client ping -c 3 -s 400 10.10.0.2; then
    log "LARGE PACKET SUCCESSFUL!"
else
    err "LARGE PACKET FAILED (Possible RTP hang issue persist)"
fi

log "CROSS-COMPATIBILITY TEST PASSED ($SERVER_TYPE -> $CLIENT_TYPE)"
