#!/bin/bash
set -e

# Integration test: WireGuard + gutd relay with iperf3 and packet capture
# Architecture:
#   relay_ns (WG client) -> server_ns (gutd relay) -> host (gutd server + WG server)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/musl/gutd}"
RESULTS_FILE="${RESULTS_FILE:-/tmp/gutd-test-results.txt}"
GUTD_OBFS="${GUTD_OBFS:-quic}"

# Per-mode default ports (override via GUT_PORTS_CSV):
#   quic   — any UDP port(s)
#   gut   — single random-looking UDP port
#   sip    — ports[0]=SIP signaling, ports[1+]=RTP media (≥2 required)
#   syslog — standard syslog UDP
if [[ -z "${GUT_PORTS_CSV:-}" ]]; then
    case "$GUTD_OBFS" in
        gut)   GUT_PORTS_CSV="2046" ;;
        sip)    GUT_PORTS_CSV="5060,10000,10001" ;;
        syslog) GUT_PORTS_CSV="514" ;;
        b64)    GUT_PORTS_CSV="8080" ;;
        *)      GUT_PORTS_CSV="41000,41001" ;;  # quic / unknown
    esac
fi

# Per-mode SNI / service name (override via GUTD_SNI):
#   quic   — TLS SNI domain in QUIC ClientHello
#   sip    — SIP domain in Via/To/From headers
#   syslog — syslog hostname / service name
#   gut   — unused
if [[ -z "${GUTD_SNI:-}" ]]; then
    case "$GUTD_OBFS" in
        syslog) GUTD_SNI="asterisk" ;;
        sip)    GUTD_SNI="sip.example.com" ;;
        gut)   GUTD_SNI="" ;;
        *)      GUTD_SNI="example.com" ;;  # quic / unknown
    esac
fi

# Per-mode WG MTU (affects both the WireGuard interface MTU and the gutd peer mtu):
#   syslog — base64 expands payload; WG_MTU=800 → wg_len≈832 ≤ GUT_B64_WG_MTU_MAX(886) ✓
#   sip    — RTP(12)+GUT(10)=22 bytes added by BPF; WG_MTU=1400 verified working;
#            WG_MTU=1408+ causes oversized frames on veth (empirically confirmed)
#   quic   — QUIC short header adds 16 bytes; keeps outer packet ≤ 1500, use 1420
#   gut   — GUT adds 10 bytes; keeps outer packet ≤ 1500, use 1420
case "$GUTD_OBFS" in
    syslog) WG_MTU="${WG_MTU:-800}"  ;;
    sip)    WG_MTU="${WG_MTU:-1400}" ;;
    *)      WG_MTU="${WG_MTU:-1420}" ;;
esac

build_udp_port_filter() {
    local csv="$1"
    local out=""
    IFS=',' read -r -a _ports <<< "$csv"
    for p in "${_ports[@]}"; do
        p="$(echo "$p" | xargs)"
        [[ -z "$p" ]] && continue
        if [[ -n "$out" ]]; then
            out+=" or "
        fi
        out+="udp port $p"
    done
    if [[ -z "$out" ]]; then
        out="udp port 41001"
    fi
    echo "$out"
}

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."

    if command -v apt-get &> /dev/null; then
        log "Attempting to install required packages via apt-get..."
        apt-get update && apt-get install -y tcpdump iptables iperf3 wireguard wireguard-tools iproute2
    fi

    local missing=0
    
    for cmd in ip wg iperf3 tcpdump; do
        if ! command -v $cmd &> /dev/null; then
            error "Required command not found: $cmd"
            missing=1
        fi
    done
    
    if [ ! -f "$GUTD_BINARY" ]; then
        error "gutd binary not found: $GUTD_BINARY"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        exit 1
    fi
    
    log "All dependencies satisfied"
}

# Generate WireGuard keys
generate_wg_keys() {
    log "Generating WireGuard keys..."
    
    # Client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # Server keys
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # gutd shared key (64 hex chars = 32 bytes) - MUST be same on both sides!
    GUTD_SHARED_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
    
    log "Keys generated successfully"
}

# Create network namespaces
setup_namespaces() {
    log "Setting up network namespaces..."
    
    # Cleanup existing namespaces
    ip netns del relay_ns 2>/dev/null || true
    ip netns del server_ns 2>/dev/null || true
    ip link del veth_host 2>/dev/null || true
    ip link del wg_srv 2>/dev/null || true
    ip link del gut1 2>/dev/null || true
    
    # Create namespaces
    ip netns add relay_ns
    ip netns add server_ns
    
    # Setup veth pairs: relay_ns <-> server_ns
    ip link add veth_relay type veth peer name veth_server
    ip link set veth_relay netns relay_ns
    ip link set veth_server netns server_ns
    
    # Configure relay_ns (WireGuard client)
    ip netns exec relay_ns ip addr add 10.100.1.1/24 dev veth_relay
    ip netns exec relay_ns ip link set veth_relay up
    ip netns exec relay_ns ip link set lo up
    
    # Configure server_ns (gutd relay)
    ip netns exec server_ns ip addr add 10.100.1.2/24 dev veth_server
    ip netns exec server_ns ip link set veth_server up
    ip netns exec server_ns ip link set lo up
    
    # Setup veth pair: server_ns <-> host
    ip link add veth_host type veth peer name veth_srv
    ip link set veth_srv netns server_ns
    ip addr add 10.100.2.1/24 dev veth_host
    ip link set veth_host up
    
    ip netns exec server_ns ip addr add 10.100.2.2/24 dev veth_srv
    ip netns exec server_ns ip link set veth_srv up

    # Disable segmentation offloads so BPF sees individual segments at the real MTU
    # (mirrors the ndpi test approach; prevents TSO/GSO from inflating effective packet size)
    for ns_cmd in \
        "ip netns exec relay_ns  ethtool -K veth_relay  gso off gro off tso off" \
        "ip netns exec server_ns ethtool -K veth_server gso off gro off tso off" \
        "ip netns exec server_ns ethtool -K veth_srv    gso off gro off tso off" \
        "ethtool -K veth_host gso off gro off tso off"
    do
        $ns_cmd 2>/dev/null || true
    done
    
    # Routing
    ip netns exec relay_ns ip route add default via 10.100.1.2
    ip netns exec server_ns ip route add default via 10.100.2.1
    ip route replace 10.100.1.0/24 via 10.100.2.2
    
    # Enable forwarding
    ip netns exec server_ns sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Block direct WG traffic bypass through server_ns:
    # Without this, relay_ns could reach host WG port directly via server_ns forwarding,
    # making the gutd tunnel unnecessary.  Drop forwarded WG (port 51821) on the transit
    # path so only gut-encapsulated traffic reaches the WG server.
    ip netns exec server_ns iptables -A FORWARD \
        -i veth_server -o veth_srv -p udp --dport 51821 -j DROP
    
    log "Network namespaces configured"
}

# Setup WireGuard baseline (no gutd)
setup_wireguard_baseline() {
    log "Setting up WireGuard baseline (no obfuscation)..."
    
    # WireGuard interface in relay_ns (client)
    ip netns exec relay_ns ip link add wg0 type wireguard
    ip netns exec relay_ns ip addr add 10.200.0.1/24 dev wg0
    
    cat > /tmp/wg-client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
ListenPort = 51820

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 10.100.2.1:51821
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 25
EOF
    
    ip netns exec relay_ns wg setconf wg0 /tmp/wg-client.conf
    ip netns exec relay_ns ip link set wg0 up
    
    # WireGuard interface on host (server)
    ip link add wg_srv type wireguard
    ip addr add 10.200.0.2/24 dev wg_srv
    
    cat > /tmp/wg-server.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = 51821

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.0.1/32
EOF
    
    wg setconf wg_srv /tmp/wg-server.conf
    ip link set wg_srv up
    
    # Wait for WireGuard handshake
    sleep 2
    
    log "WireGuard baseline configured"
}

# Capture packets
capture_packets() {
    local interface=$1
    local output_file=$2
    local count=${3:-5}
    local namespace=${4:-}
    # Optional BPF filter (5th arg); default to plain 'udp'
    local filter="${5:-udp}"

    log "Capturing $count packets on $interface -> $output_file"

    if [ -n "$namespace" ]; then
        timeout 10 ip netns exec "$namespace" tcpdump -i "$interface" -c "$count" -w "$output_file" $filter 2>/dev/null || true
    else
        timeout 10 tcpdump -i "$interface" -c "$count" -w "$output_file" $filter 2>/dev/null || true
    fi
}

# Test WireGuard baseline (no gutd)
test_wireguard_baseline() {
    log "Testing WireGuard baseline (no obfuscation)..."
    
    # Start iperf3 server on host
    iperf3 -s -B 10.200.0.2 -p 5201 -D > /tmp/iperf3-server-baseline.log 2>&1
    sleep 1
    
    # Capture packets: WireGuard on wire
    capture_packets veth_host /tmp/gutd-test-wg-baseline.pcap 5 &
    TCPDUMP_PID=$!
    
    # Run iperf3 test from relay_ns to host
    local throughput
    throughput=$(timeout 20 ip netns exec relay_ns iperf3 -c 10.200.0.2 -p 5201 -t 3 --connect-timeout 3000 -J 2>/tmp/iperf3-baseline.err | \
        jq -r '.end.sum_received.bits_per_second // 0') || true

    if [ -z "${throughput:-}" ] || [ "$throughput" = "null" ]; then
        warn "Baseline iperf3 failed or timed out; forcing throughput=0"
        [ -f /tmp/iperf3-baseline.err ] && cat /tmp/iperf3-baseline.err >&2 || true
        throughput=0
    fi
    
    wait $TCPDUMP_PID 2>/dev/null || true
    
    # Kill iperf3 server
    pkill -x iperf3 || true
    
    local throughput_mbps=$(echo "scale=2; $throughput / 1000000" | bc)
    
    log "WireGuard baseline throughput: ${throughput_mbps} Mbps"
    echo "wireguard_baseline_mbps=$throughput_mbps" >> "$RESULTS_FILE"
    
    # Analyze captured packets
    local packet_count
    packet_count=$(tcpdump -r /tmp/gutd-test-wg-baseline.pcap 2>/dev/null | wc -l)
    log "Captured $packet_count WireGuard packets (baseline)"
    echo "wireguard_baseline_packets=$packet_count" >> "$RESULTS_FILE"
}

# Cleanup WireGuard baseline
cleanup_wireguard_baseline() {
    log "Cleaning up WireGuard baseline..."
    
    ip netns exec relay_ns ip link del wg0 2>/dev/null || true
    ip link del wg_srv 2>/dev/null || true
    pkill -x iperf3 || true
}

# Setup gutd relay + server
setup_gutd() {
    local mode=${1:-ebpf}
    log "Setting up gutd relay and server (mode: $mode)..."
    
    local userspace_line=""
    local relay_responder_line=""
    local server_responder_line=""
    if [ "$mode" = "userspace" ]; then
        userspace_line="userspace_only = true"
        # In userspace mode the relay side hosts the WG client, so it must
        # bind local_socket to wg_addr (responder = false).  The server side
        # hosts the WG server and needs an ephemeral local_socket (responder = true).
        relay_responder_line="responder = false"
        server_responder_line="responder = true"
    fi

    # Optional config lines that vary by obfuscation mode
    local sni_line=""
    [[ -n "${GUTD_SNI:-}" ]] && sni_line="sni = $GUTD_SNI"
    # own_http3: anti-probe handler flag — meaningful for quic (QUIC VerNeg) and sip (SIP 401/403).
    # Other modes have no XDP anti-probe handler so keep it false.
    local own_http3_line="own_http3 = false"
    [[ "$GUTD_OBFS" == "quic" || "$GUTD_OBFS" == "sip" ]] && own_http3_line="own_http3 = true"
    
    # gutd config for relay (in server_ns)
    cat > /tmp/gutd-relay.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0
$userspace_line

[peer]
name = gut0
nic = veth_srv
mtu = $WG_MTU
address = 10.254.0.2/30
bind_ip = 10.100.2.2
peer_ip = 10.100.2.1
ports = $GUT_PORTS_CSV
obfs = $GUTD_OBFS
keepalive_drop_percent = 30
key = $GUTD_SHARED_KEY
$sni_line
$own_http3_line
$relay_responder_line
EOF
    
    # gutd config for server (on host)
    cat > /tmp/gutd-server.conf <<EOF
[global]
outer_mtu = 1500
stats_interval = 0
$userspace_line

[peer]
name = gut1
nic = veth_host
mtu = $WG_MTU
address = 10.254.0.1/30
bind_ip = 10.100.2.1
peer_ip = 10.100.2.2
ports = $GUT_PORTS_CSV
obfs = $GUTD_OBFS
keepalive_drop_percent = 30
key = $GUTD_SHARED_KEY
$sni_line
$own_http3_line
$server_responder_line
EOF
    
    # Start gutd server on host
    # In userspace mode, GUTD_WG_HOST tells the proxy where to forward deobfuscated traffic.
    log "Starting gutd server on host..."
    if [ "$mode" = "userspace" ]; then
        GUTD_WG_HOST=127.0.0.1:51821 GUTD_BIND_PORT=51822 "$GUTD_BINARY" --config /tmp/gutd-server.conf > /tmp/gutd-test-server.log 2>&1 &
    else
        "$GUTD_BINARY" --config /tmp/gutd-server.conf > /tmp/gutd-test-server.log 2>&1 &
    fi
    GUTD_SERVER_PID=$!
    sleep 2
    
    # Check if gutd server process is still running
    if ! kill -0 $GUTD_SERVER_PID 2>/dev/null; then
        error "gutd server process died"
        echo "=== gutd server log ===" >&2
        cat /tmp/gutd-test-server.log >&2
        return 1
    fi
    
    # Start gutd relay in server_ns
    log "Starting gutd relay in server_ns..."
    if [ "$mode" = "userspace" ]; then
        ip netns exec server_ns env GUTD_WG_HOST=0.0.0.0:51820 GUTD_BIND_PORT=51821 \
          "$GUTD_BINARY" --config /tmp/gutd-relay.conf > /tmp/gutd-test-relay.log 2>&1 &
    else
        ip netns exec server_ns "$GUTD_BINARY" --config /tmp/gutd-relay.conf > /tmp/gutd-test-relay.log 2>&1 &
    fi
    GUTD_RELAY_PID=$!
    sleep 2
    
    # Check if gutd relay process is still running
    if ! kill -0 $GUTD_RELAY_PID 2>/dev/null; then
        error "gutd relay process died"
        echo "=== gutd relay log ===" >&2
        cat /tmp/gutd-test-relay.log >&2
        return 1
    fi
    
    if [ "$mode" = "userspace" ]; then
        # Userspace mode: no gut interfaces, gutd is a pure UDP proxy.
        log "gutd userspace proxies started"
        echo "=== gutd server log ===" >&2
        head -10 /tmp/gutd-test-server.log >&2
        echo "=== gutd relay log ===" >&2
        head -10 /tmp/gutd-test-relay.log >&2
        return 0
    fi

    # --- eBPF-only: check gut veth interfaces ---
    
    # Check if gutd interfaces are up
    if ! ip link show gut1 > /dev/null 2>&1; then
        error "gutd server interface (gut1) not created"
        echo "=== gutd server log ===" >&2
        cat /tmp/gutd-test-server.log >&2
        echo "=== gutd server config ===" >&2
        cat /tmp/gutd-server.conf >&2
        return 1
    fi
    
    if ! ip netns exec server_ns ip link show gut0 > /dev/null 2>&1; then
        error "gutd relay interface (gut0) not created"
        echo "=== gutd relay log ===" >&2
        cat /tmp/gutd-test-relay.log >&2
        echo "=== gutd relay config ===" >&2
        cat /tmp/gutd-relay.conf >&2
        return 1
    fi
    
    log "gutd tunnel established"
    
    # Show initial gutd logs 
    echo "=== gutd server log ===" >&2
    head -10 /tmp/gutd-test-server.log >&2
    echo "=== gutd relay log ===" >&2
    head -10 /tmp/gutd-test-relay.log >&2
    
    # relay_ns needs only the WG endpoint via relay namespace gateway
    ip netns exec relay_ns ip route add 10.254.0.1/32 via 10.100.1.2
    
    log "gutd interfaces and routes configured"
    
    # Debug: Show routing tables
    log "=== Routing debug ==="
    echo "Host routes:" >&2
    ip route >&2
    echo "server_ns routes:" >&2
    ip netns exec server_ns ip route >&2
    echo "relay_ns routes:" >&2
    ip netns exec relay_ns ip route >&2
    log "=================="
    
    # Optional L3 ping checks (payload-only WG mode may not pass ICMP over gut interfaces).
    local l3_ping_check="${GUTD_L3_PING_CHECK:-0}"
    if [ "$l3_ping_check" = "1" ]; then
        log "Testing gutd L3 ICMP connectivity (GUTD_L3_PING_CHECK=1)..."
        if ip netns exec server_ns ping -c 3 -W 2 10.254.0.1 > /dev/null 2>&1; then
            log "[ok] gutd tunnel: server_ns -> host WORKING"
        else
            warn "ICMP check failed: server_ns -> host (continuing; WG checks will validate datapath)"
            ip netns exec server_ns ping -c 3 10.254.0.1 >&2 || true
        fi

        if ping -c 3 -W 2 10.254.0.2 > /dev/null 2>&1; then
            log "[ok] gutd tunnel: host -> server_ns WORKING"
        else
            warn "ICMP check failed: host -> server_ns (continuing; WG checks will validate datapath)"
            ping -c 3 10.254.0.2 >&2 || true
        fi
    else
        log "Skipping L3 ICMP checks for payload-only mode (set GUTD_L3_PING_CHECK=1 to enable)"
    fi
}

# Setup WireGuard through gutd
setup_wireguard_via_gutd() {
    local mode=${1:-ebpf}
    log "Setting up WireGuard through gutd tunnel (mode: $mode)..."

    local first_port
    first_port=$(echo "$GUT_PORTS_CSV" | cut -d, -f1 | xargs)

    if [ "$mode" = "userspace" ]; then
        # Userspace: WG client co-located with gutd relay in server_ns.
        # WG sends to 127.0.0.1:<gut_port>; gutd detects non-QUIC first byte → treats as
        # egress WG, obfuscates and sends to remote gutd server.
        ip netns exec server_ns ip link add wg0 type wireguard
        ip netns exec server_ns ip addr add 10.200.0.1/24 dev wg0
        ip netns exec server_ns ip link set wg0 mtu "$WG_MTU"

        cat > /tmp/wg-client-gutd.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 10.100.2.2:51820
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 25
EOF
        ip netns exec server_ns wg setconf wg0 /tmp/wg-client-gutd.conf
        ip netns exec server_ns ip link set wg0 up

        # WG server on host — same as eBPF mode
        ip link add wg_srv type wireguard
        ip addr add 10.200.0.2/24 dev wg_srv
        ip link set wg_srv mtu "$WG_MTU"

        cat > /tmp/wg-server-gutd.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = 51821

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.0.1/32
EOF
        wg setconf wg_srv /tmp/wg-server-gutd.conf
        ip link set wg_srv up

        # No gut0 iptables rules needed — traffic stays on loopback / UDP sockets
        sysctl -w net.ipv4.ip_forward=1 > /dev/null

        sleep 3

        log "=== WireGuard status (userspace) ==="
        echo "Client WireGuard (server_ns):" >&2
        ip netns exec server_ns wg show wg0 >&2
        echo "Server WireGuard (host):" >&2
        wg show wg_srv >&2
        log "===================================="

        log "Testing WireGuard tunnel connectivity (10 pings from server_ns)..."
        local ping_out
        ping_out=$(ip netns exec server_ns ping -c 10 -i 0.2 -W 2 10.200.0.2 2>&1) || true
        log "${ping_out}"

        local rtt_line loss_line
        rtt_line=$(echo "$ping_out"  | grep -oP 'rtt min/avg/max/mdev = \S+')
        loss_line=$(echo "$ping_out" | grep -oP '\d+% packet loss')

        if echo "$ping_out" | grep -q ' 0% packet loss'; then
            log "[ok] WireGuard tunnel working — ${rtt_line:-rtt n/a}  loss: ${loss_line:-n/a}"
        else
            warn "WireGuard tunnel ping failed (${loss_line:-100% packet loss}) — continuing to iperf3"
        fi

        echo "wg_gutd_userspace_ping_rtt=${rtt_line#*= }"  >> "$RESULTS_FILE"
        echo "wg_gutd_userspace_ping_loss=${loss_line}"     >> "$RESULTS_FILE"

        log "WireGuard through gutd (userspace) configured"
        return 0
    fi

    # --- eBPF mode: WG client in relay_ns, traffic through gut tunnel ---
    
    # WireGuard client in relay_ns -> points to gutd relay
    ip netns exec relay_ns ip link add wg0 type wireguard
    ip netns exec relay_ns ip addr add 10.200.0.1/24 dev wg0
    ip netns exec relay_ns ip link set wg0 mtu "$WG_MTU"
    
    cat > /tmp/wg-client-gutd.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
ListenPort = 51820

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 10.254.0.1:51821
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 25
EOF
    
    ip netns exec relay_ns wg setconf wg0 /tmp/wg-client-gutd.conf
    ip netns exec relay_ns ip link set wg0 up
    
    # WireGuard server on host (bind to all interfaces)
    ip link add wg_srv type wireguard
    ip addr add 10.200.0.2/24 dev wg_srv
    ip link set wg_srv mtu "$WG_MTU"
    
    cat > /tmp/wg-server-gutd.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
ListenPort = 51821

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.0.1/32
EOF
    
    wg setconf wg_srv /tmp/wg-server-gutd.conf
    ip link set wg_srv up
    
    # FORWARD allowlist for relay path (some hosts use DROP policy by default)
    # WG endpoint in relay_ns points directly to 10.254.0.2, so traffic is routed
    # via veth_server -> gut0 and consumed by relay gutd on tun interface.
    ip netns exec server_ns iptables -A FORWARD \
        -i veth_server -o gut0 -p udp --dport 51821 \
        -j ACCEPT
    ip netns exec server_ns iptables -A FORWARD \
        -i gut0 -o veth_server -m conntrack --ctstate ESTABLISHED,RELATED \
        -j ACCEPT
    
    # POSTROUTING: SNAT to make it look like it's coming from gutd
    ip netns exec server_ns iptables -t nat -A POSTROUTING \
        -o gut0 -p udp --dport 51821 \
        -j SNAT --to-source 10.254.0.2
    
    # Enable forwarding in server_ns
    ip netns exec server_ns sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    # Wait for WireGuard handshake
    sleep 3
    
    # Check WireGuard status
    log "=== WireGuard status ==="
    echo "Client WireGuard:" >&2
    ip netns exec relay_ns wg show wg0 >&2
    echo "Server WireGuard:" >&2
    wg show wg_srv >&2
    log "======================="
    
    # Test connectivity through WireGuard tunnel and record RTT stats
    log "Testing WireGuard tunnel connectivity (10 pings)..."
    local ping_out
    ping_out=$(ip netns exec relay_ns ping -c 10 -i 0.2 -W 2 10.200.0.2 2>&1) || true
    log "${ping_out}"

    # Parse summary line: "rtt min/avg/max/mdev = A/B/C/D ms"
    local rtt_line loss_line
    rtt_line=$(echo "$ping_out"  | grep -oP 'rtt min/avg/max/mdev = \S+')
    loss_line=$(echo "$ping_out" | grep -oP '\d+% packet loss')

    if echo "$ping_out" | grep -qP ' [0-2]0?% packet loss'; then
        log "[ok] WireGuard tunnel working — ${rtt_line:-rtt n/a}  loss: ${loss_line:-n/a}"
    else
        error "[FAIL] WireGuard tunnel NOT working (${loss_line:-100% packet loss})"
        return 1
    fi

    # Record for summary
    echo "wg_gutd_ping_rtt=${rtt_line#*= }"  >> "$RESULTS_FILE"
    echo "wg_gutd_ping_loss=${loss_line}"     >> "$RESULTS_FILE"

    log "WireGuard through gutd configured"
}

# Test WireGuard through gutd
test_wireguard_via_gutd() {
    local mode=${1:-ebpf}
    log "Testing WireGuard through gutd tunnel (mode: $mode)..."

    # In userspace mode WG client is in server_ns; in eBPF mode it's in relay_ns.
    local wg_client_ns
    if [ "$mode" = "userspace" ]; then
        wg_client_ns="server_ns"
    else
        wg_client_ns="relay_ns"
    fi
    
    # Start iperf3 server on host
    iperf3 -s -B 10.200.0.2 -p 5201 -D > /tmp/iperf3-server-gutd.log 2>&1
    sleep 1
    
    # Separate pcap files per mode so the userspace run can't show
    # stale eBPF capture data and both can be inspected independently.
    local wire_pcap="/tmp/gutd-test-gutd-wire-${mode}.pcap"
    local tunnel_pcap="/tmp/gutd-test-gutd-tunnel-${mode}.pcap"
    rm -f "$wire_pcap" "$tunnel_pcap"

    # Capture packets at two levels
    # 1. Wire (veth_host): should see gutd UDP on configured ports
    log "Capturing wire packets with full details..."
    local wire_filter
    wire_filter="$(build_udp_port_filter "$GUT_PORTS_CSV")"
    timeout 6 tcpdump -i veth_host -n -vv -c 10 $wire_filter > /tmp/gutd-test-wire-details.txt 2>&1 &
    TCPDUMP_DETAIL_PID=$!

    capture_packets veth_host "$wire_pcap" 5 "" "$wire_filter" &
    TCPDUMP1_PID=$!

    # 2. Tunnel (gut1): only in eBPF mode (no gut interfaces in userspace)
    if [ "$mode" != "userspace" ]; then
        capture_packets gut1 "$tunnel_pcap" 5 &
        TCPDUMP2_PID=$!
    fi
    
    # Run iperf3 test (from the namespace where WG client lives)
    local throughput
    local retransmits
    local result_json
    result_json=$(timeout 25 ip netns exec "$wg_client_ns" iperf3 -c 10.200.0.2 -p 5201 -t 5 --connect-timeout 3000 -J 2>&1) || true

    if [ -z "${result_json:-}" ] || ! echo "$result_json" | jq . >/dev/null 2>&1; then
        warn "gutd iperf3 failed or timed out; forcing throughput=0"
        echo "$result_json" >&2
        result_json='{"end":{"sum_received":{"bits_per_second":0},"sum_sent":{"retransmits":0}}}'
    fi
    
    throughput=$(echo "$result_json" | jq -r '.end.sum_received.bits_per_second // 0')
    retransmits=$(echo "$result_json" | jq -r '.end.sum_sent.retransmits // 0')
    
    log "TCP retransmits: $retransmits"
    
    wait $TCPDUMP1_PID 2>/dev/null || true
    [ -n "${TCPDUMP2_PID:-}" ] && wait $TCPDUMP2_PID 2>/dev/null || true
    wait $TCPDUMP_DETAIL_PID 2>/dev/null || true
    
    # Show detailed capture
    log "=== Detailed wire packet capture ===" 
    cat /tmp/gutd-test-wire-details.txt >&2 || true
    log "===================================="
    
    # Kill iperf3 server
    pkill -x iperf3 || true
    
    local throughput_mbps=$(echo "scale=2; $throughput / 1000000" | bc)
    
    log "WireGuard via gutd throughput: ${throughput_mbps} Mbps"
    if [ "$mode" = "userspace" ]; then
        echo "wireguard_gutd_userspace_mbps=$throughput_mbps" >> "$RESULTS_FILE"
    else
        echo "wireguard_gutd_mbps=$throughput_mbps" >> "$RESULTS_FILE"
    fi
    
    # Analyze captured packets
    local wire_packets
    wire_packets=$(tcpdump -r "$wire_pcap" 2>/dev/null | wc -l)
    log "Captured $wire_packets gutd packets on wire"
    echo "gutd_${mode}_wire_packets=$wire_packets" >> "$RESULTS_FILE"

    if [ "$mode" != "userspace" ]; then
        local tunnel_packets
        tunnel_packets=$(tcpdump -r "$tunnel_pcap" 2>/dev/null | wc -l)
        log "Captured $tunnel_packets WireGuard packets in gutd tunnel"
        echo "gutd_${mode}_tunnel_packets=$tunnel_packets" >> "$RESULTS_FILE"
    fi
    
    # Collect interface statistics
    log "=== Interface statistics ==="
    if [ "$mode" != "userspace" ]; then
        echo "Host gut1:" >&2
        ip -s link show gut1 >&2
        echo "server_ns gut0:" >&2
        ip netns exec server_ns ip -s link show gut0 >&2
    fi
    echo "WireGuard wg_srv:" >&2
    ip -s link show wg_srv >&2
    echo "${wg_client_ns} WireGuard wg0:" >&2
    ip netns exec "$wg_client_ns" ip -s link show wg0 >&2
    log "======================="
    
    # Verify obfuscation: wire packets should be gutd UDP, not WireGuard
    log "Analyzing packet obfuscation..."
    tcpdump -r "$wire_pcap" -n 2>/dev/null | head -n 5 | tee -a "$RESULTS_FILE"
    
    # Show performance stats from gutd logs
    log "=== gutd performance stats ==="
    echo "Server stats:" >&2
    grep -A 10 "Performance Stats" /tmp/gutd-test-server.log | tail -n 20 >&2 || echo "No stats found" >&2
    echo "Relay stats:" >&2
    grep -A 10 "Performance Stats" /tmp/gutd-test-relay.log | tail -n 20 >&2 || echo "No stats found" >&2
    log "============================="
}

# Test SIP anti-probing (own_http3, SIP mode only)
# Sends SIP probes from server_ns to the host GUT port (ports[0] = signaling).
# Traffic arrives at veth_host XDP ingress -> handle_sip_probe replies with
# 200 OK / 401 Unauthorized / 403 Forbidden via XDP_TX.
test_sip_antiprobe() {
    log "Testing SIP anti-probing (own_http3)..."

    if ! command -v python3 &>/dev/null; then
        warn "python3 not found — skipping SIP probe test"
        echo "sip_antiprobe=SKIP" >> "$RESULTS_FILE"
        return
    fi

    # ports[0] is the SIP signaling port (first in the CSV)
    local probe_port
    probe_port=$(echo "$GUT_PORTS_CSV" | cut -d, -f1 | xargs)

    log "Sending SIP probes from server_ns -> 10.100.2.1:$probe_port"

    # Inline probe script — mirrors test_anti_probing.sh logic
    if ip netns exec server_ns python3 - 10.100.2.1 "$probe_port" <<'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
fail = False

def probe(name, payload, want):
    global fail
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(payload, (host, port))
    try:
        data, _ = s.recvfrom(4096)
        if want is None:
            print(f"[FAIL] {name}: expected no response, got {len(data)} bytes")
            fail = True
        elif want in data:
            print(f"[OK]   {name}: got expected '{want.decode()}'")
        else:
            print(f"[FAIL] {name}: expected '{want.decode()}', got: {data[:80]}")
            fail = True
    except socket.timeout:
        if want is None:
            print(f"[OK]   {name}: dropped (no response expected)")
        else:
            print(f"[FAIL] {name}: expected '{want.decode()}', got timeout")
            fail = True
    finally:
        s.close()

probe("SIP OPTIONS",  b"OPTIONS sip:user@example.com SIP/2.0\r\n\r\n",  b"200 OK")
probe("SIP REGISTER", b"REGISTER sip:user@example.com SIP/2.0\r\n\r\n", b"401 Unauthorized")
probe("SIP INVITE",   b"INVITE sip:user@example.com SIP/2.0\r\n\r\n",  b"403 Forbidden")
probe("GARBAGE",      b"\xff\xff\xff\xff",                               None)
probe("RTP PROBE",    b"\x80\x60\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00", None)
sys.exit(1 if fail else 0)
PYEOF
    then
        log "[ok] SIP anti-probing: PASS"
        echo "sip_antiprobe=PASS" >> "$RESULTS_FILE"
    else
        warn "[FAIL] SIP anti-probing: FAIL"
        echo "sip_antiprobe=FAIL" >> "$RESULTS_FILE"
    fi
}

# Test QUIC Version Negotiation anti-probing (own_http3)
# Sends a QUIC Initial Long Header to the host GUT port from server_ns.
# Traffic arrives at veth_host XDP ingress -> handle_quic_probe bounces a
# Version Negotiation packet back via XDP_TX.
test_quic_antiprobe() {
    log "Testing QUIC anti-probing (own_http3)..."

    if ! command -v python3 &>/dev/null; then
        warn "python3 not found — skipping QUIC probe test"
        echo "quic_antiprobe=SKIP" >> "$RESULTS_FILE"
        return
    fi

    # First port from the CSV list is what the XDP program listens on
    local probe_port
    probe_port=$(echo "$GUT_PORTS_CSV" | cut -d, -f1 | xargs)

    log "Sending QUIC Initial probe from server_ns -> 10.100.2.1:$probe_port"

    # Run from server_ns: packets enter veth_host from veth_srv, hitting XDP ingress
    if ip netns exec server_ns python3 "$SCRIPT_DIR/probe_quic.py" 10.100.2.1 "$probe_port"; then
        log "[ok] QUIC Version Negotiation anti-probing: PASS"
        echo "quic_antiprobe=PASS" >> "$RESULTS_FILE"
    else
        warn "[FAIL] QUIC Version Negotiation anti-probing: FAIL"
        echo "quic_antiprobe=FAIL" >> "$RESULTS_FILE"
    fi
}

# Stop gutd processes and remove their interfaces between test runs
cleanup_gutd() {
    log "Stopping gutd processes..."
    [ -n "${GUTD_RELAY_PID:-}" ] && kill "$GUTD_RELAY_PID" 2>/dev/null && wait "$GUTD_RELAY_PID" 2>/dev/null || true
    [ -n "${GUTD_SERVER_PID:-}" ] && kill "$GUTD_SERVER_PID" 2>/dev/null && wait "$GUTD_SERVER_PID" 2>/dev/null || true
    GUTD_RELAY_PID=""
    GUTD_SERVER_PID=""
    # Remove gut veth interfaces (eBPF mode)
    ip netns exec server_ns ip link del gut0 2>/dev/null || true
    ip link del gut1 2>/dev/null || true
    # Remove WG interfaces from all possible locations
    ip netns exec relay_ns ip link del wg0 2>/dev/null || true
    ip netns exec server_ns ip link del wg0 2>/dev/null || true
    ip link del wg_srv 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    # Flush iptables in server_ns (gut0 forward rules)
    ip netns exec server_ns iptables -F 2>/dev/null || true
    ip netns exec server_ns iptables -t nat -F 2>/dev/null || true
    log "gutd cleanup done"
}

# Cleanup
cleanup() {
    if [ "${KEEP_RUNNING:-0}" = "1" ]; then
        warn "KEEP_RUNNING=1 set, skipping cleanup for live debugging"
        return
    fi

    log "Cleaning up..."
    
    # Kill processes
    [ -n "${GUTD_RELAY_PID:-}" ] && kill "$GUTD_RELAY_PID" 2>/dev/null || true
    [ -n "${GUTD_SERVER_PID:-}" ] && kill "$GUTD_SERVER_PID" 2>/dev/null || true
    pkill -x iperf3 || true
    
    # Remove interfaces
    ip netns exec relay_ns ip link del wg0 2>/dev/null || true
    ip netns exec server_ns ip link del gut0 2>/dev/null || true
    ip link del wg_srv 2>/dev/null || true
    ip link del gut1 2>/dev/null || true
    ip link del veth_host 2>/dev/null || true
    ip route del 10.100.1.0/24 via 10.100.2.2 2>/dev/null || true
    
    # Remove namespaces
    ip netns del relay_ns 2>/dev/null || true
    ip netns del server_ns 2>/dev/null || true
    
    # Flush iptables
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    
    log "Cleanup complete"
}

# Compare results
compare_results() {
    log "Comparing results..."
    
    echo "" >> "$RESULTS_FILE"
    echo "=== Test Summary ===" >> "$RESULTS_FILE"
    
    local baseline_mbps
    baseline_mbps=$(grep "wireguard_baseline_mbps=" "$RESULTS_FILE" | cut -d= -f2)
    local gutd_ebpf_mbps gutd_userspace_mbps
    gutd_ebpf_mbps=$(grep    "wireguard_gutd_mbps="           "$RESULTS_FILE" | cut -d= -f2)
    gutd_userspace_mbps=$(grep "wireguard_gutd_userspace_mbps=" "$RESULTS_FILE" | cut -d= -f2)

    log "WireGuard baseline:              ${baseline_mbps:-N/A} Mbps"

    _report_overhead() {
        local label="$1" mbps="$2"
        if [ -n "$baseline_mbps" ] && [ -n "$mbps" ]; then
            local overhead
            overhead=$(echo "scale=2; (1 - $mbps / $baseline_mbps) * 100" | bc)
            echo "Throughput overhead (${label}): ${overhead}%" >> "$RESULTS_FILE"
            log "WireGuard via gutd (${label}):   ${mbps} Mbps  (overhead: ${overhead}%)"
            local oi=${overhead%.*}
            if [ "${oi:-100}" -lt 30 ]; then
                log "[ok] ${label} overhead acceptable (<30%)"
            else
                warn "${label} overhead is high (${overhead}%)"
            fi
        fi
    }
    _report_overhead "eBPF"      "$gutd_ebpf_mbps"
    _report_overhead "userspace" "$gutd_userspace_mbps"

    local ping_rtt ping_loss
    ping_rtt=$(grep  "wg_gutd_ping_rtt="  "$RESULTS_FILE" | cut -d= -f2-)
    ping_loss=$(grep "wg_gutd_ping_loss=" "$RESULTS_FILE" | cut -d= -f2-)
    if [ -n "$ping_rtt" ]; then
        log "WG-over-gutd ping RTT:         ${ping_rtt} ms"
        log "WG-over-gutd packet loss:      ${ping_loss:-0% packet loss}"
    fi

    # Anti-probing result — key name varies by obfs mode
    local quic_result sip_result
    quic_result=$(grep "quic_antiprobe=" "$RESULTS_FILE" | cut -d= -f2)
    sip_result=$(grep  "sip_antiprobe="  "$RESULTS_FILE" | cut -d= -f2)
    case "${quic_result:-}" in
        PASS)    log  "QUIC anti-probing:             PASS" ;;
        FAIL)    warn "QUIC anti-probing:             FAIL" ;;
        SKIP)    warn "QUIC anti-probing:             SKIP (python3 missing)" ;;
        SKIPPED) log  "QUIC anti-probing:             SKIPPED (not quic mode)" ;;
        '') ;; # not run for this mode
    esac
    case "${sip_result:-}" in
        PASS)    log  "SIP anti-probing:              PASS" ;;
        FAIL)    warn "SIP anti-probing:              FAIL" ;;
        SKIP)    warn "SIP anti-probing:              SKIP (python3 missing)" ;;
        SKIPPED) log  "SIP anti-probing:              SKIPPED (not sip mode)" ;;
        '') ;; # not run for this mode
    esac
}

# Main execution
main() {
    log "Starting WireGuard + gutd integration test..."
    log "  obfs=${GUTD_OBFS}  ports=${GUT_PORTS_CSV}  SNI=${GUTD_SNI:-none}  WG_MTU=${WG_MTU}"
    
    # Init results file
    echo "=== Integration Test Results ===" > "$RESULTS_FILE"
    echo "Timestamp: $(date)" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    # Setup cleanup trap
    trap cleanup EXIT
    
    # Run tests
    check_dependencies
    generate_wg_keys
    setup_namespaces
    
    # Test 1: WireGuard baseline (no obfuscation)
    log "=== Test 1: WireGuard Baseline ==="
    setup_wireguard_baseline
    test_wireguard_baseline
    cleanup_wireguard_baseline
    
    sleep 2
    
    # Test 2: WireGuard through gutd (eBPF)
    log "=== Test 2: WireGuard via gutd (eBPF) ==="
    setup_gutd "ebpf"
    setup_wireguard_via_gutd "ebpf"
    test_wireguard_via_gutd "ebpf"

    # Test 3: anti-probing — mechanism differs by mode
    #   quic  → QUIC Version Negotiation (handle_quic_probe, XDP_TX)
    #   sip   → SIP 200/401/403 responses (handle_sip_probe, XDP_TX)
    #   other → no XDP anti-probe handler compiled in
    case "$GUTD_OBFS" in
        quic)
            log "=== Test 3: QUIC Version Negotiation anti-probing ==="
            test_quic_antiprobe
            ;;
        sip)
            log "=== Test 3: SIP anti-probing ==="
            test_sip_antiprobe
            ;;
        *)
            log "=== Test 3: anti-probing SKIPPED (obfs=${GUTD_OBFS} has no XDP probe handler) ==="
            ;;
    esac
    
    cleanup_gutd
    sleep 2

    # Test 4: WireGuard through gutd (Userspace)
    log "=== Test 4: WireGuard via gutd (Userspace) ==="
    setup_gutd "userspace"
    setup_wireguard_via_gutd "userspace"
    test_wireguard_via_gutd "userspace"

    # Compare
    compare_results
    
    log "Tests completed successfully"
    cat "$RESULTS_FILE"
}

main "$@"
