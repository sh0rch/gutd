#!/bin/bash
set -e

# Integration test: WireGuard + gutd relay with iperf3 and packet capture
# Architecture:
#   relay_ns (WG client) -> server_ns (gutd relay) -> host (gutd server + WG server)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="${GUTD_BINARY:-$SCRIPT_DIR/../target/musl/gutd}"
RESULTS_FILE="${RESULTS_FILE:-/tmp/gutd-test-results.txt}"
GUT_PORTS_CSV="${GUT_PORTS_CSV:-41000,41001}"
WG_MTU="${WG_MTU:-1420}"

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
    
    # Routing
    ip netns exec relay_ns ip route add default via 10.100.1.2
    ip netns exec server_ns ip route add default via 10.100.2.1
    ip route replace 10.100.1.0/24 via 10.100.2.2
    
    # Enable forwarding
    ip netns exec server_ns sysctl -w net.ipv4.ip_forward=1 > /dev/null
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
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
    
    log "Capturing $count packets on $interface -> $output_file"
    
    if [ -n "$namespace" ]; then
        timeout 10 ip netns exec "$namespace" tcpdump -i "$interface" -c "$count" -w "$output_file" udp 2>/dev/null || true
    else
        timeout 10 tcpdump -i "$interface" -c "$count" -w "$output_file" udp 2>/dev/null || true
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
    log "Setting up gutd relay and server..."
    
    # gutd config for relay (in server_ns)
    cat > /tmp/gutd-relay.conf <<EOF
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
    
    # gutd config for server (on host)
    cat > /tmp/gutd-server.conf <<EOF
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
    
    # Start gutd server on host
    log "Starting gutd server on host..."
    "$GUTD_BINARY" --config /tmp/gutd-server.conf > /tmp/gutd-test-server.log 2>&1 &
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
    ip netns exec server_ns "$GUTD_BINARY" --config /tmp/gutd-relay.conf > /tmp/gutd-test-relay.log 2>&1 &
    GUTD_RELAY_PID=$!
    sleep 2
    
    # Check if gutd relay process is still running
    if ! kill -0 $GUTD_RELAY_PID 2>/dev/null; then
        error "gutd relay process died"
        echo "=== gutd relay log ===" >&2
        cat /tmp/gutd-test-relay.log >&2
        return 1
    fi
    
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
    ip netns exec relay_ns ip route add 10.254.0.2/32 via 10.100.1.2
    
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
        if ip netns exec server_ns ping -c 3 -W 2 10.254.0.2 > /dev/null 2>&1; then
            log "[ok] gutd tunnel: server_ns -> host WORKING"
        else
            warn "ICMP check failed: server_ns -> host (continuing; WG checks will validate datapath)"
            ip netns exec server_ns ping -c 3 10.254.0.2 >&2 || true
        fi

        if ping -c 3 -W 2 10.254.0.1 > /dev/null 2>&1; then
            log "[ok] gutd tunnel: host -> server_ns WORKING"
        else
            warn "ICMP check failed: host -> server_ns (continuing; WG checks will validate datapath)"
            ping -c 3 10.254.0.1 >&2 || true
        fi
    else
        log "Skipping L3 ICMP checks for payload-only mode (set GUTD_L3_PING_CHECK=1 to enable)"
    fi
}

# Setup WireGuard through gutd
setup_wireguard_via_gutd() {
    log "Setting up WireGuard through gutd tunnel..."
    
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
Endpoint = 10.254.0.2:51821
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
        -j SNAT --to-source 10.254.0.1
    
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
    
    # Test connectivity through WireGuard tunnel
    log "Testing WireGuard tunnel connectivity..."
    if ip netns exec relay_ns ping -c 3 -W 2 10.200.0.2 > /dev/null 2>&1; then
        log "[ok] WireGuard tunnel working"
    else
        error "[FAIL] WireGuard tunnel NOT working"
        echo "=== Ping test ===" >&2
        ip netns exec relay_ns ping -c 3 10.200.0.2 >&2 || true
        return 1
    fi
    
    log "WireGuard through gutd configured"
}

# Test WireGuard through gutd
test_wireguard_via_gutd() {
    log "Testing WireGuard through gutd tunnel..."
    
    # Start iperf3 server on host
    iperf3 -s -B 10.200.0.2 -p 5201 -D > /tmp/iperf3-server-gutd.log 2>&1
    sleep 1
    
    # Capture packets at two levels
    # 1. Wire (veth_host): should see gutd UDP on configured ports
    log "Capturing wire packets with full details..."
    local wire_filter
    wire_filter="$(build_udp_port_filter "$GUT_PORTS_CSV")"
    timeout 6 tcpdump -i veth_host -n -vv -c 10 "$wire_filter" > /tmp/gutd-test-wire-details.txt 2>&1 &
    TCPDUMP_DETAIL_PID=$!
    
    capture_packets veth_host /tmp/gutd-test-gutd-wire.pcap 5 &
    TCPDUMP1_PID=$!
    
    # 2. Tunnel (gut1): should see original WireGuard packets
    capture_packets gut1 /tmp/gutd-test-gutd-tunnel.pcap 5 &
    TCPDUMP2_PID=$!
    
    # Run iperf3 test
    local throughput
    local retransmits
    local result_json
    result_json=$(timeout 25 ip netns exec relay_ns iperf3 -c 10.200.0.2 -p 5201 -t 5 --connect-timeout 3000 -J 2>&1) || true

    if [ -z "${result_json:-}" ] || ! echo "$result_json" | jq . >/dev/null 2>&1; then
        warn "gutd iperf3 failed or timed out; forcing throughput=0"
        echo "$result_json" >&2
        result_json='{"end":{"sum_received":{"bits_per_second":0},"sum_sent":{"retransmits":0}}}'
    fi
    
    throughput=$(echo "$result_json" | jq -r '.end.sum_received.bits_per_second // 0')
    retransmits=$(echo "$result_json" | jq -r '.end.sum_sent.retransmits // 0')
    
    log "TCP retransmits: $retransmits"
    
    wait $TCPDUMP1_PID 2>/dev/null || true
    wait $TCPDUMP2_PID 2>/dev/null || true
    wait $TCPDUMP_DETAIL_PID 2>/dev/null || true
    
    # Show detailed capture
    log "=== Detailed wire packet capture ===" 
    cat /tmp/gutd-test-wire-details.txt >&2 || true
    log "===================================="
    
    # Kill iperf3 server
    pkill -x iperf3 || true
    
    local throughput_mbps=$(echo "scale=2; $throughput / 1000000" | bc)
    
    log "WireGuard via gutd throughput: ${throughput_mbps} Mbps"
    echo "wireguard_gutd_mbps=$throughput_mbps" >> "$RESULTS_FILE"
    
    # Analyze captured packets
    local wire_packets
    wire_packets=$(tcpdump -r /tmp/gutd-test-gutd-wire.pcap 2>/dev/null | wc -l)
    log "Captured $wire_packets gutd packets on wire"
    echo "gutd_wire_packets=$wire_packets" >> "$RESULTS_FILE"
    
    local tunnel_packets
    tunnel_packets=$(tcpdump -r /tmp/gutd-test-gutd-tunnel.pcap 2>/dev/null | wc -l)
    log "Captured $tunnel_packets WireGuard packets in gutd tunnel"
    echo "gutd_tunnel_packets=$tunnel_packets" >> "$RESULTS_FILE"
    
    # Collect interface statistics
    log "=== Interface statistics ==="
    echo "Host gut1:" >&2
    ip -s link show gut1 >&2
    echo "server_ns gut0:" >&2
    ip netns exec server_ns ip -s link show gut0 >&2
    echo "WireGuard wg_srv:" >&2
    ip -s link show wg_srv >&2
    echo "relay_ns WireGuard wg0:" >&2
    ip netns exec relay_ns ip -s link show wg0 >&2
    log "======================="
    
    # Verify obfuscation: wire packets should be gutd UDP, not WireGuard
    log "Analyzing packet obfuscation..."
    tcpdump -r /tmp/gutd-test-gutd-wire.pcap -n 2>/dev/null | head -n 5 | tee -a "$RESULTS_FILE"
    
    # Show performance stats from gutd logs
    log "=== gutd performance stats ==="
    echo "Server stats:" >&2
    grep -A 10 "Performance Stats" /tmp/gutd-test-server.log | tail -n 20 >&2 || echo "No stats found" >&2
    echo "Relay stats:" >&2
    grep -A 10 "Performance Stats" /tmp/gutd-test-relay.log | tail -n 20 >&2 || echo "No stats found" >&2
    log "============================="
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
    
    local baseline_mbps=$(grep "wireguard_baseline_mbps=" "$RESULTS_FILE" | cut -d= -f2)
    local gutd_mbps=$(grep "wireguard_gutd_mbps=" "$RESULTS_FILE" | cut -d= -f2)
    
    if [ -n "$baseline_mbps" ] && [ -n "$gutd_mbps" ]; then
        local overhead=$(echo "scale=2; (1 - $gutd_mbps / $baseline_mbps) * 100" | bc)
        echo "Throughput overhead: ${overhead}%" >> "$RESULTS_FILE"
        
        log "WireGuard baseline: ${baseline_mbps} Mbps"
        log "WireGuard via gutd: ${gutd_mbps} Mbps"
        log "Overhead: ${overhead}%"
        
        # Check if overhead is acceptable (<30%)
        local overhead_int=${overhead%.*}
        if [ "${overhead_int:-100}" -lt 30 ]; then
            log "[ok] Throughput overhead is acceptable (<30%)"
        else
            warn "Throughput overhead is high (>${overhead}%)"
        fi
    fi
}

# Main execution
main() {
    log "Starting WireGuard + gutd integration test..."
    
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
    
    # Test 2: WireGuard through gutd
    log "=== Test 2: WireGuard via gutd ==="
    setup_gutd
    setup_wireguard_via_gutd
    test_wireguard_via_gutd
    
    # Compare
    compare_results
    
    log "Tests completed successfully"
    cat "$RESULTS_FILE"
}

main "$@"
