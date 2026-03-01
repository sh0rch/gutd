#!/bin/bash
# Quick setup for a WireGuard relay via gutd obfuscation
# Usage: ./wireguard-relay-simple.sh <relay|server>
#
# RELAY mode: intermediate server that receives WireGuard client connections
#             Routes them through a gutd-obfuscated tunnel to the WireGuard server
# SERVER mode: WireGuard endpoint behind a gutd receiver
#
# Topology:
#   WG client ---(obfuscated UDP, ports 6000-6003)---> RELAY ---(gutd veth)---> WG server
#
# Both relay and server must share the same gutd key.
# Generate a key on either host with:  gutd genkey

set -e

MODE="$1"

if [[ "$MODE" != "relay" && "$MODE" != "server" ]]; then
    echo "Usage: $0 <relay|server>"
    exit 1
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== GUT WireGuard Relay Setup ===${NC}\n"

if [[ "$MODE" == "relay" ]]; then
    echo -e "${YELLOW}Mode: RELAY (intermediate server)${NC}"
    echo ""
    
    echo "1. Enable IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-gut-relay.conf
    
    echo "2. Write /etc/gutd/gutd.conf..."
    mkdir -p /etc/gutd
    
    cat > /etc/gutd/gutd.conf <<'EOF'
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
mtu = 1420
address = 10.254.0.1/30
bind_ip = 0.0.0.0
peer_ip = SERVER_PUBLIC_IP_HERE
ports = 6000,6001,6002,6003
keepalive_drop_percent = 75
key = SHARED_KEY_HERE
EOF
    
    echo -e "${YELLOW}NOTE: Set peer_ip and key in /etc/gutd/gutd.conf  (gutd genkey)${NC}"
    
    echo "3. Configure iptables..."

    # WireGuard -> GUT tunnel
    iptables -t nat -C PREROUTING -p udp --dport 5050 -j DNAT --to-destination 10.254.0.2 2>/dev/null || \
        iptables -t nat -A PREROUTING -p udp --dport 5050 -j DNAT --to-destination 10.254.0.2
    
    # Masquerade
    iptables -t nat -C POSTROUTING -o gut0 -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE

    # Forwarding
    iptables -C FORWARD -i eth0 -o gut0 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
    iptables -C FORWARD -i gut0 -o eth0 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
    
    # Allow outbound GUT ports
    iptables -C OUTPUT -p udp -m multiport --dports 6000:6003 -j ACCEPT 2>/dev/null || \
        iptables -A OUTPUT -p udp -m multiport --dports 6000:6003 -j ACCEPT

    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 || true
    fi

    echo -e "${GREEN}Relay configured.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Set peer_ip and key in /etc/gutd/gutd.conf  (gutd genkey)"
    echo "2. Start: gutd -c /etc/gutd/gutd.conf"
    echo "3. Check: ip addr show gut0"
    echo "4. Check: ping -c 3 10.254.0.2"
    echo ""
    echo "WireGuard clients should connect to: $(hostname -I | awk '{print $1}'):51820"

elif [[ "$MODE" == "server" ]]; then
    echo -e "${YELLOW}Mode: SERVER (WireGuard endpoint)${NC}"
    echo ""

    echo "1. Write /etc/gutd/gutd.conf..."
    mkdir -p /etc/gutd
    
    cat > /etc/gutd/gutd.conf <<'EOF'
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
mtu = 1420
address = 10.254.0.2/30
bind_ip = 0.0.0.0
peer_ip = RELAY_PUBLIC_IP_HERE
ports = 6000,6001,6002,6003
keepalive_drop_percent = 75
key = SHARED_KEY_HERE
EOF
    
    echo -e "${YELLOW}NOTE: Set peer_ip and key in /etc/gutd/gutd.conf  (gutd genkey)${NC}"
    
    echo "2. Configure iptables..."
    # No INPUT rule needed for GUT ports (6000-6003): the XDP program processes
    # those packets before they reach the iptables INPUT chain.

    # GUT -> local WireGuard
    iptables -t nat -C PREROUTING -i gut0 -p udp -j DNAT --to-destination 127.0.0.1:51820 2>/dev/null || \
        iptables -t nat -A PREROUTING -i gut0 -p udp -j DNAT --to-destination 127.0.0.1:51820
    
    # Masquerade return traffic
    iptables -t nat -C POSTROUTING -o gut0 -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE

    # Allow loopback WireGuard
    iptables -C INPUT -i lo -p udp --dport 51820 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -i lo -p udp --dport 51820 -j ACCEPT

    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 || true
    fi

    echo -e "${GREEN}Server configured.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Set peer_ip and key in /etc/gutd/gutd.conf  (gutd genkey)"
    echo "2. Ensure WireGuard listens on 0.0.0.0:51820 or 127.0.0.1:51820"
    echo "3. Start: gutd -c /etc/gutd/gutd.conf"
    echo "4. Check: ip addr show gut0"
    echo "5. Check: ping -c 3 10.254.0.1"
fi

echo ""
echo -e "${GREEN}Done.${NC}"
