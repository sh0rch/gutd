#!/bin/bash
set -e

# Wait for background jobs on exit
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

# We need full iproute2 for namespaces, not busybox
opkg update
opkg install ip-full wireguard-tools iperf3 kmod-wireguard

GUTD=/tmp/bin/gutd-x86_64
KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PORTS="41000"

# Mount BPF filesystem if not already mounted
mount | grep /sys/fs/bpf || mount -t bpf none /sys/fs/bpf

# Create network namespaces
ip netns add ns1
ip netns add ns2

# Create and link veth pair
ip link add veth1 type veth peer name veth2
ip link set veth1 netns ns1
ip link set veth2 netns ns2

# Setup transport IP addresses
ip netns exec ns1 ip link set lo up
ip netns exec ns1 ip link set veth1 up
ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1

ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip link set veth2 up
ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2

# Test transport connectivity
ip netns exec ns1 ping -c1 -W2 10.0.0.2

# Generate WireGuard keys
WG_CLIENT_PRIV=$(wg genkey)
WG_CLIENT_PUB=$(echo "\$WG_CLIENT_PRIV" | wg pubkey)
WG_SERVER_PRIV=$(wg genkey)
WG_SERVER_PUB=$(echo "\$WG_SERVER_PRIV" | wg pubkey)

# Server config
mkdir -p /tmp/wg
cat > /tmp/wg/wg-server.conf << EOCCONF
[Interface]
PrivateKey = \$WG_SERVER_PRIV
ListenPort = 51820

[Peer]
PublicKey = \$WG_CLIENT_PUB
AllowedIPs = 10.200.0.1/32
EOCCONF

# gutd configs
cat > /tmp/wg/g1.conf << EOCCONF
[global]
[peer]
name = gut1
mtu = 1500
nic = veth1
address = 192.168.99.1/30
bind_ip = 10.0.0.1
peer_ip = 10.0.0.2
ports = \$PORTS
key = \$KEY
EOCCONF

cat > /tmp/wg/g2.conf << EOCCONF
[global]
[peer]
name = gut2
mtu = 1500
nic = veth2
address = 192.168.99.2/30
bind_ip = 10.0.0.2
peer_ip = 10.0.0.1
ports = \$PORTS
key = \$KEY
EOCCONF

# Start gutd instances
ip netns exec ns1 \$GUTD --config /tmp/wg/g1.conf > /tmp/wg/g1.log 2>&1 &
G1PID=\$!
sleep 1
ip netns exec ns2 \$GUTD --config /tmp/wg/g2.conf > /tmp/wg/g2.log 2>&1 &
G2PID=\$!
sleep 2

if ! kill -0 \$G1PID 2>/dev/null; then echo "FAIL ns1"; cat /tmp/wg/g1.log; exit 1; fi
if ! kill -0 \$G2PID 2>/dev/null; then echo "FAIL ns2"; cat /tmp/wg/g2.log; exit 1; fi

# Setup WireGuard server in ns2
ip netns exec ns2 ip link add wg0 type wireguard
ip netns exec ns2 ip addr add 10.200.0.2/24 dev wg0
ip netns exec ns2 wg setconf wg0 /tmp/wg/wg-server.conf
ip netns exec ns2 ip link set wg0 mtu 1420 up

# Client config
cat > /tmp/wg/wg-client.conf << EOCCONF
[Interface]
PrivateKey = \$WG_CLIENT_PRIV

[Peer]
PublicKey = \$WG_SERVER_PUB
Endpoint = 192.168.99.2:51820
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 5
EOCCONF

# Setup WireGuard client in ns1
ip netns exec ns1 ip link add wg0 type wireguard
ip netns exec ns1 ip addr add 10.200.0.1/24 dev wg0
ip netns exec ns1 wg setconf wg0 /tmp/wg/wg-client.conf
ip netns exec ns1 ip link set wg0 mtu 1420 up

sleep 4
ip netns exec ns1 ping -c5 -i0.2 -W3 10.200.0.2

# Test UDP throughput
ip netns exec ns2 iperf3 -s -1 -p 5202 &
sleep 0.5
ip netns exec ns1 iperf3 -c 10.200.0.2 -p 5202 -u -b 200M -t 3
