# Running

## Basic Usage

```bash
# Show version
./gutd --version

# Show help
./gutd --help

# Run with config
sudo ./gutd gutd.conf

# Run in pure userspace mode (no BPF load/mount required, no sudo on Linux if using capabilities)
GUTD_USERSPACE=1 ./gutd gutd.conf
# (Alternatively, set `userspace_only = true` in config)

# Run with custom config path
sudo ./gutd /etc/gutd/custom.conf
```

## Signals

```bash
# Reload configuration (SIGHUP)
sudo pkill -HUP gutd
```

## Hot Reload (SIGHUP)

```bash
sudo kill -HUP $(pgrep gutd)
```

Reloads config from disk and pushes updated key/ports/policy into the running BPF
maps without detaching hooks or recreating the veth pair.

## P2P Mode (Two Machines)

**Machine A (10.0.0.1):**
```ini
[peer]
bind_ip = 0.0.0.0
peer_ip = 10.0.0.2
ports = 41000,41001,41002,41003
```

**Machine B (10.0.0.2):**
```ini
[peer]
bind_ip = 0.0.0.0
peer_ip = 10.0.0.1
ports = 41000,41001,41002,41003
```

`bind_ip = 0.0.0.0` (or `::`) means "auto": gutd resolves the concrete source IP
from `ip route get <peer_ip>` on the selected ingress NIC and writes that address
into the outer header.

Start on both machines:
```bash
sudo ./gutd gutd.conf
```

gutd creates the veth pair `gut0 <-> gut0_xdp` and assigns the address from the
`address` field automatically. No manual `ip addr` commands are needed.

## RouterOS / MikroTik Container Setup

Since v2.2.0, gutd supports pure-userspace execution perfectly suited for MikroTik RouterOS (arm64). To run it, you must use the pre-built Docker tarball release.

**1. Download the Image and Upload to RouterOS**
Download the `gutd-ros-arm64-vX.Y.Z.tar` from the GitHub Releases page.
Using WinBox or SCP, upload this file to your router (e.g. into `disk1/` or `flash/`).

**2. Configure Container Networking**

```routeros
# Create a veth interface for the container
/interface veth add name=veth-gutd address=172.16.1.2/24 gateway=172.16.1.1

# Attach it to a bridge or network (assuming you want it routed)
/interface bridge add name=bridge-containers
/interface bridge port add bridge=bridge-containers interface=veth-gutd
/ip address add address=172.16.1.1/24 interface=bridge-containers
```

**3. Configure gutd**
Create a directory/file on your router to hold the configuration: `disk1/gutd/gutd.conf`
*(You can edit this file from the RouterOS terminal using `/file/edit disk1/gutd/gutd.conf contents`)*

```ini
[global]
userspace_only = true          # Crucial for RouterOS

[peer]
name = gut0
bind_ip = 172.16.1.2           # The veth IP
peer_ip = 203.0.113.10         # Your remote gutd server IP
ports = 41000                  # UDP obfuscation port
key = 001122...
```

**4. Create and Start the Container**
```routeros
# Allow container feature (requires reboot if not enabled)
/system/device-mode/update container=yes

# Create a mount point for the config file
/container/mounts/add name=gutd_cfg src=disk1/gutd dst=/etc/gutd

# Import the container from the tar file
/container/add file=disk1/gutd-ros-arm64-v2.X.X.tar interface=veth-gutd mounts=gutd_cfg root-dir=disk1/gutd-root cmd="--config /etc/gutd/gutd.conf" logging=yes

# Start the container (wait for it to extract first, status will change to "stopped")
/container/start [find file~"gutd"]
```

**5. WireGuard and NAT rules**
Point your local WireGuard interface to the remote WireGuard server IP, but we must route this traffic into our `gutd` container using NAT.

If your WireGuard server is `10.200.0.1` and `gutd` is stripping to port `41000`:
```routeros
# Create local WireGuard interface
/interface/wireguard/add name=wg0 listen-port=51820
/interface/wireguard/peers/add interface=wg0 public-key="..." endpoint-address=10.200.0.1 endpoint-port=51820

# Create a DNAT rule to intercept WireGuard traffic and send it to the container instead
/ip/firewall/nat/add chain=dstnat dst-address=10.200.0.1 protocol=udp dst-port=51820 action=dst-nat to-addresses=172.16.1.2 to-ports=41000

# Make sure the container can reach the internet
/ip/firewall/nat/add chain=srcnat src-address=172.16.1.0/24 action=masquerade
```

## Relay Mode

**IMPORTANT**: To correctly spoof QUIC roles and avoid DPI detection, gutd must know if it's acting as a Server or Client. It determines this automatically by checking the last bit of its internal `address` (the `gut0` interface IP).
**The SERVER's `gut0` IP MUST be odd (e.g. `10.254.0.1`), and the CLIENT's IP MUST be even (e.g. `10.254.0.2`).**

In relay mode a separate machine accepts WireGuard connections from clients and
forwards them through a gutd tunnel to the final server. This requires standard
NAT rules — they apply to the WireGuard traffic, not the gutd ports.

See [examples/wireguard-relay.md](../examples/wireguard-relay.md) for the full
topology. The relevant rules for each machine follow.

**Relay** (e.g. `198.51.100.1`) — forwards client WireGuard traffic into the
gut tunnel toward the server's gut0 peer address (`10.254.0.2`):

```bash
sysctl -w net.ipv4.ip_forward=1

# DNAT: redirect incoming WireGuard connections into the gut tunnel
iptables -t nat -A PREROUTING -p udp --dport 51820 \
    -j DNAT --to-destination 10.254.0.2:51820

# Masquerade so the server can route replies back through the tunnel
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE

# Allow forwarding between the physical NIC and the gut tunnel interface
iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
```

nftables equivalent:

```nftables
table inet gut_relay {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        udp dport 51820 counter dnat to 10.254.0.2:51820
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "gut0" counter masquerade
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
}
```

**Server** (e.g. `203.0.113.1`) — gutd decodes tunnel packets and delivers them
to the `gut0` interface with the original destination address intact (the gut0
peer IP and the WireGuard port configured on the relay). WireGuard receives
them directly since it listens on `0.0.0.0`. Only MASQUERADE is needed so that
reply packets are routed back through the tunnel:

```bash
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE
```

nftables equivalent:

```nftables
table inet gut_server {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "gut0" counter masquerade
    }
}
```

WireGuard listen on `0.0.0.0` (all interfaces, including `gut0`) on
whatever port is used as the DNAT target on the relay.
