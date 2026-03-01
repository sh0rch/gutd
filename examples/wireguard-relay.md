# WireGuard Relay via GUT

Example setup for proxying WireGuard traffic through a GUT tunnel for obfuscation.

> **Lineage**: this tool continues the work started in
> [xt_wgobfs](https://github.com/infinet/xt_wgobfs) (iptables module) and
> [nf_wgobfs](https://github.com/sh0rch/nf_wgobfs) (nftables module).
> gutd replaces the netfilter hook with a TC/XDP eBPF datapath and
> uses a veth pair instead of a TUN device.

## Architecture

```
WG client ---> Relay (198.51.100.1) ---(GUT UDP 6000-6003)---> Server (203.0.113.1)
   :51820         gut0 10.254.0.1/30          obfuscated            gut0 10.254.0.2/30
                  DNAT :51820 -> gut0                               forward to WG :51820
```

Data flow:

1. WireGuard client connects to relay public IP port 51820.
2. Relay DNATs port 51820 to `gut0` tunnel address (10.254.0.2).
3. GUT encapsulates and masks the WireGuard UDP payload, sends to server ports 6000-6003.
4. Server unmasks and decapsulates, forwards from `gut0` to local WireGuard on port 51820.

---

## 1. Relay (198.51.100.1)

### /etc/gutd/gutd.conf

```ini
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
nic = eth0                  # NIC facing the internet
mtu = 1420
address = 10.254.0.1/30
bind_ip = 0.0.0.0
peer_ip = 203.0.113.1       # server public IP
ports = 6000,6001,6002,6003
keepalive_drop_percent = 75
key = <output of: gutd genkey>   # shared with server
```

### iptables

```bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# WireGuard clients -> gut0 (to server via GUT tunnel)
iptables -t nat -A PREROUTING -p udp --dport 51820 \
    -j DNAT --to-destination 10.254.0.2

# Masquerade outbound GUT traffic
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE

# Forwarding
iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
```

### nftables

```nftables
table inet gut_relay {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        udp dport 51820 counter dnat to 10.254.0.2
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

---

## 2. Server (203.0.113.1)

### /etc/gutd/gutd.conf

```ini
[global]
outer_mtu = 1500
stats_interval = 0

[peer]
name = gut0
nic = eth0                  # NIC facing the internet
mtu = 1420
address = 10.254.0.2/30
bind_ip = 0.0.0.0
peer_ip = 198.51.100.1      # relay public IP
ports = 6000,6001,6002,6003
keepalive_drop_percent = 75
key = <same key as relay>
```

### iptables

```bash
# GUT tunnel -> local WireGuard
iptables -t nat -A PREROUTING -i gut0 -p udp \
    -j DNAT --to-destination 127.0.0.1:51820

# Masquerade return traffic
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE

# Allow loopback WireGuard
iptables -A INPUT -i lo -p udp --dport 51820 -j ACCEPT
```

### nftables

```nftables
table inet gut_server {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        iifname "gut0" udp dport 51820 counter dnat to 127.0.0.1:51820
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname "gut0" counter masquerade
    }
}
```

WireGuard on the server must listen on `0.0.0.0:51820` or `127.0.0.1:51820`.

---

## 3. Key generation

gutd uses a **shared symmetric key** -- generate once, copy to both hosts.

```bash
# Random 256-bit key
gutd genkey

# Passphrase-derived (HKDF-SHA256)
gutd genkey --passphrase "my-strong-passphrase"
```

Set the **same key** in `[peer]` on both relay and server:

```ini
key = a3f1b2c4d5e6f708192a3b4c5d6e7f80a1b2c3d4e5f60718293a4b5c6d7e8f9
# or:
# passphrase = my-strong-passphrase
```

WireGuard keys (for the WireGuard layer) are managed by `wg genkey` separately.

---

## 4. Start and verify

### On relay

```bash
gutd -c /etc/gutd/gutd.conf

# Check veth pair is up
ip addr show gut0
# expected: inet 10.254.0.1/30

# Ping across GUT tunnel
ping -c 3 10.254.0.2
```

### On server

```bash
gutd -c /etc/gutd/gutd.conf

ip addr show gut0
# expected: inet 10.254.0.2/30

ping -c 3 10.254.0.1
```

### WireGuard client config

```ini
[Peer]
Endpoint = 198.51.100.1:51820
AllowedIPs = 0.0.0.0/0
```

---

## 5. Debugging

### Packet capture

```bash
# On relay: incoming WireGuard from clients
tcpdump -i eth0 -n udp port 51820

# On relay: outgoing GUT traffic to server
tcpdump -i eth0 -n 'udp portrange 6000-6003'

# On relay/server: inside the GUT tunnel (should see WireGuard)
tcpdump -i gut0 -n

# On server: incoming GUT from relay
tcpdump -i eth0 -n 'udp portrange 6000-6003'
```

### gutd status

```bash
# Counters snapshot (print to stderr)
kill -USR1 $(pidof gutd)

# Or check stat file if stats_interval > 0
gutd status /run/gutd.stat
```

### NAT state

```bash
conntrack -L | grep 51820
iptables -t nat -L -n -v
```

---

## Notes

**MTU**: GUT overhead is IP(20) + UDP(8) + PMTU(20) = 48 bytes for IPv4.
With `outer_mtu = 1500`, set `mtu = 1452` (conservative: `1420`).
WireGuard itself adds ~60 bytes on top, so effective WG payload is ~1360 bytes.

**Firewall**: ensure nothing blocks:
- UDP 51820 inbound on relay (from WireGuard clients)
- UDP 6000-6003 outbound on relay (GUT to server)

Do **not** add INPUT rules for GUT ports 6000-6003 on the server. The XDP program
processes incoming GUT packets before they reach the iptables/nftables INPUT chain --
GUT traffic never gets to INPUT, it is redirected into `gut0` at the XDP layer.

**Ports**: `ports = 6000,6001,6002,6003` distributes GUT traffic across 4 UDP flows,
improving RSS/NIC queue balancing. Use a single port for simpler setups.

**GUT ports vs WireGuard ports**: in payload-only mode the `ports` list must match
the WireGuard UDP endpoint ports on wire. The relay DNAT redirects WireGuard UDP
(port 51820) into the GUT veth -- GUT then sends it out on the configured GUT ports.
Both sides must agree on the same port list.

**Reload**: `kill -HUP $(pidof gutd)` reloads config without dropping the tunnel.

**IPv6**: set `bind_ip` and `peer_ip` to IPv6 addresses; `address` can be an IPv6
prefix for the tunnel side (e.g. `fd00::1/126`).
