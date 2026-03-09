# Configuration

All supported keys (see `gutd.conf` for the annotated example):

```ini
[global]
outer_mtu = 1500          # outer link MTU; runtime: max(route_pmtu, iface_mtu, outer_mtu)
stats_interval = 5        # write /run/gutd.stat every N seconds (0 = off)
userspace_only = false    # set to true to force Mio userspace proxy instead of eBPF
stat_file = /run/gutd.stat

[peer]
name = gut0               # veth pair name: gut0 <-> gut0_xdp
mtu = 1420                # inner MTU hint (loader computes actual from PMTU)
nic = eth0                # ingress NIC for XDP (auto-detected from default route if omitted)
address = 10.0.0.1/30    # point-to-point IP on the veth (/30 or /31 only)
                          #   peer address auto-computed (.1<->.2)
bind_ip = 0.0.0.0        # local bind IP (0.0.0.0 = auto from route src)
peer_ip = 203.0.113.10    # remote peer IP (or "dynamic" — see below)
ports = 41000,41001       # UDP ports (must match WG listen/endpoint ports)
keepalive_drop_percent = 30
# own_http3 = true        # eBPF XDP responder for active DPI probes on UDP ports
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
# passphrase = my-secret  # alternative to key (HKDF-SHA256 derived)
```

## Environment Variables

When `GUTD_PEER_IP` is set and no config file is passed via CLI, gutd reads all settings from environment variables instead of a config file. This is convenient for Docker/container deployments.

| Env Var | Required | Default | Config Equivalent |
|---|---|---|---|
| `GUTD_PEER_IP` | **yes** | — | `peer_ip` (accepts `dynamic`) |
| `GUTD_BIND_IP` | **yes** | — | `bind_ip` |
| `GUTD_ADDRESS` | **yes** | — | `address` |
| `GUTD_PORTS` | **yes** | — | `ports` |
| `GUTD_KEY` | **yes**\* | — | `key` |
| `GUTD_SECRET` | alias | — | `key` (fallback for `GUTD_KEY`) |
| `GUTD_CIPHER` | alias | — | `key` (fallback for `GUTD_SECRET`) |
| `GUTD_PASSPHRASE` | **yes**\* | — | `passphrase` (used if no key vars set) |
| `GUTD_PHRASE` | alias | — | `passphrase` (fallback for `GUTD_PASSPHRASE`) |
| `GUTD_NAME` | no | `gut0` | `name` |
| `GUTD_MTU` | no | `1492` | `mtu` |
| `GUTD_OUTER_MTU` | no | `1500` | `outer_mtu` |
| `GUTD_NIC` | no | auto | `nic` |
| `GUTD_DEFAULT_POLICY` | no | `allow` | `default_policy` |
| `GUTD_KEEPALIVE_DROP_PCT` | no | `30` | `keepalive_drop_percent` |
| `GUTD_OWN_HTTP3` | no | `true` | `own_http3` |
| `GUTD_USERSPACE_ONLY` | no | `false` | `userspace_only` |
| `GUTD_STATS_INTERVAL` | no | `5` | `stats_interval` |
| `GUTD_STAT_FILE` | no | `/run/gutd.stat` | `stat_file` |

\* One of `GUTD_KEY`/`GUTD_SECRET`/`GUTD_CIPHER` **or** `GUTD_PASSPHRASE`/`GUTD_PHRASE` is required.

### Userspace-only runtime variables

These variables are only used in userspace proxy mode.

| Env Var | Default | Description |
|---|---|---|
| `GUTD_WG_HOST` | `127.0.0.1:51820` | Address (`ip:port`) of the local WireGuard listener. In containers (e.g. RouterOS) set to the host/router IP and WG listen port reachable from the container |

### Runtime overrides (always checked, both modes)

| Env Var | Description |
|---|---|
| `GUTD_USERSPACE` | If set to any value, forces userspace proxy mode regardless of config |
| `GUTD_FORCE_L4_CSUM` | Set to `0`/`false`/`no` to disable BPF inner L4 checksum (debug) |

Minimal env-var example (eBPF mode, requires root):

```bash
export GUTD_PEER_IP=203.0.113.10
export GUTD_BIND_IP=0.0.0.0
export GUTD_ADDRESS=10.0.0.1/30
export GUTD_PORTS=41000
export GUTD_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./gutd
```

Minimal env-var example (userspace mode — containers, RouterOS):

```bash
export GUTD_PEER_IP=203.0.113.10
export GUTD_BIND_IP=172.16.1.2       # container's own IP
export GUTD_ADDRESS=10.0.0.2/30
export GUTD_PORTS=41000
export GUTD_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
export GUTD_WG_HOST=172.16.1.1:51820   # router/host WG address (not 127.0.0.1!)
./gutd
```

In userspace mode only 5 env vars are required: `GUTD_PEER_IP`, `GUTD_BIND_IP`,
`GUTD_ADDRESS`, `GUTD_PORTS`, and a key (`GUTD_KEY` or `GUTD_PASSPHRASE`).
eBPF-specific settings (`GUTD_NIC`, `GUTD_OWN_HTTP3`, `GUTD_DEFAULT_POLICY`, etc.)
are ignored. Set `GUTD_WG_HOST` when WireGuard runs on the host, not inside the container.

Dynamic peer env-var example (server side):

```bash
export GUTD_PEER_IP=dynamic
export GUTD_BIND_IP=0.0.0.0
export GUTD_ADDRESS=10.0.0.1/30
export GUTD_PORTS=41000
export GUTD_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./gutd
```

## Dynamic Peer (NAT Traversal)

When the remote peer is behind NAT and its IP is not known in advance, set:

```ini
peer_ip = dynamic
```

or via environment variable:

```bash
export GUTD_PEER_IP=dynamic
```

This is a **server-side** setting — the server must have a stable public IP.
The client always uses a normal static `peer_ip` pointing to the server.

How it works:

- **eBPF mode**: XDP ingress validates each inbound packet by its QUIC DCID and PPN
  (cryptographic proof of possession of the shared key). On success, the source
  IP:port is written to a BPF map (`peer_endpoint_map`). TC egress reads the
  learned endpoint from this map for outbound packets.
- **Userspace mode**: the same DCID/PPN verification is performed in `quic_verify()`.
  Packets that fail are silently dropped (anti-probing). On success, the sender
  address is saved and used for all subsequent outbound traffic.

No additional firewall rules are needed. Anti-probing remains active: packets
that do not pass cryptographic validation are dropped (or answered with a QUIC
Version Negotiation in eBPF mode).

## Key Generation

```bash
# Random 256-bit key
gutd genkey

# Derive from passphrase
gutd genkey --passphrase "my secret phrase"
```

## MTU

gutd v2 encapsulates WireGuard UDP packets inside a fake QUIC wrapper.
It prepends a QUIC Long Header (including SNI) to every packet and appends
variable padding to obfuscate packet length. These additions increase the
packet size.

### gutd config `mtu`

Sets the MTU of the gut TUN interface (the veth pair gutd creates). gutd also
applies this value as `gso_max_size` on both veth endpoints to prevent the
kernel from generating super-segments larger than the link can carry.

Default: `1420`. This is the standard WireGuard veth MTU and works for most
setups. The 4-byte gutd metadata overhead is covered by the built-in 20-byte
PMTU reserve.

### WireGuard `wg0` MTU

Set `wg0` MTU to the standard WireGuard recommendation for your link:

```
wg0 mtu = outer_link_mtu - 60   (20 IP + 8 UDP + 32 WireGuard header/tag)
```

For a 1500-byte Ethernet link: `wg0 mtu = 1420` (default WireGuard value).

The 4 extra bytes added by gutd fit within the 20-byte PMTU headroom already
accounted for in WireGuard's MTU formula, so **no adjustment to wg0 MTU is
needed** when running WireGuard over gutd.

### `outer_mtu` config key

Maximum size of the outer Ethernet frame on the physical link. Default: `1500`.
Override only if your uplink uses jumbo frames or has a reduced MTU (e.g. PPPoE: `1492`).
