# Configuration

All supported keys (see `gutd.conf` for the annotated example):

Minimal config (only 3 fields required per peer):

```ini
[peer]
peer_ip = 203.0.113.10
ports = 41000
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Full reference with all defaults shown:

```ini
[global]
# outer_mtu = 1500          # outer link MTU; runtime: max(route_pmtu, iface_mtu, outer_mtu)
# stats_interval = 5        # write /run/gutd.stat every N seconds (0 = off)
# userspace_only = false    # set to true to force Mio userspace proxy instead of eBPF
#                           # (always true on Windows)
# stat_file = /run/gutd.stat  # Linux default
# stat_file = C:\ProgramData\gutd\gutd.stat  # Windows default

[peer]
# name = gut0               # veth pair name: gut0 <-> gut0_xdp  [default: gut0]
# mtu = 1420                # inner MTU hint (loader computes from PMTU)  [default: 1492]
# nic = eth0                # ingress NIC for XDP  [default: auto-detect]
# bind_ip = 0.0.0.0         # local bind IP  [default: 0.0.0.0]
# responder = true           # QUIC server role; inferred from dynamic_peer if not set
peer_ip = 203.0.113.10      # remote peer IP (or "dynamic" — see below)
ports = 41000,41001         # UDP ports (must match WG listen/endpoint ports)
# keepalive_drop_percent = 30
# own_http3 = true           # eBPF XDP responder for active DPI probes
# obfs = quic                # obfuscation mode: quic (default) or noise (random UDP)
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
# passphrase = my-secret     # alternative to key (HKDF-SHA256 derived)
```

### Obfuscation mode

The `obfs` key controls how gutd-encapsulated packets look on the wire:

- **`quic`** (default) — packets carry a recognizable QUIC Long Header with a fake SNI. Effective against WireGuard-specific DPI, but packets are identifiable as QUIC.
- **`noise`** — additionally masks the first bytes of the QUIC header so that packets appear as random UDP traffic. Useful when QUIC itself is blocked or throttled.

Both sides of the tunnel must use the same `obfs` mode.

### Responder role

gutd must know whether it acts as the QUIC "server" (responder) or "client"
(initiator) to generate correct header formats. The role is resolved as follows:

1. **Explicit** `responder = true/false` in config (or `GUTD_RESPONDER` env var)
2. **From `peer_ip = dynamic`** — implies responder (server side)
3. **Default**: initiator

## Environment Variables

When `GUTD_PEER_IP` is set and no config file is passed via CLI, gutd reads all settings from environment variables instead of a config file. This is convenient for Docker/container deployments.

| Env Var | Required | Default | Config Equivalent |
|---|---|---|---|
| `GUTD_PEER_IP` | **yes** | — | `peer_ip` (accepts `dynamic`) |
| `GUTD_PORTS` | **yes** | — | `ports` |
| `GUTD_KEY` | **yes**\* | — | `key` |
| `GUTD_SECRET` | alias | — | `key` (fallback for `GUTD_KEY`) |
| `GUTD_CIPHER` | alias | — | `key` (fallback for `GUTD_SECRET`) |
| `GUTD_PASSPHRASE` | **yes**\* | — | `passphrase` (used if no key vars set) |
| `GUTD_PHRASE` | alias | — | `passphrase` (fallback for `GUTD_PASSPHRASE`) |
| `GUTD_BIND_IP` | no | `0.0.0.0` | `bind_ip` |
| `GUTD_RESPONDER` | no | auto | `responder` (inferred from `peer_ip = dynamic`) |
| `GUTD_NAME` | no | `gut0` | `name` |
| `GUTD_MTU` | no | `1492` | `mtu` |
| `GUTD_OUTER_MTU` | no | `1500` | `outer_mtu` |
| `GUTD_NIC` | no | auto | `nic` |
| `GUTD_DEFAULT_POLICY` | no | `allow` | `default_policy` |
| `GUTD_KEEPALIVE_DROP_PCT` | no | `30` | `keepalive_drop_percent` |
| `GUTD_OWN_HTTP3` | no | `true` | `own_http3` |
| `GUTD_OBFS` | no | `quic` | `obfs` (`quic` or `noise`) |
| `GUTD_USERSPACE_ONLY` | no | `false` | `userspace_only` |
| `GUTD_STATS_INTERVAL` | no | `5` | `stats_interval` |
| `GUTD_STAT_FILE` | no | `/run/gutd.stat` | `stat_file` |

\* One of `GUTD_KEY`/`GUTD_SECRET`/`GUTD_CIPHER` **or** `GUTD_PASSPHRASE`/`GUTD_PHRASE` is required.

> **Windows note:** Default `stat_file` is `C:\ProgramData\gutd\gutd.stat`.
> Default config path is `C:\ProgramData\gutd\gutd.conf`.
> eBPF-specific variables (`GUTD_NIC`, `GUTD_OWN_HTTP3`, `GUTD_DEFAULT_POLICY`) are ignored.

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
export GUTD_PORTS=41000
export GUTD_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
sudo ./gutd
```

Minimal env-var example (userspace mode — containers, RouterOS):

```bash
export GUTD_PEER_IP=203.0.113.10
export GUTD_BIND_IP=172.16.1.2       # container's own IP
export GUTD_PORTS=41000
export GUTD_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
export GUTD_WG_HOST=172.16.1.1:51820   # router/host WG address (not 127.0.0.1!)
./gutd
```

Only 3 env vars are strictly required: `GUTD_PEER_IP`, `GUTD_PORTS`, and a key
(`GUTD_KEY` or `GUTD_PASSPHRASE`). Everything else has sensible defaults.
eBPF-specific settings (`GUTD_NIC`, `GUTD_OWN_HTTP3`, `GUTD_DEFAULT_POLICY`, etc.)
are ignored in userspace mode. Set `GUTD_WG_HOST` when WireGuard runs on the
host, not inside the container.

Dynamic peer env-var example (server side):

```bash
export GUTD_PEER_IP=dynamic
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
  IP:port is written to a per-client LRU BPF map (`client_map`, keyed by WG index).
  TC egress reads the learned endpoint from this map for outbound packets.
  Multiple clients behind NAT are supported — each gets a separate map entry.
- **Userspace mode**: the same DCID/PPN verification is performed in `quic_verify()`.
  Packets that fail are silently dropped (anti-probing). On success, the sender
  address is stored per WG client index and used for subsequent outbound traffic.

In dynamic peer mode, server-initiated WireGuard rekeys (Type 1) are silently
dropped — the client will re-initiate the handshake. This is necessary because
Type 1 packets lack a receiver index for routing.

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
