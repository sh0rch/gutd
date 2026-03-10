# Running

## Basic Usage

```bash
# Show version
./gutd --version

# Show help
./gutd --help

# Run with config (Linux)
sudo ./gutd gutd.conf

# Run in pure userspace mode (no BPF load/mount required, no sudo on Linux if using capabilities)
GUTD_USERSPACE=1 ./gutd gutd.conf
# (Alternatively, set `userspace_only = true` in config)

# Run with custom config path
sudo ./gutd /etc/gutd/custom.conf

# Windows (always userspace mode)
gutd.exe gutd.conf
```

## Signals

```bash
# Reload configuration (SIGHUP) — Linux only
sudo pkill -HUP gutd
```

## Hot Reload (SIGHUP)

```bash
sudo kill -HUP $(pgrep gutd)
```

Reloads config from disk and pushes updated key/ports/policy into the running BPF
maps without detaching hooks or recreating the veth pair.

> **Note:** Hot reload via SIGHUP is only available on Linux. On Windows, stop
> and restart the service to apply config changes.

## P2P Mode (Two Machines)

**Machine A** (responder / server):
```ini
[peer]
responder = true
peer_ip = 10.0.0.2
ports = 41000,41001,41002,41003
key = <shared key>
```

**Machine B** (initiator / client):
```ini
[peer]
peer_ip = 10.0.0.1
ports = 41000,41001,41002,41003
key = <shared key>
```

Only `peer_ip`, `ports`, and `key` are required. `bind_ip` defaults to `0.0.0.0`
(auto-detect source IP from routing table).

Start on both machines:
```bash
# Linux
sudo ./gutd gutd.conf

# Windows
gutd.exe gutd.conf
```

gutd creates the veth pair `gut0 <-> gut0_xdp` and assigns addresses automatically.
No manual `ip addr` commands are needed.

## Windows

gutd runs on Windows in **userspace mode only** (no eBPF). It is wire-compatible
with Linux peers running either eBPF or userspace mode.

### Running from Command Line

```powershell
# Run with config file
gutd.exe gutd.conf

# Run with custom path
gutd.exe C:\ProgramData\gutd\gutd.conf
```

### Running as a Windows Service

```powershell
# Install (requires Administrator)
gutd.exe install

# Start / stop
net start gutd
net stop gutd

# Uninstall
gutd.exe uninstall
```

The service reads its config from `C:\ProgramData\gutd\gutd.conf`.

### Default Paths (Windows)

| Item | Path |
|---|---|
| Binary | `C:\Program Files\gutd\gutd.exe` |
| Config | `C:\ProgramData\gutd\gutd.conf` |
| Stats  | `C:\ProgramData\gutd\gutd.stat` |

### Limitations on Windows

- **No eBPF** — `userspace_only = true` is always implied.
- **No SIGHUP** — config reload requires restarting the service (`net stop gutd && net start gutd`).
- **No SIGUSR1** — stats are written periodically to `stat_file` (no on-demand dump).
- BPF-specific settings (`nic`, `own_http3`, `default_policy`) are ignored.

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

You can configure gutd either via a config file or entirely through environment variables.

#### Option A: Config file

Create a directory/file on your router to hold the configuration: `disk1/gutd/gutd.conf`
*(You can edit this file from the RouterOS terminal using `/file/edit disk1/gutd/gutd.conf contents`)*

```ini
[global]
userspace_only = true          # Crucial for RouterOS

[peer]
bind_ip = 172.16.1.2           # The container veth IP
peer_ip = 203.0.113.10         # Your remote gutd server IP
ports = 41000                  # UDP obfuscation port
key = 001122...
```

> **Important:** In userspace mode, gutd forwards decapsulated packets to the
> local WireGuard listener. By default it sends to `127.0.0.1:51820`, which
> only works when WireGuard runs inside the same container/namespace.
> On RouterOS the WireGuard interface lives on the router itself, so you must
> set the `GUTD_WG_HOST` environment variable to the router's WG address reachable
> from the container (e.g. `172.16.1.1:51820`). Set it via `/container/envs/add` even
> when using a config file.

#### Option B: Environment variables (no config file needed)

Pass all settings as env vars directly in the container definition. When `GUTD_PEER_IP` is set and no config file is passed, gutd reads everything from the environment. This avoids mounting a config file entirely.

**4. Create and Start the Container**

#### With config file (Option A)
```routeros
/system/device-mode/update container=yes

/container/mounts/add name=gutd_cfg src=disk1/gutd dst=/etc/gutd

/container/envs/add name=gutd key=GUTD_WG_HOST value=172.16.1.1:51820

/container/add file=disk1/gutd-ros-arm64-v2.X.X.tar interface=veth-gutd \
    mounts=gutd_cfg envlist=gutd root-dir=disk1/gutd-root \
    cmd="--config /etc/gutd/gutd.conf" logging=yes

/container/start [find file~"gutd"]
```

#### With environment variables (Option B)
```routeros
/system/device-mode/update container=yes

/container/envs/add name=gutd key=GUTD_PEER_IP value=203.0.113.10
/container/envs/add name=gutd key=GUTD_BIND_IP value=172.16.1.2
/container/envs/add name=gutd key=GUTD_PORTS value=41000
/container/envs/add name=gutd key=GUTD_KEY value=001122...
/container/envs/add name=gutd key=GUTD_USERSPACE_ONLY value=true
/container/envs/add name=gutd key=GUTD_WG_HOST value=172.16.1.1:51820

/container/add file=disk1/gutd-ros-arm64-v2.X.X.tar interface=veth-gutd \
    envlist=gutd root-dir=disk1/gutd-root logging=yes

/container/start [find file~"gutd"]
```

**5. WireGuard Configuration**

With `GUTD_WG_HOST` set to the router's WG listen address (`172.16.1.1:51820`), gutd forwards
decapsulated WireGuard packets directly to the router's WireGuard interface.

WireGuard on the router must send its outbound packets **to the gutd container**
(not directly to the remote server), so gutd can obfuscate them. Set the WG peer
endpoint to the container's veth IP and **any** of the `GUTD_PORTS` ports:

```routeros
/interface/wireguard/add name=wg0 listen-port=51820
/interface/wireguard/peers/add interface=wg0 public-key="..." \
    endpoint-address=172.16.1.2 endpoint-port=41000 \
    allowed-address=0.0.0.0/0

# Container must reach the remote gutd server on the internet
/ip/firewall/nat/add chain=srcnat src-address=172.16.1.0/24 action=masquerade

# Forward ALL obfuscation ports from public interface to the container
# The remote peer may send on any of these ports
/ip/firewall/nat/add chain=dstnat protocol=udp dst-port=41000-41003 \
    action=dst-nat to-addresses=172.16.1.2
```

> **Multi-port:** When `ports = 41000,41001,41002,41003`, gutd listens on all
> four ports. The remote server distributes inbound traffic across them for
> obfuscation. Outbound traffic from gutd is also rotated across ports
> (round-robin). The DNAT rule must cover the entire port range. WG only needs
> one endpoint port — gutd accepts WireGuard traffic on any of them.
>
> **QUIC fidelity note:** A real QUIC connection uses a single source port
> for its entire lifetime. Multi-port rotation makes the traffic look like
> several parallel QUIC sessions — normal for browsers, but less "clean" than
> a single connection. For maximum stealth, use `ports = 443` (single port).
> Multi-port is useful for throughput diversity and evading per-flow rate limits.

**Traffic flow:**
```
Outbound: WG(router) → 172.16.1.2:41000 (gutd) → obfuscate → remote:41000-41003 (rotated)
Inbound:  remote → router:41000-41003 → DNAT → 172.16.1.2 (gutd) → deobfuscate → 172.16.1.1:51820 (WG)
```

## Dynamic Peer (Client behind NAT)

When the client's IP is not known in advance (NAT, mobile, CGNAT), the **server**
can learn the peer endpoint automatically from the first cryptographically
validated inbound packet.

**Server** config (`/etc/gutd/gutd.conf`):
```ini
[peer]
peer_ip = dynamic             # learn endpoint from first valid packet
ports   = 41000
key     = <shared key>
```

`peer_ip = dynamic` automatically sets `responder = true`. No other fields required.

**Client** config (normal static peer_ip pointing to the server):
```ini
[peer]
peer_ip = 203.0.113.1        # server's public IP
ports   = 41000
key     = <shared key>
```

Using environment variables on the server:
```bash
export GUTD_PEER_IP=dynamic
export GUTD_PORTS=41000
export GUTD_KEY=<shared key>
sudo ./gutd
```

Notes:
- In eBPF mode, `nic` is auto-detected from the default route when `peer_ip = dynamic`.
- In userspace mode, packets that fail DCID/PPN verification are silently dropped
  (anti-probing).
- The server updates the learned endpoint on every valid packet, so the client
  can roam between networks seamlessly.

## Relay Mode

gutd must know its QUIC role (server / client) to generate correct headers.
The role is resolved automatically: `responder = true` or `peer_ip = dynamic`
makes gutd act as QUIC server; otherwise it acts as QUIC client.  You can also
set `responder = true/false` explicitly.

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
