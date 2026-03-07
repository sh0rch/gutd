# docker/

This directory contains all Docker-related files for gutd.

## Files

| File | Purpose |
|---|---|
| `Dockerfile.x86_64` | **Build image** — compiles a fully static musl binary for `x86_64` |
| `Dockerfile.cross` | **Cross-build toolchain** — used by `cross` to compile for `aarch64`, `armv7`, `mips`, `mipsle` |
| `Dockerfile.run` | **Runtime image** — `FROM scratch`, multi-arch; contains only the gutd binary |
| `build-multiarch.sh` | Builds binaries for all platforms and assembles a multi-arch Docker manifest |
| `docker-compose.example.yml` | Example `docker compose` deployment with env-var config |

---

## Build images

### x86_64 (native)

```bash
docker build -t gutd-builder -f docker/Dockerfile.x86_64 .
CID=$(docker create gutd-builder)
docker cp "$CID:/out/gutd" dist/gutd-amd64
docker rm "$CID"
```

Or via the helper script (also handles musl static linking):

```bash
./build-musl.sh          # build
./build-musl.sh verify   # build + verify static + smoke test
```

### Other architectures (aarch64 / armv7 / mips)

Uses [`cross`](https://github.com/cross-rs/cross) with `docker/Dockerfile.cross` as the per-target toolchain image (configured in `Cross.toml`):

```bash
cross build --release --target aarch64-unknown-linux-musl RPi 4+
cross build --release --target armv7-unknown-linux-musleabihf


```

---

## Runtime image

`Dockerfile.run` builds a `FROM scratch` image that contains only the static gutd binary.
It is multi-arch: the same image tag works on `x86_64`, `aarch64`, `armv7`, and `mips` hosts —
Docker automatically pulls the right variant.

### Quick single-arch build (current machine only)

```bash
make docker-build                    # builds amd64 runtime image tagged gutd:latest
make docker-build DOCKER_TAG=myimg   # custom tag
```

### Multi-arch build + push (for deployment on mixed hardware)

```bash
bash docker/build-multiarch.sh --tag yourrepo/gutd:latest --push
```

This produces a manifest list with `linux/amd64` and `linux/arm64` by default.
Use `--platforms` to add more:

```bash
bash docker/build-multiarch.sh \
  --platforms linux/amd64,linux/arm64,linux/arm/v7,linux/mips,linux/mipsle \
  --tag yourrepo/gutd:latest --push
```

Or via Make:

```bash
make docker-push DOCKER_TAG=yourrepo/gutd:latest
make docker-push DOCKER_TAG=yourrepo/gutd:latest PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7
```

### Supported platforms

| Docker platform | Rust target | Hardware examples |
|---|---|---|
| `linux/amd64` | `x86_64-unknown-linux-musl` | PC / VPS / server |
| `linux/arm64` | `aarch64-unknown-linux-musl` | Raspberry Pi 4/5 |
| `linux/arm/v7` | `armv7-unknown-linux-musleabihf` | Raspberry Pi 2/3, older routers |

| `linux/mipsle` | `mipsel-unknown-linux-musl` | hEX lite |

---

## Running the container

gutd attaches TC/XDP BPF programs to real network interfaces, so it needs:

- `--network host` — to see the same NICs as the host
- `--cap-add NET_ADMIN SYS_ADMIN NET_RAW` — for BPF and interface manipulation
- `-v /sys/fs/bpf:/sys/fs/bpf` — BPF filesystem for pinning objects across reloads

### Config file mode

```bash
docker run --rm --privileged \
  --network host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /path/to/gutd.conf:/etc/gutd.conf:ro \
  yourrepo/gutd:latest
```

### Environment variable mode (no config file needed)

```bash
docker run --rm --privileged \
  --network host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e GUTD_BIND_IP=0.0.0.0 \
  -e GUTD_PEER_IP=203.0.113.10 \
  -e GUTD_ADDRESS=10.99.0.1/30 \
  -e GUTD_PORTS=41000,41001,41002,41003 \
  -e GUTD_KEY=<64-char-hex> \
  -e GUTD_NIC=eth0 \
  yourrepo/gutd:latest
```

Generate a key: `gutd genkey` or `docker run --rm yourrepo/gutd:latest genkey`

See `docker/docker-compose.example.yml` for a full `docker compose` example.

### Config reload (SIGHUP)

```bash
# send SIGHUP to reload config without restart
docker kill --signal HUP <container-name-or-id>
# or with compose:
docker compose kill -s HUP gutd
```

---

## How gutd relates to WireGuard

gutd is **transparent to WireGuard** — WG is unaware of it and requires no patching.
gutd inserts itself into the data path by attaching BPF programs to the kernel:

```
WireGuard process
      │  UDP on gut0 (veth, inner)
      ▼
   TC egress hook  ← gutd wraps each WG packet in a fake QUIC Long Header
      │              + ChaCha masking + random padding
      ▼
   Physical NIC (eth0)  → internet
      │                     obfuscated UDP on GUTD_PORTS

   Physical NIC (eth0)  ← internet
      │                     obfuscated UDP on GUTD_PORTS
      ▼
   XDP ingress hook  ← gutd strips QUIC header, unmasks payload
      │
      ▼
WireGuard process
      │  UDP on gut0 (veth, inner)
```

gutd creates a `gut0 ↔ gut0_xdp` veth pair automatically.
WireGuard should use `gut0` as the interface for its tunnel traffic.
The physical NIC (`GUTD_NIC`) is only used for the obfuscated outer transport.

Because the container uses `--network host`, BPF programs are attached to **real host interfaces** — the container boundary is irrelevant to the data path.
There are no `-p` port forwarding rules; the ports are host-level UDP sockets.

---

## The `GUTD_PORTS` / `ports` parameter

`GUTD_PORTS` is a comma-separated list of **UDP port numbers used on the external (internet-facing) wire**.
gutd distributes obfuscated packets across all listed ports (port striping) and the XDP hook demuxes them back.

**These ports must be:**
1. **Open in the host firewall** — the XDP hook runs before the kernel netfilter stack (it's pre-`iptables`), but the host OS must not drop the incoming UDP before XDP gets to it.  
   With `nftables`:
   ```bash
   nft add rule inet filter input udp dport { 41000, 41001, 41002, 41003 } accept
   ```
   With `iptables`:
   ```bash
   iptables -A INPUT -p udp -m multiport --dports 41000,41001,41002,41003 -j ACCEPT
   ```
   Actually gutd's XDP hook intercepts packets *before* they reach iptables/nftables, so the firewall only needs to not have a DROP policy at the XDP level. If `GUTD_DEFAULT_POLICY = drop` is set, all non-GUT traffic on those ports is dropped at XDP — you don't need separate firewall rules for them.

2. **Matching on both peers** — both sides must list exactly the same ports in the same order.

3. **Not `-p` published in Docker** — since the container runs with `--network host`, Docker port mapping (`-p 41000:41000`) is neither needed nor effective. The ports are bound directly on the host network stack.

**Number of ports:** the more ports, the better traffic pattern diversity. 1–16 ports are supported. 4 ports (e.g. `41000,41001,41002,41003`) is a practical default.

---

## WireGuard setup with gutd in Docker

gutd only obfuscates — it does not replace WireGuard. WireGuard runs separately on the host (or in another container with `--network host`).

### P2P: two machines, WireGuard between them

Both machines run gutd (in Docker) **and** WireGuard. gutd wraps WG traffic transparently.

**Machine A** (`192.0.2.1`) — e.g. a VPS:

```bash
# 1. Start gutd container
docker run -d --name gutd --restart unless-stopped \
  --network host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e GUTD_BIND_IP=0.0.0.0 \
  -e GUTD_PEER_IP=198.51.100.2 \   # Machine B public IP
  -e GUTD_ADDRESS=10.254.0.1/30 \
  -e GUTD_PORTS=41000,41001,41002,41003 \
  -e GUTD_KEY=<shared-key> \
  yourrepo/gutd:latest

# 2. Configure WireGuard to use gut0 as the tunnel endpoint
# /etc/wireguard/wg0.conf on Machine A:
#   [Interface]
#   Address = 10.99.0.1/30
#   ListenPort = 51820
#   PrivateKey = <A private key>
#
#   [Peer]
#   PublicKey = <B public key>
#   Endpoint = 10.254.0.2:51820   ← gut0 peer address, NOT Machine B public IP
#   AllowedIPs = 10.99.0.2/32

wg-quick up wg0
```

**Machine B** (`198.51.100.2`) — mirror config, swapped IPs:

```bash
docker run -d --name gutd --restart unless-stopped \
  --network host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e GUTD_BIND_IP=0.0.0.0 \
  -e GUTD_PEER_IP=192.0.2.1 \     # Machine A public IP
  -e GUTD_ADDRESS=10.254.0.2/30 \ # other end of /30
  -e GUTD_PORTS=41000,41001,41002,41003 \
  -e GUTD_KEY=<same-shared-key> \
  yourrepo/gutd:latest
```

```ini
# /etc/wireguard/wg0.conf on Machine B:
[Interface]
Address = 10.99.0.2/30
ListenPort = 51820
PrivateKey = <B private key>

[Peer]
PublicKey = <A public key>
Endpoint = 10.254.0.1:51820   # ← gut0 peer address on Machine A side
AllowedIPs = 10.99.0.1/32
```

> **Key point:** The WireGuard `Endpoint` points to the **gut0 tunnel address** of the remote peer (e.g. `10.254.0.2:51820`), not to the public IP. gutd intercepts the WG UDP traffic on `gut0`, obfuscates it, and delivers it to the real peer via the external ports.

---

### Relay: WireGuard clients → gutd relay → server with WireGuard

Use this when WireGuard clients connect to a relay (e.g. a VPS), and the relay forwards their traffic to the actual WireGuard server via an obfuscated gutd tunnel.

```
WG clients  ──:51820──▶  Relay VPS  ══GUT on 41000-41003══▶  WG Server
                         (Docker)                              (Docker)
```

**Relay** (`198.51.100.1`):

```bash
docker run -d --name gutd --restart unless-stopped \
  --network host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e GUTD_BIND_IP=0.0.0.0 \
  -e GUTD_PEER_IP=203.0.113.1 \   # server public IP
  -e GUTD_ADDRESS=10.254.0.1/30 \
  -e GUTD_PORTS=41000,41001,41002,41003 \
  -e GUTD_KEY=<shared-key> \
  yourrepo/gutd:latest
```

```bash
# DNAT: WireGuard clients arriving on :51820 → gut0 peer address on server side
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p udp --dport 51820 \
    -j DNAT --to-destination 10.254.0.2
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o gut0 -j ACCEPT
iptables -A FORWARD -i gut0 -o eth0 -j ACCEPT
```

**Server** (`203.0.113.1`):

```bash
docker run -d --name gutd --restart unless-stopped \
  --network host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -e GUTD_BIND_IP=0.0.0.0 \
  -e GUTD_PEER_IP=198.51.100.1 \  # relay public IP
  -e GUTD_ADDRESS=10.254.0.2/30 \
  -e GUTD_PORTS=41000,41001,41002,41003 \
  -e GUTD_KEY=<same-shared-key> \
  yourrepo/gutd:latest
```

```bash
# Forward gut0 traffic to local WireGuard
iptables -t nat -A PREROUTING -i gut0 -p udp \
    -j DNAT --to-destination 127.0.0.1:51820
iptables -t nat -A POSTROUTING -o gut0 -j MASQUERADE
iptables -A INPUT -i lo -p udp --dport 51820 -j ACCEPT
```

WireGuard on the server listens on `127.0.0.1:51820` or `0.0.0.0:51820` as usual.
WG clients connect to the relay's public IP on port `51820` — they are unaware of gutd.

See [examples/wireguard-relay.md](../examples/wireguard-relay.md) for the full relay example with nftables.

---

## Environment variables reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `GUTD_BIND_IP` | yes* | — | Local listen address (`0.0.0.0` or specific IP) |
| `GUTD_PEER_IP` | yes* | — | Remote peer IP |
| `GUTD_ADDRESS` | yes* | — | Tunnel CIDR for this end (e.g. `10.99.0.1/30`) |
| `GUTD_PORTS` | yes* | — | Comma-separated port list (e.g. `41000,41001`) |
| `GUTD_KEY` | yes† | — | 64-char hex key |
| `GUTD_PASSPHRASE` | yes† | — | Passphrase (key derived via HKDF-SHA256) |
| `GUTD_NAME` | no | `gut0` | Peer name |
| `GUTD_NIC` | no | auto | Host NIC to attach XDP to |
| `GUTD_MTU` | no | `1492` | Inner tunnel MTU |
| `GUTD_OUTER_MTU` | no | `1500` | Outer (physical) MTU |
| `GUTD_OWN_HTTP3` | no | `true` | Respond to QUIC Version Negotiation probes |
| `GUTD_KEEPALIVE_DROP_PERCENT` | no | `75` | % of keepalive packets to drop |
| `GUTD_DEFAULT_POLICY` | no | `allow` | XDP policy for non-GUT traffic (`allow`\|`drop`) |
| `GUTD_STATS_INTERVAL` | no | `0` | Stats dump interval in seconds (0 = off) |
| `GUTD_STAT_FILE` | no | `/run/gutd.stat` | Path for stats file |

\* Required when using env-var mode (i.e. when `GUTD_PEER_IP` is set and no `--config` is given).  
† One of `GUTD_KEY` or `GUTD_PASSPHRASE` is required.
