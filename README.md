# gutd - WireGuard Traffic Obfuscator (TC/XDP eBPF)

[![CI](https://github.com/sh0rch/gutd/actions/workflows/ci.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/ci.yml)
[![Integration Test](https://github.com/sh0rch/gutd/actions/workflows/run-test-integration.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/run-test-integration.yml)
[![Release](https://github.com/sh0rch/gutd/actions/workflows/release.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/release.yml)

<!-- INTEGRATION_TEST_RESULTS_START -->
| Proto | Bandwidth | Packet Loss |
|---|---|---|
| **TCP** | 1.01 Gbits/sec | - |
| **UDP** | 1.13 Gbits/sec | 0% |
<!-- INTEGRATION_TEST_RESULTS_END -->


gutd obfuscates WireGuard UDP traffic in-place using a Linux TC/XDP eBPF datapath.
It sits transparently between a WireGuard peer and the network: on egress the TC
program masks each packet with a ChaCha keystream; on ingress the XDP program
unmasks it before passing it up. The WireGuard process is unaware of gutd.

## Features

- In-place WireGuard payload masking with ChaCha (4 rounds by default)
- TC egress hook on a veth pair, XDP ingress hook on the physical NIC
- Port striping: multiple fixed UDP ports per peer
- keepalive probabilistic drop to suppress WireGuard timing patterns
- ballast padding for short payloads
- Hot reload via SIGHUP (BPF map update, no restart)
- Multi-peer support (one veth pair + BPF program per peer)
- Static musl build supported
- IPv4 and IPv6 outer transport
- Stats readable via `gutd status` or SIGUSR1 signal

## Statistics

```bash
# Print BPF map counters to stderr (while daemon is running)
kill -USR1 $(pidof gutd)

# Read latest counters from stat file
gutd status
# or:
cat /run/gutd.stat
```

The stat file is written periodically (controlled by `stats_interval` in config).
Counters include per-peer egress/ingress packet counts, drops, bytes, and mask operations.

## Wire Format

```
UDP payload = WireGuard payload (in-place transformed)
```

### Payload Transform (current)

- Keepalive packets (`type=4`, 32 bytes) may be probabilistically dropped using `keepalive_drop_percent`.
- For short packets, ballast `3..63` bytes may be appended; ballast length is stored in `reserved[0]` (`byte 1`).
- First 16 bytes are XOR-masked with ChaCha block 0.
- For `type=1`, bytes `[132..147]` are additionally XOR-masked with ChaCha block 1.
- For `type=2`, bytes `[76..91]` are additionally XOR-masked with ChaCha block 1.

## Build Instructions

The build system includes dynamic versioning from git tags. See [VERSIONING.md](VERSIONING.md) for details.

### Standard Build

```bash
cargo build --release

# Check version
./target/release/gutd --version
```

### Static Build (musl)

The musl build requires Docker (libbpf-sys cannot be cross-compiled with plain musl-gcc):

```bash
# Build static binary into target/musl/gutd
./build-musl.sh

# Build and verify it is fully static + smoke-test in Alpine
./build-musl.sh verify

# Force Docker image rebuild (e.g. after Dockerfile change)
./build-musl.sh --rebuild
```

The resulting binary is at `target/musl/gutd`.

See [METRICS.md](METRICS.md) for counter descriptions.

## Configuration

All supported keys (see `gutd.conf` for the annotated example):

```ini
[global]
outer_mtu = 1500          # outer link MTU; runtime: max(route_pmtu, iface_mtu, outer_mtu)
stats_interval = 5        # write /run/gutd.stat every N seconds (0 = off)
stat_file = /run/gutd.stat

[peer]
name = gut0               # veth pair name: gut0 <-> gut0_xdp
mtu = 1420                # inner MTU hint (loader computes actual from PMTU)
nic = eth0                # ingress NIC for XDP (auto-detected from default route if omitted)
address = 10.0.0.1/30    # point-to-point IP on the veth (/30 or /31 only)
                          #   peer address auto-computed (.1<->.2)
bind_ip = 0.0.0.0        # local bind IP (0.0.0.0 = auto from route src)
peer_ip = 203.0.113.10
ports = 41000,41001       # UDP ports (must match WG listen/endpoint ports)
keepalive_drop_percent = 75
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
# passphrase = my-secret  # alternative to key (HKDF-SHA256 derived)
```

### Key Generation

```bash
# Random 256-bit key
gutd genkey

# Derive from passphrase
gutd genkey --passphrase "my secret phrase"
```

## Running

### Basic Usage

```bash
# Show version
./gutd --version

# Show help
./gutd --help

# Run with config
sudo ./gutd gutd.conf

# Run with custom config path
sudo ./gutd /etc/gutd/custom.conf
```

### Signals

```bash
# Reload configuration (SIGHUP)
sudo pkill -HUP gutd
```

### P2P Mode (Two Machines)

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

## Hot Reload (SIGHUP)

```bash
sudo kill -HUP $(pgrep gutd)
```

Reloads config from disk and pushes updated key/ports/policy into the running BPF
maps without detaching hooks or recreating the veth pair.

## MTU

gutd operates on WireGuard's outer UDP packets in-place. It always appends
4 bytes of metadata (`GUT_L4_META_SIZE`) to every processed packet.
Short packets (WireGuard handshake and keepalive, payload < 220 bytes) also
receive 0–63 bytes of ChaCha-derived ballast to obscure their size; these are
small enough that ballast does not affect MTU.

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

## Firewall

**No firewall rules are needed for gutd ports.**

Incoming gutd packets are processed by an XDP program attached directly to the
NIC. XDP runs before the kernel network stack and before netfilter/iptables, so
the packets are intercepted and redirected to the WireGuard interface without
ever reaching the INPUT chain. Adding an iptables or ufw rule for gutd ports
has no effect.

### Relay mode

In relay mode a separate machine accepts WireGuard connections from clients and
forwards them through a gutd tunnel to the final server. This requires standard
NAT rules — they apply to the WireGuard traffic, not the gutd ports.

See [examples/wireguard-relay.md](examples/wireguard-relay.md) for the full
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

WireGuard must listen on `0.0.0.0` (all interfaces, including `gut0`) on
whatever port is used as the DNAT target on the relay.

## Testing

### Unit Tests

Run unit and integration tests:

```bash
cargo test
```

Test suites included:
- ChaCha masking / unmasking round-trip
- Config parser (single peer, multi-peer, duplicate port rejection)
- MAC / veth addressing helpers
- Kernel-version detection

### Integration Tests with WireGuard

```bash
# Full integration test (requires sudo, wireguard-tools, iperf3, tcpdump, jq)
make test-integration

# Or directly:
sudo bash tests/integration-wg.sh
```

The test spins up two network namespaces, runs gutd in each with a shared key,
establishes a WireGuard tunnel through the gutd veth pair, and verifies connectivity
with iperf3. Artifacts written to `/tmp/gutd-test-*.{log,pcap,txt}`.

See [tests/README.md](tests/README.md) for details.



## Architecture

gutd creates a **veth pair** (`gut0 ↔ gut0_xdp`) and attaches two BPF programs:
- **TC egress** on `gut0` — intercepts outgoing WireGuard UDP before it hits the wire
- **XDP ingress** on the physical NIC — intercepts incoming obfuscated UDP before the kernel stack sees it

WireGuard is configured to use the gutd veth address as its endpoint. It is
unaware of gutd and sees a normal UDP socket.

### Egress (outbound)

```
WireGuard
  | sends UDP to peer via gut0 (e.g. wg endpoint = 10.8.0.2:41000)
  v
gut0  [TC egress BPF]
  - select port from striping table (rotates per packet)
  - XOR-mask WireGuard payload bytes with ChaCha keystream
  - append 4-byte metadata + 0..63 byte ballast for short packets
  - rewrite outer UDP src/dst port
  v
gut0_xdp  (veth peer, devmap redirect target)
  v
physical NIC
  v
wire  - observer sees opaque UDP on pseudo-random port, no WireGuard signature
```

### Ingress (inbound)

```
wire  - opaque UDP arrives on one of the configured ports
  v
physical NIC  [XDP ingress BPF]
  - check dst port is in gutd port table; pass-through everything else
  - derive ChaCha keystream from masked nonce
  - XOR-unmask WireGuard payload bytes
  - strip metadata + ballast, restore original port numbers
  - rewrite IP/UDP lengths and checksums
  - bpf_redirect_map → gut0_xdp  (bypasses kernel stack entirely)
  v
gut0_xdp → gut0
  v
WireGuard  (receives a normal WireGuard UDP packet)
```

### Userspace daemon

gutd (userspace) only handles startup and control:
- Creates the veth pair and assigns the tunnel address
- Loads and attaches the BPF programs
- Initialises BPF maps (key, ports, peer IP, MAC addresses)
- Updates BPF maps on SIGHUP without restarting
- Tears down the veth pair on exit

All per-packet processing runs entirely in the kernel BPF programs.

## Security

gutd provides **traffic obfuscation, not encryption**.

- Masking with ChaCha prevents passive DPI signature matching
- An active attacker who knows the key can unmask traffic
- WireGuard itself provides the cryptographic security layer
- gutd is designed to be run *underneath* WireGuard, not instead of it

## Troubleshooting

### veth pair not created
```bash
# Check gutd log output for errors
journalctl -u gutd -n 50
# or run in foreground:
sudo gutd -c /etc/gutd.conf
```

### XDP not attaching
```bash
# Kernel >= 5.2 required
uname -r

# Check that the ingress NIC name is correct (auto-detected or set via nic = ...)
ip link show
```

### No packets received
```bash
# Check firewall allows configured UDP ports
sudo iptables -L -n -v | grep 41000

# Verify peer IP is reachable
ping <peer_ip>

# Check BPF stats
gutd status
```

## Dependencies

- `libc` - system calls
- `anyhow` - error handling
- `nix` - Linux-specific IO
- `libbpf-rs` / `libbpf-sys` - BPF program loading and map management
- `libbpf-cargo` - BPF skeleton generation at build time

## License

See LICENSE file.

## Contributing

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for architecture and implementation details.

## Related Projects

This project is part of a lineage of WireGuard traffic obfuscation tools:

```
 xt_wgobfs  (iptables/netfilter, original concept)
     |
 nf_wgobfs  (nftables/netfilter, userspace)
     |
  gutd       (TC/XDP eBPF, this project)
```

- [xt_wgobfs](https://github.com/infinet/xt_wgobfs) - original iptables/xt_tables WireGuard
  obfuscation module; the idea of in-place WireGuard payload masking originates here.

- [nf_wgobfs](https://github.com/sh0rch/nf_wgobfs) - nftables-based successor;
  gutd is the natural continuation of that project, migrated to the TC/XDP eBPF
  datapath for zero-copy kernel-side processing and multi-port striping.

## References

- [IMPLEMENTATION.md](IMPLEMENTATION.md) - architecture and internals
- [BUILD.md](BUILD.md) - build instructions
- [METRICS.md](METRICS.md) - stats counters
- `gutd.conf` - annotated example config
