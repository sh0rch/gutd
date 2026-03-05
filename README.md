# gutd v2 - WireGuard Traffic Obfuscator (TC/XDP eBPF over QUIC)

[![CI](https://github.com/sh0rch/gutd/actions/workflows/ci.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/ci.yml)
[![Release](https://github.com/sh0rch/gutd/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/sh0rch/gutd/actions/workflows/release.yml)

<!-- INTEGRATION_TEST_RESULTS_START -->
### Benchmark: gutd vs wg-obfuscator
| Tool | TCP Bandwidth | UDP Bandwidth | UDP Loss |
|---|---|---|---|
| **gutd** ([v2.0.0](https://github.com/sh0rch/gutd/releases/tag/v2.0.0)) | 918 Mbits/sec | 874 Mbits/sec | 0% |
| **wg-obfuscator** ([v1.5](https://github.com/ClusterM/wg-obfuscator/releases)) | 315 Mbits/sec | 242 Mbits/sec | 73% |

<sub><i>* Performance measured using `iperf3` between 2 isolated network namespaces on GitHub Actions Ubuntu 22.04 runners. [See test logic and full logs](https://github.com/sh0rch/gutd/actions/runs/22722690185). Last updated: 2026-03-05 14:34</i></sub>
<!-- INTEGRATION_TEST_RESULTS_END -->







gutd v2 obfuscates WireGuard UDP traffic using a Linux TC/XDP eBPF datapath.
It sits transparently between a WireGuard peer and the network. On egress, the TC
program encapsulates each packet in a fake QUIC Long Header containing a fake SNI,
adds variable padding, and masks the payload with a ChaCha keystream.
On ingress, the XDP program removes the QUIC emulation and unmasks the packet
before passing it up. The XDP program can also optionally mock an HTTP/3 server by
answering DPI UDP probes directly from the kernel ring buffer.
The WireGuard process is unaware of gutd.

gutd v2 obfuscates WireGuard UDP traffic using a Linux TC/XDP eBPF datapath.
It sits transparently between a WireGuard peer and the network. On egress,
the TC program encapsulates each packet in a fake QUIC Long Header containing
a fake SNI, adds variable padding, and masks the payload with a ChaCha keystream.
On ingress, the XDP program removes the QUIC emulation and unmasks the packet
before passing it up. The XDP program can also optionally mock an HTTP/3 server
by answering DPI UDP probes directly from the kernel ring buffer.
The WireGuard process is unaware of gutd.

If QUIC traffic mimicry is not desired and one prefers traffic that looks like
random UDP garbage (valid packets with checksums but intentionally not matching
any recognizable protocol, similar to the **GOST-style random-looking traffic**
used in projects like [xt_wgobfs](https://github.com/infinet/xt_wgobfs)), the earlier implementation **gutd v1.2.0**
may be more suitable. That version provides the same TC/XDP eBPF datapath but
uses a simpler obfuscation format producing random-looking UDP noise instead
of QUIC-style traffic shaping.

## Features

- Fake QUIC Long Header encapsulation to mimic typical HTTPS/QUIC traffic (gutd v2)
- Built-in lightweight HTTP/3 (QUIC) responder at the XDP layer to mock DPI active probes transparently
- WireGuard payload masking with ChaCha (4 rounds by default)
- TC egress hook on a veth pair, XDP ingress hook on the physical NIC
- Port striping: multiple fixed UDP ports per peer
- keepalive probabilistic drop to suppress WireGuard timing patterns
- Variable padding to obscure packet sizes
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
# own_http3 = true        # eBPF XDP responder for active DPI probes on UDP ports
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

## Firewall

**No firewall rules are needed for gutd ports.**

Incoming gutd packets are processed by an XDP program attached directly to the
NIC. XDP runs before the kernel network stack and before netfilter/iptables, so
the packets are intercepted and redirected to the WireGuard interface without
ever reaching the INPUT chain. Adding an iptables or ufw rule for gutd ports
has no effect.

### Relay mode

**IMPORTANT**: To correctly spoof QUIC roles and avoid DPI detection, gutd must know if it's acting as a Server or Client. It determines this automatically by checking the last bit of its internal `address` (the `gut0` interface IP).
**The SERVER's `gut0` IP MUST be odd (e.g. `10.254.0.1`), and the CLIENT's IP MUST be even (e.g. `10.254.0.2`).**

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
  - select port from striping table
  - XOR-mask WireGuard payload bytes with ChaCha keystream
  - append fake QUIC header and variable padding
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
  - verify and strip fake QUIC header and padding
  - derive ChaCha keystream and XOR-unmask WireGuard payload bytes
  - restore original port numbers
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
