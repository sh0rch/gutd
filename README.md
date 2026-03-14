# gutd v2 — WireGuard Traffic Obfuscator (TC/XDP eBPF)

[![CI](https://github.com/sh0rch/gutd/actions/workflows/ci.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/ci.yml)
[![Release](https://github.com/sh0rch/gutd/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/sh0rch/gutd/actions/workflows/release.yml)

<!-- INTEGRATION_TEST_RESULTS_START -->
### Benchmark: gutd vs wg-obfuscator
| Tool | TCP Bandwidth | UDP Bandwidth | UDP Loss |
|---|---|---|---|
| **gutd (eBPF)** ([v2.5.0](https://github.com/sh0rch/gutd/releases/tag/v2.5.0)) | 878 Mbits/sec | 778 Mbits/sec | 0.023% |
| **gutd (Userspace)** ([v2.5.0](https://github.com/sh0rch/gutd/releases/tag/v2.5.0)) | 920 Mbits/sec | 669 Mbits/sec | 28% |
| **wg-obfuscator** ([v1.5](https://github.com/ClusterM/wg-obfuscator/releases)) | 322 Mbits/sec | 269 Mbits/sec | 68% |
<sub><i>* Performance measured using `iperf3` between 2 isolated network namespaces on GitHub Actions Ubuntu 22.04 runners. [See test logic and full logs](https://github.com/sh0rch/gutd/actions/runs/23080561396). Last updated: 2026-03-14 04:39</i></sub>
<!-- INTEGRATION_TEST_RESULTS_END -->

**gutd v2** transparently obfuscates WireGuard UDP traffic using a Linux TC/XDP eBPF datapath. On egress it wraps each packet in a fake QUIC Long Header with a fake SNI, adds variable padding and masks the payload with a ChaCha keystream. On ingress the XDP program strips the QUIC emulation and unmasks the packet before the kernel stack sees it. WireGuard is completely unaware of gutd. A **pure userspace mode** (Mio-based, wire-compatible with eBPF path) is available for older kernels, unprivileged containers, MikroTik RouterOS, and **Windows**.

## Features

- Fake QUIC Long Header encapsulation to mimic typical HTTPS/QUIC traffic
- Optional `obfs=noise` mode — masks QUIC signatures so packets look like random UDP
- Built-in lightweight HTTP/3 (QUIC) responder at the XDP layer to mock DPI active probes
- WireGuard payload masking with ChaCha (4 rounds by default)
- TC egress hook on a veth pair, XDP ingress hook on the physical NIC
- Port striping: multiple fixed UDP ports per peer
- Keepalive probabilistic drop to suppress WireGuard timing patterns
- Variable padding to obscure packet sizes
- Hot reload via SIGHUP (BPF map update, no restart)
- Pure userspace fallback mode (zero eBPF requirements, ~500 Mbps capable)
- Cross-platform: Linux (eBPF + userspace), Windows (userspace), RouterOS (userspace)
- Multi-peer support (one veth pair + BPF program per peer)
- Static musl build, zero OS dependencies — runs in empty `scratch` containers
- IPv4 and IPv6 outer transport
- Dynamic peer endpoint learning for clients behind NAT (`peer_ip = dynamic`)
- Stats via `gutd status` or SIGUSR1 signal

## Quick Start

Generate a shared key and create a minimal config on both peers:

```bash
gutd genkey          # → prints 256-bit hex key
```

```ini
# /etc/gutd/gutd.conf  (Linux)
# C:\ProgramData\gutd\gutd.conf  (Windows)
[peer]
peer_ip    = 203.0.113.10    # remote peer public IP
ports      = 41000
key        = <output of gutd genkey>
```

## Running

```bash
# eBPF mode (default on Linux, requires root and kernel ≥ 5.2)
sudo ./gutd /etc/gutd/gutd.conf

# Pure userspace mode (Linux — no eBPF, no root with capabilities)
GUTD_USERSPACE=1 ./gutd /etc/gutd/gutd.conf

# Windows (always userspace, run as Administrator for install)
gutd.exe gutd.conf

# Reload config without restart (Linux)
sudo kill -HUP $(pgrep gutd)
```

## Build

```bash
# Linux (default, with eBPF)
cargo build --release

# Linux static musl binary
./build-musl.sh

# Windows (userspace only, cross-compile from Linux)
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

See [BUILD.md](BUILD.md) for cross-compilation and musl details.

## Documentation

| Document | Description |
|---|---|
| [doc/configuration.md](doc/configuration.md) | Full config reference, key generation, MTU tuning |
| [doc/running.md](doc/running.md) | All running modes: basic, P2P, RouterOS, relay |
| [doc/architecture.md](doc/architecture.md) | Egress/ingress datapath, userspace daemon, security, related projects |
| [doc/testing.md](doc/testing.md) | Unit and integration tests |
| [doc/troubleshooting.md](doc/troubleshooting.md) | Troubleshooting, firewall notes |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Architecture and internals |
| [BUILD.md](BUILD.md) | Build instructions |
| [METRICS.md](METRICS.md) | Stats counters |

## License

Dual-licensed: userspace code under **MIT**, eBPF/kernel code under **GPL-2.0-only**. See [LICENSE](LICENSE).
