# gutd v3 — WireGuard Traffic Obfuscator (TC/XDP eBPF)

[![CI](https://github.com/sh0rch/gutd/actions/workflows/ci.yml/badge.svg)](https://github.com/sh0rch/gutd/actions/workflows/ci.yml)
[![Release](https://github.com/sh0rch/gutd/actions/workflows/release.yml/badge.svg?event=push)](https://github.com/sh0rch/gutd/actions/workflows/release.yml)

<!-- INTEGRATION_TEST_RESULTS_START -->
### Benchmark: gutd vs wg-obfuscator
| Tool | TCP Bandwidth | UDP Bandwidth | UDP Loss |
|---|---|---|---|
| **gutd (eBPF)** ([v3.0.0](https://github.com/sh0rch/gutd/releases/tag/v3.0.0)) | 934 Mbits/sec | 810 Mbits/sec | 0.039% |
| **gutd (Userspace)** ([v3.0.0](https://github.com/sh0rch/gutd/releases/tag/v3.0.0)) | 1.53 Gbits/sec | 1.12 Gbits/sec | 28% |
| **wg-obfuscator** ([v1.5](https://github.com/ClusterM/wg-obfuscator/releases)) | 331 Mbits/sec | 255 Mbits/sec | 76% |
<sub><i>* Performance measured using `iperf3` between 2 isolated network namespaces on GitHub Actions Ubuntu 22.04 runners. [See test logic and full logs](https://github.com/sh0rch/gutd/actions/runs/23644686799). Last updated: 2026-03-27 11:47</i></sub>
<!-- INTEGRATION_TEST_RESULTS_END -->

**gutd v3** transparently obfuscates WireGuard UDP traffic using a Linux TC/XDP eBPF datapath. On egress the TC BPF program wraps each WireGuard packet in a chosen obfuscation envelope, masks the payload with a ChaCha keystream and optionally pads it. On ingress the XDP program validates, strips the envelope and restores the original packet before WireGuard sees it. WireGuard is completely unaware of gutd. A **pure userspace mode** (wire-compatible with the eBPF path) is available for older kernels, unprivileged containers, MikroTik RouterOS, and **Windows**.

## Obfuscation Modes

| Mode | `obfs=` | Wire appearance | Anti-probing | Ports |
|---|---|---|---|---|
| **QUIC** *(default)* | `quic` | Fake QUIC Long Header + SNI (looks like HTTPS/3) | XDP replies with QUIC Version Negotiation | any UDP |
| **GUT** | `gut` | GOST-like random UDP — no QUIC/TLS signatures | silent drop | any UDP |
| **SIP/RTP** | `sip` | Signaling packets wrapped in SIP headers; data in RTP frames | XDP replies with `200 OK` / `401` / `403` | `ports[0]` = SIP (5060), `ports[1+]` = RTP (≥ 2 required) |
| **Syslog** | `syslog` | Payload base64-encoded inside a fake syslog message | silent drop | any UDP (514 typical) |

All modes apply ChaCha payload masking on top of the envelope. Both peers must use the same mode.

## Features

- Four obfuscation modes: QUIC, GUT (GOST-like random UDP), SIP/RTP, Syslog — selectable per peer
- Active DPI probe deflection at XDP layer (QUIC: Version Negotiation; SIP: `200 OK`/`401`/`403`)
- WireGuard payload masking with ChaCha (4 rounds by default)
- TC egress hook on a veth pair, XDP ingress hook on the physical NIC
- Port striping: multiple UDP ports per peer with per-packet rotation
- Keepalive probabilistic drop to suppress WireGuard timing fingerprints
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
# obfs = quic               # quic (default) | gut | sip | syslog
```

> **MTU note:** The obfuscation envelope adds overhead on top of the WireGuard packet.
> Set your WireGuard interface MTU accordingly (see [MTU reference](#mtu-reference) below):
>
> | Mode | Overhead | Recommended WG MTU |
> |---|---|---|
> | `quic` | 16 bytes | 1420 (default) |
> | `gut` | 10 bytes | 1420 |
> | `sip` | 22 bytes (RTP+GUT) | **1400** |
> | `syslog` | base64 expansion | **800** |

## Running

```bash
# eBPF mode (default on Linux, requires root and kernel ≥ 5.17)
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

## MTU Reference

Each obfuscation mode adds a different amount of overhead to every WireGuard packet.
You **must** set the WireGuard interface MTU lower than the default 1420 for modes
that add more than 16 bytes, otherwise oversized frames will be silently dropped by
the network link.

| Mode | Header added by gutd | Max safe WG MTU\* |
|---|---|---|
| `quic` | 16 bytes (QUIC short header) | **1420** |
| `gut` | 10 bytes (GUT header) | **1420** |
| `sip` | 22 bytes (RTP 12 + GUT 10) | **1400** |
| `syslog` | base64 expansion (~4/3×) | **800** |

\* For a 1500-byte outer link MTU (standard Ethernet). Adjust proportionally for PPPoE (1492) or other links.

**SIP special requirement:** `sip` mode requires at least **2 ports** — `ports[0]` carries
SIP signaling packets and `ports[1+]` carry RTP data frames. gutd will refuse to start
with fewer than 2 ports in SIP mode.

## Kernel Compatibility (eBPF mode)

gutd eBPF programs use `bpf_loop` (kernel ≥ 5.17) and `noinline` BPF subprograms.
The BPF verifier complexity budget (`processed insns`) varies significantly across
kernel versions due to verifier improvements in state pruning and precision tracking.

| Kernel | QUIC | GUT | Syslog | SIP | Notes |
|---|---|---|---|---|---|
| **≥ 6.1** | ✅ | ✅ | ✅ | ✅ | Fully tested; 6.1 uses `-mcpu=v3` + verifier-safe clamps |
| **5.17 – 6.0** | ⚠️ | ✅ | ⚠️ | ⚠️ | Only GUT mode is reliable |
| **< 5.17** | ❌ | ❌ | ❌ | ❌ | No `bpf_loop`; use userspace mode |

⚠️ = may fail to load depending on kernel config and compiler optimization.
Use `GUTD_USERSPACE=1` as a fallback on older kernels.

```ini
# Correct SIP config example
[peer]
obfs  = sip
ports = 5060, 10000, 10001   # [0]=signaling  [1+]=RTP
mtu   = 1400
sni   = sip.example.com
key   = <shared key>
```

## Documentation

| Document | Description |
|---|---|
| [doc/configuration.md](doc/configuration.md) | Full config reference, obfs modes, MTU tuning |
| [doc/running.md](doc/running.md) | All running modes: basic, P2P, RouterOS, relay |
| [doc/architecture.md](doc/architecture.md) | Egress/ingress datapath, userspace daemon, security |
| [doc/testing.md](doc/testing.md) | Unit and integration tests |
| [doc/troubleshooting.md](doc/troubleshooting.md) | Troubleshooting, firewall notes |
| [BUILD.md](BUILD.md) | Build instructions |
| [METRICS.md](METRICS.md) | Stats counters |

## License

Dual-licensed: userspace code under **MIT**, eBPF/kernel code under **GPL-2.0-only**. See [LICENSE](LICENSE).
