# GUT v2 Implementation Snapshot

This file summarizes what is currently implemented in this repository.

## 1. Data Plane Architecture

- Egress: TC program (`gut_egress`) encapsulates inner packet into outer UDP and applies masking.
- Ingress: XDP program (`xdp_gut_ingress`) validates, unmasks, decapsulates, and redirects to tunnel side.
- Redirect path uses veth/devmap fast path.

Key files:

- `src/tc/bpf/tc_gut_egress.bpf.c`
- `src/tc/bpf/xdp_gut_ingress.bpf.c`
- `src/tc/bpf/gut_common.h`
- `src/tc/loader.rs`

## 2. Current Wire Layout (gutd v2)

Outer UDP payload:

`QUIC Long Header (40 bytes with SNI) + Original WireGuard payload (ChaCha masked) + Variable Padding`

Constants:

- `GUT_WIRE_HDR_SIZE = 103` (QUIC header + maximum padding)
- `GUT_QUIC_LONG_HEADER_SIZE = 40`

Current transform:

- payloads are masked and dynamically padded to resist length-based heuristics

## 3. Keepalive Model

- Config parameter `keepalive_drop_percent` controls probabilistic dropping of WG keepalive packets.

## 4. Checksum and Reliability Strategy

- Egress finalizes inner L4 checksum when needed (`CHECKSUM_PARTIAL` safety path).
- Egress computes outer UDP checksum from full outer packet bytes and writes it explicitly.
- Zero outer UDP checksum is not emitted; checksum failures cause packet drop.
- Ingress currently performs reverse transform + length/tail normalization before redirect.

## 5. Config and Control Plane

Primary peer parameters (only `peer_ip`, `ports`, `key`/`passphrase` are required):

- `peer_ip` (or `dynamic`), `ports`, `key`/`passphrase`
- Optional: `bind_ip` (default `0.0.0.0`), `responder` (auto-inferred), `keepalive_drop_percent`
- Optional: `obfs` (`quic` default, `noise` for random-UDP appearance). Env: `GUTD_OBFS`

Related files:

- `src/config.rs`
- `src/tc/maps.rs`
- `src/tc/loader.rs`
- `gutd.conf`

## 6. Performance Notes

- In-place masking/unmasking on packet memory.
- Per-CPU maps (`scratch_map`, `stats_map`) used to stay verifier-safe and avoid heavy stack usage.
- Bounded loops and verifier-friendly helpers used for stable BPF loading.

## 7. Validation Flow

Recommended validation after protocol/header changes:

```bash
cargo build
sudo bash tests/integration-wg.sh
```

Optional packet-level check:

```bash
sudo tcpdump -ni <iface> -vv -n 'udp port <gut_port>'
```

## 8. Compatibility Warning

The current wire format (fake QUIC) is not interoperable with historical v1 peers.
Both sides must run compatible versions/config.

## 9. Cross-Platform Support

gutd is developed primarily for Linux but also builds and runs on **Windows**
(userspace mode only). The wire format is identical across platforms — a Windows
client can talk to a Linux server running eBPF mode and vice versa.

- **Linux**: Full support — eBPF (TC/XDP) and userspace mode.
- **Windows**: Userspace mode only. `userspace_only = true` is implied.
  Installs as a Windows Service via `sc.exe`. No SIGHUP/SIGUSR1 signals;
  Ctrl+C / Ctrl+Break handled via `SetConsoleCtrlHandler`.
- **RouterOS (arm64)**: Userspace mode in a Docker container.

Build target: `x86_64-pc-windows-gnu` (or `i686-pc-windows-gnu`) with
`--no-default-features` to exclude eBPF dependencies.
