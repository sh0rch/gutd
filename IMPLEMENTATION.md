# GUT v1 Implementation Snapshot (Current)

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

## 2. Current Wire Layout

Outer UDP payload:

`WireGuard payload with in-place transform (no added protocol header)`

Constants:

- `GUT_WIRE_HDR_SIZE = 0`
- `GUT_MIN_OVERHEAD = 0`

Current transform:

- ballast length is stored in `reserved[0]` (byte 1)
- first 16 bytes are transformed
- for types 1/2 an extra 16-byte tail block is transformed at fixed offsets

## 3. Keepalive/Ballast Model

- Config parameter `keepalive_drop_percent` controls probabilistic dropping of WG keepalive packets.
- Short payloads may receive ballast (`3..63` bytes).
- Ingress reads ballast length from byte 1 and trims appended tail.

## 4. Checksum and Reliability Strategy

- Egress finalizes inner L4 checksum when needed (`CHECKSUM_PARTIAL` safety path).
- Egress computes outer UDP checksum from full outer packet bytes and writes it explicitly.
- Zero outer UDP checksum is not emitted; checksum failures cause packet drop.
- Ingress currently performs reverse transform + length/tail normalization before redirect.

## 5. Config and Control Plane

Primary peer parameters:

- `bind_ip`, `peer_ip`, `ports`, `key`/`passphrase`, `keepalive_drop_percent`

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

The current 4-byte cookie wire format is not interoperable with historical 1-byte-cookie peers.
Both sides must run compatible versions/config.
