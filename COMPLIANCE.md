# GUT v1 Compliance Checklist (Current Repository)

This checklist tracks what the current code actually implements.

## 1. Protocol Layout

- [ok] `udp_payload` is transformed in place (no extra protocol header bytes added)
- [ok] `GUT_WIRE_HDR_SIZE = 0`, `GUT_MIN_OVERHEAD = 0`
- [ok] Ballast length is carried in byte 1 (`reserved[0]`)
- [ok] Ballast tail is appended/trimmed symmetrically on egress/ingress

Sources:

- `src/tc/bpf/gut_common.h`
- `src/tc/bpf/tc_gut_egress.bpf.c`
- `src/tc/bpf/xdp_gut_ingress.bpf.c`

## 2. Datapath Behavior

- [ok] Egress applies payload transform for WG types and optional ballast append
- [ok] Ingress applies reverse transform and ballast tail trim
- [ok] Keepalive packets can be probabilistically dropped by config (`keepalive_drop_percent`)
- [ok] Outer UDP checksum is always computed and written by egress BPF

## 3. Config/Control-Plane Consistency

- [ok] Config uses `keepalive_drop_percent` (0..100)
- [ok] Rust `GutConfig` and BPF `struct gut_config` layouts are aligned

Sources:

- `src/config.rs`
- `src/tc/maps.rs`
- `src/tc/loader.rs`
- `src/tc/bpf/gut_common.h`

## 4. MTU/Overhead Accounting

- [ok] Rust overhead constants reflect payload-only mode (no extra protocol bytes)
- [ok] Sample config docs updated to payload-only overhead formulas

Sources:

- `src/tc/maps.rs`
- `gutd.conf`
- `src/installer.rs`

## 5. Safety/Reliability Constraints

- [ok] BPF verifier-safe bounds checks retained on variable-length operations
- [ok] Scratch map is used for bounded packet read/modify/write operations
- [ok] Invalid cookie / malformed packets are dropped on ingress
- [ok] Checksum calculation failures drop packet (no invalid packet emission)

## 6. Verification Commands

Recommended validation sequence:

```bash
cargo build
bash tests/check-deps.sh       # check host dependencies
sudo bash tests/integration-wg.sh  # full TC/XDP integration test
```

Optional live checksum check:

```bash
sudo tcpdump -ni <iface> -vv -n 'udp port <gut_port>'
```

## 7. Known Compatibility Note

This payload-only WG layout is not interoperable with old nonce/pkt_id/cookie wire peers.
