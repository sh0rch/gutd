# Architecture

gutd creates a **veth pair** (`gut0 ↔ gut0_xdp`) and attaches two BPF programs:
- **TC egress** on `gut0` — intercepts outgoing WireGuard UDP before it hits the wire
- **XDP ingress** on the physical NIC — intercepts incoming obfuscated UDP before the kernel stack sees it

WireGuard is configured to use the gutd veth address as its endpoint. It is
unaware of gutd and sees a normal UDP socket.

## Egress (outbound)

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

## Ingress (inbound)

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

## Userspace Daemon

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

## Zero Dependencies and Scratch Containers

gutd v2 requires no external OS binaries (like `iproute2` or `ethtool`). It is fully self-contained using raw sockets and Netlink for routing and ARP/NDP resolution.

Because of this, you can run gutd inside a completely empty Docker `scratch` container. This ensures minimal footprint and high portability across operating systems.

Libraries used in compilation:
- `libc` — system calls
- `anyhow` — error handling
- `nix` — Linux-specific IO
- `libbpf-rs` / `libbpf-sys` — BPF program loading and map management
- `libbpf-cargo` — BPF skeleton generation at build time

## Related Projects

This project is part of a lineage of WireGuard traffic obfuscation tools:

```
 xt_wgobfs  (iptables/netfilter, original concept by Wei Chen)
     |
 nf_wgobfs  (nftables/netfilter, userspace)
     |
  gutd       (TC/XDP eBPF, this project)
```

**[xt_wgobfs](https://github.com/infinet/xt_wgobfs)** — original iptables/xtables WireGuard obfuscation module created by [Wei Chen](https://github.com/infinet).
The idea of in-place masking of WireGuard payloads originates from this project and inspired the work that eventually led to `nf_wgobfs` and later `gutd`.

**[nf_wgobfs](https://github.com/sh0rch/nf_wgobfs)** — NFQUEUE-based successor implementing the same concept in userspace.

**gutd** — TC/XDP eBPF implementation that moves packet processing into the kernel datapath and adds more advanced traffic shaping and obfuscation mechanisms.
