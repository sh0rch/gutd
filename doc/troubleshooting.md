# Troubleshooting

## veth pair not created

```bash
# Check gutd log output for errors
journalctl -u gutd -n 50
# or run in foreground:
sudo gutd -c /etc/gutd.conf
```

## XDP not attaching

```bash
# Kernel >= 5.2 required
uname -r

# Check that the ingress NIC name is correct (auto-detected or set via nic = ...)
ip link show
```

## No packets received

```bash
# Check firewall allows configured UDP ports
sudo iptables -L -n -v | grep 41000

# Verify peer IP is reachable
ping <peer_ip>

# Check BPF stats
gutd status
```

## Firewall

**No firewall rules are needed for gutd ports.**

Incoming gutd packets are processed by an XDP program attached directly to the
NIC. XDP runs before the kernel network stack and before netfilter/iptables, so
the packets are intercepted and redirected to the WireGuard interface without
ever reaching the INPUT chain. Adding an iptables or ufw rule for gutd ports
has no effect.

## BPF verifier rejects program on kernel 6.1 / 6.2

The BPF verifier enforces a 1,000,000 processed-instruction complexity limit.
gutd programs pass on kernel ≥ 6.3 but **QUIC and SIP egress** may exceed the
limit on kernels 6.1–6.2 due to missing verifier optimizations:

- **6.1–6.2**: `mark_precise` backtracking does not work across `noinline`
  subprogram boundaries and `bpf_loop` callbacks. The verifier over-explores
  states, inflating the instruction count by 2–4×.
- **6.3+**: `parent track_live` and improved state merging fix this.
- **6.6+**: Full `mark_precise` for `bpf_loop` callbacks; all modes verified.

### Measured verifier complexity (kernel 6.6)

| Mode | Egress | Ingress | Margin |
|---|---|---|---|
| QUIC | 552,062 | 113,846 | 45% free |
| GUT | 173,178 | 4,788 | 83% free |
| Syslog | 176,373 | 8,336 | 82% free |
| SIP | ~200K+ | ~10K | ~80% free |

On kernel 6.1 the same programs consume ~2–4× more verifier budget. QUIC egress
at 552K × 2 = **>1M → verification failure**.

### Workarounds

1. **Upgrade kernel** to ≥ 6.3 (Ubuntu 23.04+, Debian 12 backports, Fedora 38+)
2. **Switch obfs mode** to `gut` or `syslog` — they have 5× more headroom
3. **Use userspace mode**: `GUTD_USERSPACE=1 ./gutd <config>`

### Diagnosing

```bash
# Check current verifier budget usage
sudo bpftool -d prog load /path/to/tc_gut_egress.o /sys/fs/bpf/test 2>&1 | \
  grep 'processed.*insns'
sudo rm -f /sys/fs/bpf/test
```
