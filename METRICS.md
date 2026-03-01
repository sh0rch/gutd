# Metrics

gutd counts events using lock-free atomic counters (`AtomicU64`, `Ordering::Relaxed`).
No feature flags. No overhead worth mentioning. Always on.

## Counters

| Counter | Description |
|---------|-------------|
| `rx_packets` / `rx_bytes` | Packets and bytes received from the wire |
| `tx_packets` / `tx_bytes` | Packets and bytes sent to the wire |
| `rx_dropped` / `tx_dropped` | Packets dropped (parse error, short read, etc.) |
| `chacha_encode_count` | ChaCha masking operations on egress |
| `chacha_decode_count` | ChaCha unmasking operations on ingress |

## Reading counters

### SIGUSR1 - print to stderr

```bash
kill -USR1 $(pidof gutd)
# or
sudo kill -USR1 $(cat /run/gutd.pid)
```

Output:
```
=== gutd Performance Metrics ===
Uptime: 3600.5s

--- Packets ---
  RX: 1234567 packets (1800000000 bytes, ...)
  TX: 1234560 packets (...)
  RX Dropped: 0 (...)
  TX Dropped: 0 (...)

--- Encryption ---
  Encryption Encode: 1234567
  Encryption Decode: 1234560

================================
```

### Stat file

When `stats_interval > 0` in `gutd.conf`, gutd atomically writes a plain-text
counters file (default `/run/gutd.stat`) at the configured interval:

```bash
cat /run/gutd.stat
# or
gutd status
# or
gutd status /run/gutd.stat
```

### Programmatic (Rust)

```rust
use gutd::metrics::METRICS;

let snap = METRICS.snapshot();
println!("rx: {} pkts {} bytes", snap.rx_packets, snap.rx_bytes);
println!("tx: {} pkts {} bytes", snap.tx_packets, snap.tx_bytes);
println!("chacha encode: {}", snap.chacha_encode_count);
```
