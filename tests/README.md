# Integration Tests

End-to-end tests for gutd using real WireGuard traffic inside Linux network namespaces.

## Architecture

```
+----------------------------------+   +----------------------------------+   +----------------------------------+
|  relay_ns (WG client)            |   |  server_ns (gutd relay)          |   |  host (gutd server)              |
|                                  |   |                                  |   |                                  |
|  wg0  10.200.0.1 <-- WG tunnel ->|-->|  veth_relay  10.100.1.2          |   |                                  |
|                                  |   |       |                          |   |                                  |
|                                  |   |  gut0 (gutd)  10.254.0.1 <-UDP ->|-->|  gut1 (gutd)  10.254.0.2         |
|                                  |   |       |          6000-6003        |   |       |                          |
|                                  |   |  veth_srv  10.100.2.2    <------->|-->|  veth_host  10.100.2.1           |
|                                  |   |                                  |   |  wg_srv  10.200.0.2              |
+----------------------------------+   +----------------------------------+   +----------------------------------+
```

## What is tested

### Test 1: WireGuard baseline (no obfuscation)
- Direct WireGuard connection: `relay_ns` <-> `host`
- iperf3 connectivity check
- tcpdump capture on `veth_host`

### Test 2: WireGuard through gutd
- WireGuard traffic proxied through gutd tunnel
- `relay_ns` (WG client) -> `server_ns` (gutd relay) -> `host` (gutd server + WG server)
- iperf3 connectivity check via gutd
- Packet capture at two levels:
  - Wire (`veth_host`): obfuscated UDP 6000-6003 -- no WireGuard visible
  - Tunnel (`gut1`): original WireGuard packets visible

## Running locally

```bash
# Check dependencies
bash tests/check-deps.sh

# Full integration test (requires root)
sudo bash tests/integration-wg.sh

# Custom gutd binary path
sudo GUTD_BINARY=/path/to/gutd bash tests/integration-wg.sh
```

## Artifacts

Results are written to `/tmp/`:

| File | Contents |
|------|----------|
| `gutd-test-results.txt` | Test summary |
| `gutd-test-wg-baseline.pcap` | Baseline WireGuard packets |
| `gutd-test-gutd-wire.pcap` | gutd obfuscated packets on wire |
| `gutd-test-gutd-tunnel.pcap` | Original WireGuard inside gutd tunnel |
| `gutd-test-server.log` | gutd server log |
| `gutd-test-relay.log` | gutd relay log |

Inspect captures:

```bash
# Baseline: should see WireGuard message types 1-4
tcpdump -r /tmp/gutd-test-wg-baseline.pcap -n -X

# Wire: should see UDP on ports 6000-6003, NOT WireGuard
tcpdump -r /tmp/gutd-test-gutd-wire.pcap -n -X

# Tunnel: should see original WireGuard inside gutd
tcpdump -r /tmp/gutd-test-gutd-tunnel.pcap -n -X
```

## CI/CD

Automatic checks on every push/PR (`ci.yml`): formatting, clippy, unit tests, musl build.

Integration tests are NOT run automatically on push. They run:
- Manually: GitHub Actions -> "Integration Tests with WireGuard" -> Run workflow
- Automatically: before every release (inside `release.yml`)

To emulate CI locally:

```bash
sudo apt-get install -y wireguard-tools iperf3 tcpdump iproute2 jq bc
cargo build --release
sudo GUTD_BINARY=$PWD/target/release/gutd bash tests/integration-wg.sh
```

## Troubleshooting

**"interface not found" or leftover state:**
```bash
sudo ip netns del relay_ns 2>/dev/null || true
sudo ip netns del server_ns 2>/dev/null || true
sudo pkill gutd 2>/dev/null || true
```

**WireGuard handshake not completing:**
```bash
sudo ip netns exec relay_ns wg show
sudo wg show wg_srv
sudo ip netns exec relay_ns ip route
```

**gutd not starting:**
```bash
cat /tmp/gutd-test-server.log
cat /tmp/gutd-test-relay.log
ls -l target/release/gutd
```

**iperf3 connection refused:**
```bash
ps aux | grep iperf3
sudo ip netns exec relay_ns ping -c 3 10.200.0.2
```

## Packet verification

- **Baseline**: WireGuard message types (1-4) visible in tcpdump
- **Wire (gutd)**: only UDP on ports 6000-6003, no WireGuard framing
- **Tunnel (gutd)**: original WireGuard packets visible inside the tunnel

## See also
- [WireGuard Relay Configuration](../examples/wireguard-relay.md)
- [Build Documentation](../BUILD.md)
- [Implementation Details](../IMPLEMENTATION.md)
