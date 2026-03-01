# Integration Tests

Integration tests run gutd end-to-end with real WireGuard traffic inside Linux
network namespaces. No external hosts required.

## Test scripts

| Script | What it does |
|--------|-------------|
| `tests/integration-wg.sh` | Full test: namespaces + WireGuard + gutd relay + packet capture |
| `tests/check-deps.sh` | Check for required packages and kernel modules |

## Architecture

```
+------------------+     +------------------+     +------------------+
|  relay_ns        |     |  server_ns       |     |  host            |
|  (WG client)     |     |  (gutd relay)    |     |  (gutd server)   |
|                  |     |                  |     |                  |
|  wg0             |<--->|  veth_relay      |     |                  |
|  10.200.0.1      |WG   |  10.100.1.2      |     |                  |
|                  |     |       |          |     |                  |
|                  |     |  gut0 (gutd)     |<--->|  gut1 (gutd)     |
|                  |     |  10.254.0.1      |UDP  |  10.254.0.2      |
|                  |     |       |          |6000 |       |          |
|                  |     |  veth_srv        |<--->|  veth_host       |
|                  |     |  10.100.2.2      |     |  10.100.2.1      |
|                  |     |                  |     |  wg_srv          |
|                  |     |                  |     |  10.200.0.2      |
+------------------+     +------------------+     +------------------+
```

## Test scenarios

### Scenario 1: WireGuard baseline
1. Setup WireGuard direct: `relay_ns` <-> `host`
2. iperf3 connectivity check (10.200.0.1 -> 10.200.0.2)
3. tcpdump capture 5 packets on `veth_host`
4. Result: WireGuard packets visible on wire

### Scenario 2: WireGuard through gutd
1. Setup gutd tunnel `server_ns` <-> `host` (UDP 6000-6003)
2. Setup WireGuard through gutd (endpoint 10.254.0.x)
3. NAT/forwarding rules in `server_ns`
4. iperf3 connectivity check via gutd+WG
5. tcpdump capture at two levels:
   - Wire (`veth_host`): gutd UDP packets -- no WireGuard visible
   - Tunnel (`gut1`): original WireGuard packets
6. Result: confirmed obfuscation

## Obfuscation verification

- **Wire packets**: UDP on ports 6000-6003 only -- no WireGuard framing
- **Tunnel packets**: original WireGuard packets visible inside gutd tunnel
- **Proof**: tcpdump at both levels shows the transformation

## Acceptance criteria

- Packet capture verification: obfuscation confirmed
- No packet loss during test
- WireGuard handshake successful via gutd

## Running tests

### Locally
```bash
# Check dependencies
bash tests/check-deps.sh

# Full integration test
sudo bash tests/integration-wg.sh
```

### CI/CD
- Runs automatically before each release
- Can be triggered manually: GitHub Actions -> "Integration Tests with WireGuard" -> Run workflow
- Artifacts available in GitHub Actions run

## Artifacts

Files created in `/tmp/`:

| File | Contents |
|------|----------|
| `gutd-test-results.txt` | Test summary |
| `gutd-test-wg-baseline.pcap` | WireGuard without obfuscation |
| `gutd-test-gutd-wire.pcap` | gutd UDP packets on wire |
| `gutd-test-gutd-tunnel.pcap` | WireGuard inside gutd tunnel |
| `gutd-test-server.log` | gutd server log |
| `gutd-test-relay.log` | gutd relay log |
| `iperf3-*.log` | iperf3 server log |

### Inspection
```bash
# Packet inspection
tcpdump -r /tmp/gutd-test-gutd-wire.pcap -n -X | head -20

# gutd logs
tail -50 /tmp/gutd-test-server.log
```

## Dependencies

### Required packages
- `wireguard-tools`
- `iperf3`
- `tcpdump`
- `iproute2`
- `iputils-ping`
- `jq`
- `bc`

### Kernel modules
- `wireguard`
- `tun`

### Install
**Ubuntu/Debian:**
```bash
sudo apt-get install -y wireguard-tools iperf3 tcpdump iproute2 iputils-ping jq bc
```

**Alpine:**
```bash
sudo apk add wireguard-tools iperf3 tcpdump iproute2 iputils jq bc
```

## Troubleshooting

See [tests/README.md](tests/README.md) for detailed troubleshooting.

Common issues:
- **Permission denied**: run with sudo
- **Kernel module not found**: check `modprobe wireguard`
- **gutd not starting**: check logs in /tmp/gutd-test-*.log
- **WireGuard handshake fails**: check routing and firewall rules

## Next steps

Potential improvements:
- [ ] Docker-based tests (full isolation)
- [ ] Multi-platform tests (aarch64, armv7)
- [ ] IPv6 outer transport tests
- [ ] MTU edge cases and fragmentation tests
- [ ] Traffic shaping tests (loss, delay, jitter)
