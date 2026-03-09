# Testing

## Unit Tests

Run unit and integration tests:

```bash
cargo test
```

Test suites included:
- ChaCha masking / unmasking round-trip
- Config parser (single peer, multi-peer, duplicate port rejection)
- MAC / veth addressing helpers
- Kernel-version detection

## Integration Tests with WireGuard

```bash
# Full integration test (requires sudo, wireguard-tools, iperf3, tcpdump, jq)
make test-integration

# Or directly:
sudo bash tests/integration-wg.sh
```

The test spins up two network namespaces, runs gutd in each with a shared key,
establishes a WireGuard tunnel through the gutd veth pair, and verifies connectivity
with iperf3. Artifacts written to `/tmp/gutd-test-*.{log,pcap,txt}`.

See [tests/README.md](../tests/README.md) for details.
