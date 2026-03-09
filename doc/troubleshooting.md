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
