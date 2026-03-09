# Configuration

All supported keys (see `gutd.conf` for the annotated example):

```ini
[global]
outer_mtu = 1500          # outer link MTU; runtime: max(route_pmtu, iface_mtu, outer_mtu)
stats_interval = 5        # write /run/gutd.stat every N seconds (0 = off)
userspace_only = false    # set to true to force Mio userspace proxy instead of eBPF
stat_file = /run/gutd.stat

[peer]
name = gut0               # veth pair name: gut0 <-> gut0_xdp
mtu = 1420                # inner MTU hint (loader computes actual from PMTU)
nic = eth0                # ingress NIC for XDP (auto-detected from default route if omitted)
address = 10.0.0.1/30    # point-to-point IP on the veth (/30 or /31 only)
                          #   peer address auto-computed (.1<->.2)
bind_ip = 0.0.0.0        # local bind IP (0.0.0.0 = auto from route src)
peer_ip = 203.0.113.10
ports = 41000,41001       # UDP ports (must match WG listen/endpoint ports)
keepalive_drop_percent = 30
# own_http3 = true        # eBPF XDP responder for active DPI probes on UDP ports
key = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
# passphrase = my-secret  # alternative to key (HKDF-SHA256 derived)
```

## Key Generation

```bash
# Random 256-bit key
gutd genkey

# Derive from passphrase
gutd genkey --passphrase "my secret phrase"
```

## MTU

gutd v2 encapsulates WireGuard UDP packets inside a fake QUIC wrapper.
It prepends a QUIC Long Header (including SNI) to every packet and appends
variable padding to obfuscate packet length. These additions increase the
packet size.

### gutd config `mtu`

Sets the MTU of the gut TUN interface (the veth pair gutd creates). gutd also
applies this value as `gso_max_size` on both veth endpoints to prevent the
kernel from generating super-segments larger than the link can carry.

Default: `1420`. This is the standard WireGuard veth MTU and works for most
setups. The 4-byte gutd metadata overhead is covered by the built-in 20-byte
PMTU reserve.

### WireGuard `wg0` MTU

Set `wg0` MTU to the standard WireGuard recommendation for your link:

```
wg0 mtu = outer_link_mtu - 60   (20 IP + 8 UDP + 32 WireGuard header/tag)
```

For a 1500-byte Ethernet link: `wg0 mtu = 1420` (default WireGuard value).

The 4 extra bytes added by gutd fit within the 20-byte PMTU headroom already
accounted for in WireGuard's MTU formula, so **no adjustment to wg0 MTU is
needed** when running WireGuard over gutd.

### `outer_mtu` config key

Maximum size of the outer Ethernet frame on the physical link. Default: `1500`.
Override only if your uplink uses jumbo frames or has a reduced MTU (e.g. PPPoE: `1492`).
