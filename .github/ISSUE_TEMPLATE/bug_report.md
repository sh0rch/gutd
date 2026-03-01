---
name: Bug Report
about: Something broken or not working as expected
title: ''
labels: bug
assignees: ''
---

**gutd version**
Output of `gutd --version`:

**Environment**
- OS/kernel: (e.g. Ubuntu 22.04, kernel 5.15)
- Architecture: (x86_64 / aarch64)
- NIC driver: (e.g. virtio_net, ixgbe)

**Config** (redact key)
```ini
[global]
[peer]
nic = 
address = 
bind_ip = 
peer_ip = 
ports = 
mtu = 
```

**What happened**


**Expected behavior**


**Logs**
```
gutd stderr/journal output
```

**Additional context**
tcpdump, `ip link show`, `tc filter show dev <nic> egress`, `ip netns list`, etc.
