//! veth pair creation for BPF-based tunnel

use crate::Result;

fn interface_exists(name: &str) -> bool {
    use std::process::Stdio;
    std::process::Command::new("ip")
        .args(["link", "show", "dev", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn delete_interface(name: &str) {
    use std::process::Stdio;
    let _ = std::process::Command::new("ip")
        .args(["link", "del", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn create_veth_pair_once(peer_name: &str, xdp_name: &str) -> bool {
    std::process::Command::new("ip")
        .args([
            "link", "add", xdp_name, "type", "veth", "peer", "name", peer_name,
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn set_interface_offloads(ifname: &str) {
    use std::process::Stdio;

    // ── ETHTOOL ioctl — no external binary required ────────────────────
    //
    // Disable TX checksum offload and TSO on the veth interfaces so that
    // packets reaching the TC BPF egress hook always carry a complete
    // (or partial-but-handleable) L4 checksum, and so oversized GSO
    // segments are never sent to our BPF program.
    //
    // Command codes from <linux/ethtool.h>:
    //   ETHTOOL_STXCSUM = 0x0e — set TX hardware checksum capability
    //   ETHTOOL_STSO    = 0x1e — set TCP segmentation offload
    const ETHTOOL_STXCSUM: u32 = 0x0000_000e;
    const ETHTOOL_STSO: u32 = 0x0000_001e;
    const SIOCETHTOOL: u64 = 0x8946;

    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock >= 0 {
        for cmd in [ETHTOOL_STXCSUM, ETHTOOL_STSO] {
            unsafe {
                let mut ev = EthtoolValue { cmd, data: 0 };
                let mut ifr: libc::ifreq = std::mem::zeroed();
                let name_bytes = ifname.as_bytes();
                let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
                for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                    ifr.ifr_name[i] = b as libc::c_char;
                }
                ifr.ifr_ifru.ifru_data = (&mut ev) as *mut EthtoolValue as *mut libc::c_char;
                #[allow(clippy::cast_possible_truncation)]
                libc::ioctl(sock, SIOCETHTOOL as _, &ifr as *const libc::ifreq);
            }
        }
        unsafe { libc::close(sock) };
    }

    // ── ip link set gso_max_segs — belt-and-suspenders GSO cap ─────────
    //
    // gso_max_size is already limited to the tunnel MTU elsewhere.
    // Setting gso_max_segs=1 prevents the kernel from coalescing multiple
    // TCP segments into a single large skb that would exceed inner MTU.
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", ifname, "gso_max_segs", "1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Compute peer address for a point-to-point /30 or /31 link.
///
/// Given `"10.0.0.1/30"`, returns `("10.0.0.1", "10.0.0.2", 30)`.
/// Given `"10.0.0.2/30"`, returns `("10.0.0.2", "10.0.0.1", 30)`.
/// For /31 (RFC 3021): the peer is the XOR-1 address.
pub fn compute_p2p_peer(cidr: &str) -> Result<(String, String, u8)> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR: {cidr}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("Invalid prefix length: {prefix_str}"))?;

    let octets: Vec<u8> = ip_str
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| format!("Invalid IPv4 address: {ip_str}"))?;

    if octets.len() != 4 {
        return Err(format!("Invalid IPv4 address: {ip_str}").into());
    }

    let ip: u32 = (octets[0] as u32) << 24
        | (octets[1] as u32) << 16
        | (octets[2] as u32) << 8
        | (octets[3] as u32);

    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let network = ip & mask;
    let host_part = ip & !mask;
    let max_host = !mask;

    let peer = if prefix == 31 {
        // RFC 3021 point-to-point /31: two addresses, peer is the other one
        network | (host_part ^ 1)
    } else if prefix >= 30 {
        // /30: network(0), host1(1), host2(2), broadcast(3)
        if host_part == 0 || host_part == max_host {
            return Err(format!("{ip_str}/{prefix} is a network/broadcast address").into());
        }
        // Peer is the other host: 1↔2
        network | if host_part == 1 { 2 } else { 1 }
    } else {
        return Err(format!("Auto peer address only works with /30 or /31, got /{prefix}").into());
    };

    let peer_str = format!(
        "{}.{}.{}.{}",
        (peer >> 24) & 0xFF,
        (peer >> 16) & 0xFF,
        (peer >> 8) & 0xFF,
        peer & 0xFF,
    );

    Ok((ip_str.to_string(), peer_str, prefix))
}

/// Generate a deterministic locally-administered MAC from an IPv4 address.
///
/// Format: `02:47:ip[0]:ip[1]:ip[2]:ip[3]`
///   - `02` = locally administered, unicast
///   - `47` = 'G' for GUT
///   - remaining 4 bytes = IPv4 octets
pub fn mac_from_ipv4(ip_str: &str) -> Result<[u8; 6]> {
    let octets: Vec<u8> = ip_str
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| format!("Invalid IPv4 address: {ip_str}"))?;
    if octets.len() != 4 {
        return Err(format!("Invalid IPv4 address: {ip_str}").into());
    }
    Ok([0x02, 0x47, octets[0], octets[1], octets[2], octets[3]])
}

pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Create a veth pair for XDP bulk redirect mode.
///
/// Creates `xdp_name` ↔ `peer_name` where:
/// - `peer_name` is the user-facing interface (gets IP, point-to-point tunnel)
/// - `xdp_name` is the XDP redirect target (NIC XDP → devmap → xdp_name TX → peer RX)
///
/// When `address` is set (e.g. `"10.0.0.1/30"`):
/// - MACs are derived from tunnel IPs: `02:47:ip[0]:ip[1]:ip[2]:ip[3]`
/// - peer address is auto-computed (.1↔.2)
/// - static neighbor entry is created (no ARP)
/// - ARP is disabled on the interface
pub fn create_veth_pair(
    peer_name: &str,
    xdp_name: &str,
    mtu: u16,
    address: Option<&str>,
) -> Result<([u8; 6], [u8; 6])> {
    // Compute MACs and peer address from tunnel IP
    let (local_mac, xdp_mac, p2p_info) = if let Some(addr) = address {
        let (local_ip, peer_ip, prefix) = compute_p2p_peer(addr)?;
        let lmac = mac_from_ipv4(&local_ip)?;
        let xmac = mac_from_ipv4(&peer_ip)?;
        (lmac, xmac, Some((local_ip, peer_ip, prefix)))
    } else {
        // No address — use fixed MACs
        let lmac: [u8; 6] = [0x02, 0x47, 0x55, 0x54, 0x31, 0x00];
        let xmac: [u8; 6] = [0x02, 0x47, 0x55, 0x54, 0x32, 0x00];
        (lmac, xmac, None)
    };

    let local_mac_str = mac_to_string(&local_mac);
    let xdp_mac_str = mac_to_string(&xdp_mac);

    // Create veth pair (idempotent for service restarts):
    // if names already exist, clean and retry once.
    if !create_veth_pair_once(peer_name, xdp_name) {
        let had_conflict = interface_exists(peer_name) || interface_exists(xdp_name);
        if had_conflict {
            // Deleting either end of a veth pair removes both; try both names to
            // also handle partially existing stale interfaces.
            delete_interface(xdp_name);
            delete_interface(peer_name);
        }

        if !create_veth_pair_once(peer_name, xdp_name) {
            return Err(format!("Failed to create veth pair {xdp_name} ↔ {peer_name}").into());
        }
    }

    // Set deterministic MAC addresses
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", peer_name, "address", &local_mac_str])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", xdp_name, "address", &xdp_mac_str])
        .status();

    let mtu_str = mtu.to_string();

    // Set MTU on both ends
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", peer_name, "mtu", &mtu_str])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", xdp_name, "mtu", &mtu_str])
        .status();

    // Disable offloads on both ends to keep checksum/segmentation behavior
    // deterministic in BPF datapath across different VPS kernels.
    set_interface_offloads(peer_name);
    set_interface_offloads(xdp_name);

    // gso_max_size is set by TC loader after PMTU/outer_mtu resolution.

    // Assign point-to-point address + static neighbor (no ARP needed)
    if let Some((local_ip, peer_ip, prefix)) = &p2p_info {
        let peer_cidr = format!("{peer_ip}/{prefix}");
        eprintln!(
            "  {peer_name}: {local_ip} peer {peer_cidr} | mac {local_mac_str} ↔ {xdp_mac_str}"
        );

        // Assign point-to-point address
        let status = std::process::Command::new("ip")
            .args([
                "addr", "add", local_ip, "peer", &peer_cidr, "dev", peer_name,
            ])
            .status();
        if status.is_err() || !status.as_ref().unwrap().success() {
            return Err(format!(
                "Failed to assign address {local_ip} peer {peer_cidr} to {peer_name}"
            )
            .into());
        }

        // Static neighbor entry — kernel never needs to ARP
        let status = std::process::Command::new("ip")
            .args([
                "neigh",
                "add",
                peer_ip,
                "lladdr",
                &xdp_mac_str,
                "dev",
                peer_name,
                "nud",
                "permanent",
            ])
            .status();
        if status.is_err() || !status.as_ref().unwrap().success() {
            return Err(format!(
                "Failed to add static neighbor {peer_ip} → {xdp_mac_str} on {peer_name}"
            )
            .into());
        }

        // Disable ARP on the interface — everything is statically configured
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", peer_name, "arp", "off"])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", xdp_name, "arp", "off"])
            .status();
    }

    // Bring both interfaces up
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", xdp_name, "up"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", peer_name, "up"])
        .status();

    Ok((local_mac, xdp_mac))
}

/// Destroy a veth pair by deleting one end (kernel removes the other automatically).
pub fn destroy_veth(xdp_name: &str) {
    let _ = std::process::Command::new("ip")
        .args(["link", "del", xdp_name])
        .status();
}
