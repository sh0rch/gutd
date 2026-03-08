//! veth pair creation for BPF-based tunnel.
//!
//! All Linux network operations delegate to `crate::netlink` — no external
//! binaries (iproute2 / ethtool) are required.

use crate::netlink::{
    addr_add_p2p_v4, get_ifindex, link_delete, link_disable_offloads, link_set_gso_max_segs,
    link_set_mac, link_set_mtu, link_set_noarp, link_set_up, neigh_add_v4_permanent, veth_create,
};
use crate::Result;

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
    // Use get_ifindex (ioctl) not link_exists (sysfs) — sysfs may be absent
    // in minimal container environments (RouterOS).
    if veth_create(peer_name, xdp_name).is_err() {
        let had_conflict = get_ifindex(peer_name).is_ok() || get_ifindex(xdp_name).is_ok();
        if had_conflict {
            link_delete(xdp_name);
            link_delete(peer_name);
        }
        veth_create(peer_name, xdp_name)
            .map_err(|e| format!("Failed to create veth pair {xdp_name} ↔ {peer_name}: {e}"))?;
    }

    // Set deterministic MAC addresses
    let _ = link_set_mac(peer_name, &local_mac);
    let _ = link_set_mac(xdp_name, &xdp_mac);

    // Set MTU on both ends
    let _ = link_set_mtu(peer_name, mtu as u32);
    let _ = link_set_mtu(xdp_name, mtu as u32);

    // Disable TX checksum offload + TSO and cap gso_max_segs.
    link_disable_offloads(peer_name);
    link_disable_offloads(xdp_name);
    link_set_gso_max_segs(peer_name, 1);
    link_set_gso_max_segs(xdp_name, 1);

    // Assign point-to-point address + static neighbor (no ARP needed)
    if let Some((local_ip, peer_ip, prefix)) = &p2p_info {
        let peer_cidr = format!("{peer_ip}/{prefix}");
        eprintln!(
            "  {peer_name}: {local_ip} peer {peer_cidr} | mac {local_mac_str} ↔ {xdp_mac_str}"
        );

        // Assign point-to-point address
        addr_add_p2p_v4(peer_name, local_ip, peer_ip, *prefix).map_err(|e| {
            format!("Failed to assign address {local_ip} peer {peer_cidr} to {peer_name}: {e}")
        })?;

        // Static neighbor entry — kernel never needs to ARP
        neigh_add_v4_permanent(peer_name, peer_ip, &xdp_mac).map_err(|e| {
            format!("Failed to add static neighbor {peer_ip} → {xdp_mac_str} on {peer_name}: {e}")
        })?;

        // Disable ARP on both ends — everything is statically configured
        link_set_noarp(peer_name);
        link_set_noarp(xdp_name);
    }

    // Bring both interfaces up
    link_set_up(xdp_name);
    link_set_up(peer_name);

    Ok((local_mac, xdp_mac))
}

/// Destroy a veth pair by deleting one end (kernel removes the other automatically).
pub fn destroy_veth(xdp_name: &str) {
    link_delete(xdp_name);
}
