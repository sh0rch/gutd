//! Windows-only: pick a viable physical uplink toward `peer_ip` and pin a
//! /32 (or /128) host route through it with `metric = 1`.
//!
//! Rationale: on Windows clients the host may already have WireGuard/OpenVPN/
//! Tailscale default route pointing into a virtual (wintun/tap) adapter. We
//! MUST NOT send obfuscated UDP into another VPN — it would loop or drop.
//!
//! Strategy:
//!   1. Enumerate all NICs via `GetIfTable2`.
//!   2. Filter out loopback, tunnel, propagated-virtual, non-HW,
//!      non-dedicated, and drivers whose description matches a VPN blacklist.
//!   3. For each surviving NIC call `GetBestRoute2` with that `InterfaceLuid`
//!      — this forces the routing decision as if only this NIC existed.
//!   4. Pick the NIC with the lowest route metric.
//!   5. `CreateIpForwardEntry2` for `peer_ip/prefixlen` via that LUID with
//!      `Metric = 1`.
//!   6. Verify via `GetBestInterfaceEx` that the pin actually won; if some
//!      other VPN still beats us, roll back and warn.
//!
//! The returned `PinnedRoute` removes the route on `Drop`.
#![cfg(target_os = "windows")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestInterfaceEx, GetBestRoute2,
    GetIfEntry2, GetIfTable2, IF_CONNECTION_DEDICATED, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, MIB_IF_ROW2,
    MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

/// Hard-coded black-list of description substrings (case-insensitive)
/// that identify VPN / virtual drivers masquerading as Ethernet. Primary
/// filter is `IfType` + `HardwareInterface`; this is only a last-resort
/// sieve for misbehaving drivers.
const VPN_BLACKLIST: &[&str] = &[
    "wintun",
    "tap-windows",
    "tap0901",
    "openvpn",
    "wireguard",
    "tailscale",
    "zerotier",
    "anyconnect",
    "cisco secure",
    "globalprotect",
    "palo alto",
    "fortinet",
    "forticlient",
    "pulse secure",
    "sonicwall",
    "hamachi",
    "nordlynx",
    "expressvpn",
    "protonvpn",
    "mullvad",
    "wsl",
    "hyper-v virtual",
    "vmware",
    "vbox",
    "virtualbox",
    "teredo",
    "isatap",
    "6to4",
];

/// Holds a pinned host-route. Removes it on drop.
pub struct PinnedRoute {
    row: MIB_IPFORWARD_ROW2,
    /// Local source address the OS would pick for this route.
    pub source: IpAddr,
    /// Human-readable interface alias (for logging).
    pub if_alias: String,
}

impl Drop for PinnedRoute {
    fn drop(&mut self) {
        let rc = unsafe { DeleteIpForwardEntry2(&self.row) };
        if rc != NO_ERROR {
            eprintln!(
                "gutd: DeleteIpForwardEntry2 failed (rc={}); route may linger until reboot",
                rc
            );
        } else {
            eprintln!("gutd: removed pinned route via {}", self.if_alias);
        }
    }
}

/// Pin a host-route toward `peer_ip` through the best viable physical uplink.
/// Returns `Err` on any failure (caller logs and continues with system default).
pub fn pin_route_to_peer(peer_ip: IpAddr) -> Result<PinnedRoute, String> {
    let candidates = enumerate_viable_uplinks()?;
    if candidates.is_empty() {
        return Err(
            "no viable physical uplink found (all NICs are virtual/tunnel/down)".to_string(),
        );
    }

    // For each candidate, ask the stack for the best route + source as if
    // only this NIC existed. Rank by route metric.
    let mut best: Option<(u32, String, u64, MIB_IPFORWARD_ROW2, IpAddr)> = None;
    for (luid, alias) in &candidates {
        match best_route_via(*luid, peer_ip) {
            Ok((row, src)) => {
                // Family must match peer family.
                if src.is_ipv4() != peer_ip.is_ipv4() {
                    continue;
                }
                let metric = row.Metric;
                let better = match &best {
                    None => true,
                    Some((m, _, _, _, _)) => metric < *m,
                };
                if better {
                    best = Some((metric, alias.clone(), *luid, row, src));
                }
            }
            Err(e) => {
                eprintln!("gutd: GetBestRoute2 via {} failed: {}", alias, e);
            }
        }
    }

    let (metric, alias, luid, mut row, src) =
        best.ok_or_else(|| "no route could be computed on any viable uplink".to_string())?;

    // Override just the fields we care about. Keep the NextHop that
    // GetBestRoute2 computed — it's the real default-gateway of the chosen
    // uplink (e.g. 192.168.255.1). Zeroing NextHop would mark the route as
    // "on-link", which is wrong for any off-subnet peer and silently breaks
    // ARP resolution, causing the stack to fall back to a shorter-prefix
    // route (e.g. WireGuard's 64.0.0.0/2).
    row.Metric = 1;
    set_host_prefix(&mut row, peer_ip);

    // Without this the route inherits ValidLifetime=0 from our zero-init
    // and Windows expires it in ~30 minutes. Use INFINITE on both.
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    // Mark immortal so the stack does not GC the entry under memory
    // pressure or policy churn. `BOOLEAN` is a `u8` in windows-sys.
    row.Immortal = 1;
    row.Publish = 0;

    let rc = unsafe { CreateIpForwardEntry2(&row) };
    if rc != NO_ERROR {
        // ERROR_OBJECT_ALREADY_EXISTS (5010) — a prior gutd instance crashed.
        const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
        if rc == ERROR_OBJECT_ALREADY_EXISTS {
            unsafe { DeleteIpForwardEntry2(&row) };
            let rc2 = unsafe { CreateIpForwardEntry2(&row) };
            if rc2 != NO_ERROR {
                return Err(format!(
                    "CreateIpForwardEntry2 rc={} (after stale delete); need Administrator?",
                    rc2
                ));
            }
        } else {
            return Err(format!(
                "CreateIpForwardEntry2 rc={}; need Administrator privileges?",
                rc
            ));
        }
    }

    // Verify our pin actually took effect.
    match verify_best_interface_luid(peer_ip) {
        Ok(winner_luid) if winner_luid == luid => {
            eprintln!(
                "gutd: pinned route to {} via {} (source {}, metric {} → 1)",
                peer_ip, alias, src, metric
            );
            Ok(PinnedRoute {
                row,
                source: src,
                if_alias: alias,
            })
        }
        Ok(_) => {
            unsafe { DeleteIpForwardEntry2(&row) };
            Err(format!(
                "pinned route to {} was overridden by another interface \
                 (some VPN is using metric 0); leaving system routing intact",
                peer_ip
            ))
        }
        Err(e) => {
            unsafe { DeleteIpForwardEntry2(&row) };
            Err(format!("post-pin verification failed: {}", e))
        }
    }
}

/// Return `(InterfaceLuid, alias)` for every NIC that looks like a real
/// physical uplink.
fn enumerate_viable_uplinks() -> Result<Vec<(u64, String)>, String> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIfTable2(&mut table_ptr) };
    if rc != NO_ERROR || table_ptr.is_null() {
        return Err(format!("GetIfTable2 rc={}", rc));
    }

    let mut out = Vec::new();
    // SAFETY: `GetIfTable2` returned NO_ERROR and a non-null pointer above,
    // so `table_ptr` points to a valid `MIB_IF_TABLE2` whose lifetime ends
    // at the matching `FreeMibTable` call below. We use raw-pointer field
    // access (`addr_of!`) instead of materialising `&MIB_IF_TABLE2`, because
    // the struct ends in a flexible array (`Table: [MIB_IF_ROW2; ANYSIZE]`)
    // and creating a reference to it would be unsound. Each row pointer is
    // bounds-checked against `NumEntries` returned by the OS.
    //
    // lgtm[rust/access-invalid-pointer]
    // codeql[rust/access-invalid-pointer]: GetIfTable2 contract guarantees
    //   `table_ptr` is valid until FreeMibTable; flexible-array rows are
    //   accessed via addr_of! and bounded by OS-reported NumEntries.
    unsafe {
        use std::ptr::addr_of;
        let num = std::ptr::read(addr_of!((*table_ptr).NumEntries)) as usize;
        let rows: *const MIB_IF_ROW2 = addr_of!((*table_ptr).Table) as *const MIB_IF_ROW2;
        if !rows.is_null() {
            for i in 0..num {
                let row_ptr = rows.add(i);
                if row_ptr.is_null() {
                    continue;
                }
                let row: &MIB_IF_ROW2 = &*row_ptr;
                if !is_viable_uplink(row) {
                    continue;
                }
                let alias = utf16_to_string(&row.Alias);
                let luid = row.InterfaceLuid.Value;
                out.push((luid, alias));
            }
        }
        FreeMibTable(table_ptr as *mut _);
    }
    Ok(out)
}

fn is_viable_uplink(row: &MIB_IF_ROW2) -> bool {
    // Must be operationally up.
    if row.OperStatus != IfOperStatusUp {
        return false;
    }

    // Hard exclusions by type.
    match row.Type {
        IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL => return false,
        _ => {}
    }

    // Allow only "normal" uplink types.
    match row.Type {
        IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_PPP => {}
        _ => return false,
    }

    // Bitfield: bit 0 = HardwareInterface. Must be a real hardware NIC.
    if (row.InterfaceAndOperStatusFlags._bitfield & 0x01) == 0 {
        return false;
    }

    // Dedicated physical link (not demand-dial, not passive tunnel).
    // `ConnectionType` is typed as `NET_IF_CONNECTION_TYPE = i32` while the
    // `IF_CONNECTION_DEDICATED` constant is `u32` — compare via cast.
    if row.ConnectionType != IF_CONNECTION_DEDICATED as i32 {
        return false;
    }

    // Description blacklist — belt & suspenders for VPN drivers that
    // impersonate Ethernet.
    let desc_l = utf16_to_string(&row.Description).to_ascii_lowercase();
    for bad in VPN_BLACKLIST {
        if desc_l.contains(bad) {
            return false;
        }
    }

    true
}

/// Ask the stack: if only this LUID existed, what's the best route + source
/// address toward `peer_ip`?
fn best_route_via(luid: u64, peer_ip: IpAddr) -> Result<(MIB_IPFORWARD_ROW2, IpAddr), String> {
    let dst = ip_to_sockaddr_inet(peer_ip);
    let net_luid = NET_LUID_LH { Value: luid };

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    let rc = unsafe {
        GetBestRoute2(
            &net_luid,
            0, // InterfaceIndex: 0 when LUID is provided
            std::ptr::null(),
            &dst,
            0,
            &mut row,
            &mut src,
        )
    };
    if rc != NO_ERROR {
        return Err(format!("rc={}", rc));
    }
    let src_ip =
        sockaddr_inet_to_ip(&src).ok_or_else(|| "source address family unknown".to_string())?;
    Ok((row, src_ip))
}

/// After adding our route, check the stack really picks our LUID.
fn verify_best_interface_luid(peer_ip: IpAddr) -> Result<u64, String> {
    let dst = ip_to_sockaddr_inet(peer_ip);
    let mut idx: u32 = 0;
    // GetBestInterfaceEx takes `SOCKADDR *`; SOCKADDR_INET has `si_family`
    // first in the same layout, so the cast is safe.
    let rc = unsafe { GetBestInterfaceEx(&dst as *const _ as *const SOCKADDR, &mut idx) };
    if rc != NO_ERROR {
        return Err(format!("GetBestInterfaceEx rc={}", rc));
    }
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = idx;
    let rc2 = unsafe { GetIfEntry2(&mut row) };
    if rc2 != NO_ERROR {
        return Err(format!("GetIfEntry2 rc={}", rc2));
    }
    Ok(unsafe { row.InterfaceLuid.Value })
}

// ─── helpers ──────────────────────────────────────────────────────────────

fn ip_to_sockaddr_inet(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            let p: *mut SOCKADDR_IN = &mut sa as *mut _ as *mut SOCKADDR_IN;
            unsafe {
                (*p).sin_family = AF_INET;
                // IN_ADDR.S_un is a union; write the 32-bit value directly.
                (*p).sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
            }
        }
        IpAddr::V6(v6) => {
            let p: *mut SOCKADDR_IN6 = &mut sa as *mut _ as *mut SOCKADDR_IN6;
            unsafe {
                (*p).sin6_family = AF_INET6;
                (*p).sin6_addr.u.Byte = v6.octets();
            }
        }
    }
    sa
}

fn sockaddr_inet_to_ip(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        let family = sa.si_family;
        if family == AF_INET {
            let bytes = sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        } else if family == AF_INET6 {
            Some(IpAddr::V6(Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte)))
        } else {
            None
        }
    }
}

fn set_host_prefix(row: &mut MIB_IPFORWARD_ROW2, peer_ip: IpAddr) {
    row.DestinationPrefix.Prefix = ip_to_sockaddr_inet(peer_ip);
    row.DestinationPrefix.PrefixLength = if peer_ip.is_ipv4() { 32 } else { 128 };
}

fn utf16_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
