//! Pure-Rust Linux network interface management.
//!
//! Uses RTnetlink messages and ioctl — no external binaries required.
//! This is the single authoritative place for all kernel network configuration
//! so that gutd can run as a fully static `FROM scratch` container with no
//! iproute2 / ethtool / ip present in the image.
//!
//! Public API summary:
//!   Interface queries : `link_exists`, `get_ifindex`, `read_mac`, `read_mtu`
//!   Link management   : `link_delete`, `veth_create`
//!   Link properties   : `link_set_mac`, `link_set_mtu`, `link_set_up`,
//!                       `link_set_noarp`, `link_disable_offloads`,
//!                       `link_set_gso_max_segs`
//!   Address / neighbor: `addr_add_p2p_v4`, `neigh_add_v4_permanent`
//!   Neighbor lookup   : `lookup_arp_cache`, `lookup_ndp_cache`
//!   Utilities         : `parse_mac`

use crate::Result;

// ── RTnetlink attribute type constants ───────────────────────────────────────
// IFLA attributes (linux/if_link.h)
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
// veth peer info (linux/if_link.h — VETH_INFO_PEER)
const VETH_INFO_PEER: u16 = 1;
// IFA attributes (linux/if_addr.h)
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
// NDA attributes (linux/neighbour.h)
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

// ── ioctl request codes (x86_64 / arm64 Linux — same values) ─────────────────
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCGIFHWADDR: libc::c_ulong = 0x8927;
const SIOCSIFMTU: libc::c_ulong = 0x8922;
const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
const SIOCGIFADDR: libc::c_ulong = 0x8915;
const SIOCETHTOOL: libc::c_ulong = 0x8946;

// ── ethtool command codes (linux/ethtool.h) ───────────────────────────────────
const ETHTOOL_STXCSUM: u32 = 0x0000_000e; // set TX checksum offload
const ETHTOOL_STSO: u32 = 0x0000_001e; // set TCP segmentation offload

// ── Address / neighbor constants ─────────────────────────────────────────────
const IFA_F_PERMANENT: u8 = 0x80;
const RT_SCOPE_UNIVERSE: u8 = 0;

// ── Internal helpers ──────────────────────────────────────────────────────────

/// RAII close guard for raw file descriptors.
struct FdGuard(std::os::fd::RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Copy an interface name into an `[c_char; IFNAMSIZ]` array (null-padded).
fn fill_ifname(dst: &mut [libc::c_char; libc::IFNAMSIZ], name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(libc::IFNAMSIZ - 1);
    for (i, &b) in bytes[..n].iter().enumerate() {
        dst[i] = b as libc::c_char;
    }
}

// ── RTnetlink message builder ─────────────────────────────────────────────────

struct NlBuf(Vec<u8>);

impl NlBuf {
    fn new() -> Self {
        Self(Vec::with_capacity(256))
    }
    fn push_u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn push_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_ne_bytes());
    }
    fn push_bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn align4(&mut self) {
        while !self.0.len().is_multiple_of(4) {
            self.0.push(0);
        }
    }
    fn patch_u16_at(&mut self, pos: usize, v: u16) {
        self.0[pos..pos + 2].copy_from_slice(&v.to_ne_bytes());
    }
    fn patch_u32_at(&mut self, pos: usize, v: u32) {
        self.0[pos..pos + 4].copy_from_slice(&v.to_ne_bytes());
    }
    /// Start an rtattr: write zero-length placeholder + type. Returns position of length.
    fn rta_begin(&mut self, rta_type: u16) -> usize {
        let pos = self.0.len();
        self.push_u16(0);
        self.push_u16(rta_type);
        pos
    }
    /// Finish an rtattr: patch length, pad to 4 bytes.
    fn rta_end(&mut self, start: usize) {
        let len = (self.0.len() - start) as u16;
        self.patch_u16_at(start, len);
        self.align4();
    }
    /// Write a complete attribute (header + data + padding).
    fn attr(&mut self, rta_type: u16, data: &[u8]) {
        let s = self.rta_begin(rta_type);
        self.push_bytes(data);
        self.rta_end(s);
    }
    /// Write a string attribute with null terminator.
    fn attr_str(&mut self, rta_type: u16, s: &str) {
        let pos = self.rta_begin(rta_type);
        self.push_bytes(s.as_bytes());
        self.0.push(0);
        self.rta_end(pos);
    }
    /// Patch `nlmsghdr.nlmsg_len` at offset 0.
    fn finalize_nlmsg(&mut self) {
        let len = self.0.len() as u32;
        self.patch_u32_at(0, len);
    }
    /// Write `struct ifinfomsg` (16 bytes).
    fn write_ifinfomsg(&mut self, family: u8, if_type: u16, index: i32, flags: u32, change: u32) {
        self.0.push(family);
        self.0.push(0); // pad
        self.push_u16(if_type);
        self.push_u32(index as u32);
        self.push_u32(flags);
        self.push_u32(change);
    }
    /// Write `struct ifaddrmsg` (8 bytes).
    fn write_ifaddrmsg(&mut self, family: u8, prefixlen: u8, flags: u8, scope: u8, index: u32) {
        self.0.push(family);
        self.0.push(prefixlen);
        self.0.push(flags);
        self.0.push(scope);
        self.push_u32(index);
    }
    /// Write `struct ndmsg` (12 bytes).
    fn write_ndmsg(&mut self, family: u8, ifindex: i32, state: u16, flags: u8, ndm_type: u8) {
        self.0.push(family);
        self.0.push(0); // pad1
        self.push_u16(0); // pad2
        self.push_u32(ifindex as u32);
        self.push_u16(state);
        self.0.push(flags);
        self.0.push(ndm_type);
    }
}

// ── RTnetlink message senders ─────────────────────────────────────────────────

/// Open an `AF_NETLINK` socket, send `msg`, receive one reply, and check the
/// `NLMSG_ERROR` error code.  Returns `Ok(())` on success (errno == 0).
fn nl_transact(msg: &[u8]) -> Result<()> {
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(format!("socket(AF_NETLINK): {}", std::io::Error::last_os_error()).into());
        }
        let _g = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return Err(format!("bind(AF_NETLINK): {}", std::io::Error::last_os_error()).into());
        }

        let sent = libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
        if sent < 0 {
            return Err(format!("netlink send: {}", std::io::Error::last_os_error()).into());
        }

        let mut buf = [0u8; 4096];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) as usize;
        let nlh_size = std::mem::size_of::<libc::nlmsghdr>();
        if n < nlh_size {
            return Err("netlink: short reply".into());
        }

        let nlh = &*(buf.as_ptr() as *const libc::nlmsghdr);
        if nlh.nlmsg_type == libc::NLMSG_ERROR as u16 {
            let off = nlh_size;
            if n >= off + 4 {
                let code = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
                if code != 0 {
                    return Err(format!(
                        "netlink error {code}: {}",
                        std::io::Error::from_raw_os_error(-code)
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
}

// ── Public interface query functions ─────────────────────────────────────────

/// Returns `true` if the interface exists (checks `/sys/class/net/<name>`).
pub fn link_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

/// Return the interface index for `name` via `if_nametoindex(3)`.
pub fn get_ifindex(name: &str) -> Result<i32> {
    use std::ffi::CString;
    let c = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(format!("Interface '{name}' not found").into());
    }
    Ok(idx.cast_signed())
}

/// Parse a colon-separated MAC string (e.g. `"02:47:0a:00:00:01"`) into `[u8; 6]`.
pub fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("Invalid MAC format: {mac}").into());
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] =
            u8::from_str_radix(p, 16).map_err(|_| format!("Invalid MAC byte '{p}' in '{mac}'"))?;
    }
    Ok(out)
}

/// Read the MAC address of `name` from `/sys/class/net/<name>/address`.
pub fn read_mac(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{name}/address");
    let s =
        std::fs::read_to_string(&path).map_err(|e| format!("Cannot read MAC for '{name}': {e}"))?;
    parse_mac(s.trim())
}

/// Read the MTU of `name` from `/sys/class/net/<name>/mtu`.
pub fn read_mtu(name: &str) -> Result<u16> {
    let path = format!("/sys/class/net/{name}/mtu");
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read MTU for '{name}': {e}"))?
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("Invalid MTU for '{name}': {e}").into())
}

/// Read `gso_max_size` from `/sys/class/net/<name>/gso_max_size`.
pub fn read_gso_max_size(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{name}/gso_max_size");
    std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read gso_max_size for '{name}': {e}"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("Invalid gso_max_size for '{name}': {e}").into())
}

// ── Link management (RTnetlink) ───────────────────────────────────────────────

/// Delete an interface by name (RTM_DELLINK).
/// Silently ignores ENODEV.  Deleting one end of a veth pair removes both.
pub fn link_delete(name: &str) {
    let idx = match get_ifindex(name) {
        Ok(i) => i,
        Err(_) => return, // already gone
    };
    let mut buf = NlBuf::new();
    buf.push_u32(0); // len placeholder
    buf.push_u16(libc::RTM_DELLINK);
    buf.push_u16((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16);
    buf.push_u32(1);
    buf.push_u32(0);
    buf.write_ifinfomsg(libc::AF_UNSPEC as u8, 0, idx, 0, 0);
    buf.finalize_nlmsg();
    let _ = nl_transact(&buf.0);
}

/// Create a veth pair `name` ↔ `peer` (RTM_NEWLINK with IFLA_LINKINFO veth).
///
/// The message structure:
/// ```text
/// nlmsghdr  ifinfomsg(first end)  IFLA_IFNAME  IFLA_LINKINFO {
///   IFLA_INFO_KIND="veth"  IFLA_INFO_DATA { VETH_INFO_PEER {
///     ifinfomsg(zeroed)  IFLA_IFNAME(peer)
/// }}}
/// ```
pub fn veth_create(name: &str, peer: &str) -> Result<()> {
    let mut buf = NlBuf::new();

    // nlmsghdr
    buf.push_u32(0);
    buf.push_u16(libc::RTM_NEWLINK);
    buf.push_u16(
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK) as u16,
    );
    buf.push_u32(1);
    buf.push_u32(0);

    // First end: ifinfomsg (zeroed)
    buf.write_ifinfomsg(libc::AF_UNSPEC as u8, 0, 0, 0, 0);

    // IFLA_IFNAME for first end
    buf.attr_str(IFLA_IFNAME, name);

    // IFLA_LINKINFO
    let li = buf.rta_begin(IFLA_LINKINFO);

    // IFLA_INFO_KIND = "veth"
    buf.attr_str(IFLA_INFO_KIND, "veth");

    // IFLA_INFO_DATA
    let ld = buf.rta_begin(IFLA_INFO_DATA);

    // VETH_INFO_PEER
    let vp = buf.rta_begin(VETH_INFO_PEER);

    // Peer end: ifinfomsg (zeroed, 16 bytes) — required by kernel veth driver
    buf.write_ifinfomsg(0, 0, 0, 0, 0);

    // IFLA_IFNAME for peer end
    buf.attr_str(IFLA_IFNAME, peer);

    buf.rta_end(vp);
    buf.rta_end(ld);
    buf.rta_end(li);

    buf.finalize_nlmsg();

    nl_transact(&buf.0).map_err(|e| format!("veth_create({name} ↔ {peer}): {e}").into())
}

// ── Link properties (ioctl) ───────────────────────────────────────────────────

/// Open an `AF_INET SOCK_DGRAM` socket suitable for ioctl interface operations.
fn ioctl_sock() -> std::os::fd::RawFd {
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) }
}

/// Set the MAC address of `name` via `SIOCSIFHWADDR`.
pub fn link_set_mac(name: &str, mac: &[u8; 6]) -> Result<()> {
    unsafe {
        let sock = ioctl_sock();
        if sock < 0 {
            return Err("socket for SIOCSIFHWADDR failed".into());
        }
        let _g = FdGuard(sock);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifr.ifr_name, name);
        ifr.ifr_ifru.ifru_hwaddr.sa_family = 1; // ARPHRD_ETHER
        for (i, &b) in mac.iter().enumerate() {
            ifr.ifr_ifru.ifru_hwaddr.sa_data[i] = b as libc::c_char;
        }
        if libc::ioctl(sock, SIOCSIFHWADDR as _, &ifr) != 0 {
            return Err(
                format!("SIOCSIFHWADDR({name}): {}", std::io::Error::last_os_error()).into(),
            );
        }
        Ok(())
    }
}

/// Set the MTU of `name` via `SIOCSIFMTU`.
pub fn link_set_mtu(name: &str, mtu: u32) -> Result<()> {
    unsafe {
        let sock = ioctl_sock();
        if sock < 0 {
            return Err("socket for SIOCSIFMTU failed".into());
        }
        let _g = FdGuard(sock);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifr.ifr_name, name);
        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        if libc::ioctl(sock, SIOCSIFMTU as _, &ifr) != 0 {
            return Err(format!(
                "SIOCSIFMTU({name}, {mtu}): {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        Ok(())
    }
}

/// Read current `IFF_*` flags from `SIOCGIFFLAGS`.
unsafe fn get_iface_flags(sock: libc::c_int, name: &str) -> libc::c_short {
    let mut ifr: libc::ifreq = std::mem::zeroed();
    fill_ifname(&mut ifr.ifr_name, name);
    if libc::ioctl(sock, SIOCGIFFLAGS as _, &mut ifr) == 0 {
        ifr.ifr_ifru.ifru_flags
    } else {
        0
    }
}

/// Apply `IFF_*` flags via `SIOCSIFFLAGS`.
unsafe fn set_iface_flags(sock: libc::c_int, name: &str, flags: libc::c_short) {
    let mut ifr: libc::ifreq = std::mem::zeroed();
    fill_ifname(&mut ifr.ifr_name, name);
    ifr.ifr_ifru.ifru_flags = flags;
    libc::ioctl(sock, SIOCSIFFLAGS as _, &ifr);
}

/// Bring an interface up (`IFF_UP`).
pub fn link_set_up(name: &str) {
    unsafe {
        let sock = ioctl_sock();
        if sock < 0 {
            return;
        }
        let _g = FdGuard(sock);
        let flags = get_iface_flags(sock, name);
        set_iface_flags(sock, name, flags | libc::IFF_UP as libc::c_short);
    }
}

/// Set `IFF_NOARP` on an interface (disables ARP — useful for point-to-point
/// veth interfaces where we configure static neighbors).
pub fn link_set_noarp(name: &str) {
    const IFF_NOARP: libc::c_short = 0x0080;
    unsafe {
        let sock = ioctl_sock();
        if sock < 0 {
            return;
        }
        let _g = FdGuard(sock);
        let flags = get_iface_flags(sock, name);
        set_iface_flags(sock, name, flags | IFF_NOARP);
    }
}

/// Disable TX checksum offload and TSO via `SIOCETHTOOL` (ethtool ioctl).
///
/// This ensures that packets arriving at the TC BPF egress hook always carry a
/// complete L4 checksum and are not coalesced by GSO, which would confuse the
/// BPF datapath on some kernels / veth configurations.
pub fn link_disable_offloads(name: &str) {
    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }

    unsafe {
        let sock = ioctl_sock();
        if sock < 0 {
            return;
        }
        let _g = FdGuard(sock);
        for cmd in [ETHTOOL_STXCSUM, ETHTOOL_STSO] {
            let mut ev = EthtoolValue { cmd, data: 0 };
            let mut ifr: libc::ifreq = std::mem::zeroed();
            fill_ifname(&mut ifr.ifr_name, name);
            ifr.ifr_ifru.ifru_data = &mut ev as *mut EthtoolValue as *mut libc::c_char;
            libc::ioctl(sock, SIOCETHTOOL as _, &ifr);
        }
    }
}

/// Set `gso_max_segs` via RTM_NEWLINK with IFLA_GSO_MAX_SEGS (kernel ≥ 4.16).
/// Falls back to sysfs write if netlink fails.
pub fn link_set_gso_max_segs(name: &str, segs: u32) {
    if nl_set_gso(name, IFLA_GSO_MAX_SEGS, segs).is_err() {
        // sysfs fallback (works on older kernels / some container configs)
        let _ = std::fs::write(
            format!("/sys/class/net/{name}/gso_max_segs"),
            segs.to_string(),
        );
    }
}

/// Set `gso_max_size` via RTM_NEWLINK with IFLA_GSO_MAX_SIZE (kernel ≥ 4.16).
/// Falls back to sysfs write if netlink fails.
pub fn link_set_gso_max_size(name: &str, size: u32) {
    if nl_set_gso(name, IFLA_GSO_MAX_SIZE, size).is_err() {
        let _ = std::fs::write(
            format!("/sys/class/net/{name}/gso_max_size"),
            size.to_string(),
        );
    }
}

/// Internal: send RTM_NEWLINK with a single u32 attribute (used for GSO limits).
fn nl_set_gso(name: &str, attr: u16, value: u32) -> Result<()> {
    let ifindex = get_ifindex(name)?;
    let mut buf = NlBuf::new();
    buf.push_u32(0);
    buf.push_u16(libc::RTM_NEWLINK);
    buf.push_u16((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16);
    buf.push_u32(1);
    buf.push_u32(0);
    buf.write_ifinfomsg(libc::AF_UNSPEC as u8, 0, ifindex, 0, 0);
    buf.attr(attr, &value.to_ne_bytes());
    buf.finalize_nlmsg();
    nl_transact(&buf.0)
}

// ── Address and neighbor management (RTnetlink) ───────────────────────────────

/// Assign a point-to-point IPv4 address via `RTM_NEWADDR`.
///
/// Equivalent to: `ip addr add <local_ip> peer <peer_ip>/<prefix> dev <name>`
///
/// For a /30 pair `10.99.0.1/30 ↔ 10.99.0.2`: pass
///   `local_ip = "10.99.0.1"`, `peer_ip = "10.99.0.2"`, `prefix = 30`.
pub fn addr_add_p2p_v4(name: &str, local_ip: &str, peer_ip: &str, prefix: u8) -> Result<()> {
    let ifindex = get_ifindex(name)?;
    let local: std::net::Ipv4Addr = local_ip
        .parse()
        .map_err(|_| format!("Invalid local IP: {local_ip}"))?;
    let peer: std::net::Ipv4Addr = peer_ip
        .parse()
        .map_err(|_| format!("Invalid peer IP: {peer_ip}"))?;

    let mut buf = NlBuf::new();
    buf.push_u32(0);
    buf.push_u16(libc::RTM_NEWADDR);
    buf.push_u16(
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK) as u16,
    );
    buf.push_u32(1);
    buf.push_u32(0);
    buf.write_ifaddrmsg(
        libc::AF_INET as u8,
        prefix,
        IFA_F_PERMANENT,
        RT_SCOPE_UNIVERSE,
        ifindex as u32,
    );
    buf.attr(IFA_LOCAL, &local.octets());
    // For P2P: IFA_ADDRESS is the *peer* address (remote end)
    buf.attr(IFA_ADDRESS, &peer.octets());
    buf.finalize_nlmsg();

    nl_transact(&buf.0).map_err(|e| {
        format!("addr_add_p2p_v4({name}, {local_ip} peer {peer_ip}/{prefix}): {e}").into()
    })
}

/// Add a permanent IPv4 neighbor (ARP) entry via `RTM_NEWNEIGH`.
///
/// Equivalent to: `ip neigh add <ip> lladdr <mac> dev <name> nud permanent`
pub fn neigh_add_v4_permanent(name: &str, ip: &str, mac: &[u8; 6]) -> Result<()> {
    let ifindex = get_ifindex(name)?;
    let addr: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| format!("Invalid neighbor IP: {ip}"))?;

    let mut buf = NlBuf::new();
    buf.push_u32(0);
    buf.push_u16(libc::RTM_NEWNEIGH);
    buf.push_u16(
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_REPLACE | libc::NLM_F_ACK) as u16,
    );
    buf.push_u32(1);
    buf.push_u32(0);
    buf.write_ndmsg(
        libc::AF_INET as u8,
        ifindex,
        libc::NUD_PERMANENT,
        0,
        libc::RTN_UNICAST,
    );
    buf.attr(NDA_DST, &addr.octets());
    buf.attr(NDA_LLADDR, mac);
    buf.finalize_nlmsg();

    nl_transact(&buf.0).map_err(|e| format!("neigh_add_v4_permanent({name}, {ip}): {e}").into())
}

// ── Neighbor cache lookup ─────────────────────────────────────────────────────

// IP_UNICAST_IF — specify outgoing interface for UDP without CAP_NET_RAW (Linux ≥ 3.9)
const IP_UNICAST_IF: libc::c_int = 50;

/// Trigger kernel ARP resolution by sending a UDP probe on `ifname`.
/// Uses IP_UNICAST_IF (no CAP_NET_RAW needed) + SO_BINDTODEVICE (best-effort).
/// Sends an actual byte so the kernel immediately resolves the next-hop MAC.
/// Send a raw ARP Request (who-has `target_ip`) on `ifname`.
///
/// Uses `AF_PACKET` + `SOCK_RAW` so the kernel puts it directly on the wire
/// and will populate its own ARP table when the reply arrives.  Requires
/// `CAP_NET_RAW`; silently ignored if the capability is absent.
///
/// Sender MAC/IP are read via ioctl (no sysfs) so this works in containers
/// where `/sys/class/net` may be absent.
/// Send an ARP Request for `target_ip` on `ifname` and wait for the reply,
/// reading it directly from the AF_PACKET socket — does NOT rely on the kernel
/// neighbor table or `/proc/net/arp` (both unreliable inside container namespaces).
///
/// 4 attempts × 400 ms each.  Returns None if CAP_NET_RAW is absent.
pub fn arp_request_reply(target_ip: std::net::Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    unsafe {
        let arp_proto = (0x0806u16).to_be() as libc::c_int;
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            arp_proto,
        );
        if fd < 0 {
            return None;
        } // CAP_NET_RAW absent
        let _guard = FdGuard(fd);

        let ifindex = match get_ifindex(ifname) {
            Ok(i) => i,
            Err(_) => return None,
        };

        // Bind to this interface + ARP ethertype (filters out other traffic)
        let mut bind_sll: libc::sockaddr_ll = std::mem::zeroed();
        bind_sll.sll_family = libc::AF_PACKET as u16;
        bind_sll.sll_protocol = (0x0806u16).to_be();
        bind_sll.sll_ifindex = ifindex;
        if libc::bind(
            fd,
            &bind_sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) < 0
        {
            return None;
        }

        // Read our MAC via SIOCGIFHWADDR ioctl (no sysfs needed)
        let mut ifreq: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifreq.ifr_name, ifname);
        if libc::ioctl(fd, SIOCGIFHWADDR as _, &raw mut ifreq) < 0 {
            return None;
        }
        let sd = ifreq.ifr_ifru.ifru_hwaddr.sa_data;
        let src_mac: [u8; 6] = [
            sd[0] as u8,
            sd[1] as u8,
            sd[2] as u8,
            sd[3] as u8,
            sd[4] as u8,
            sd[5] as u8,
        ];

        // Read our IP via SIOCGIFADDR — requires an AF_INET socket (not AF_PACKET).
        // Using the AF_PACKET fd for SIOCGIFADDR silently returns zero on most kernels,
        // producing a 0.0.0.0 sender IP (ARP Probe) which RouterOS ignores.
        let inet_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        let mut ifreq2: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifreq2.ifr_name, ifname);
        let sender_ip: [u8; 4] =
            if inet_fd >= 0 && libc::ioctl(inet_fd, SIOCGIFADDR as _, &raw mut ifreq2) >= 0 {
                let p = &ifreq2.ifr_ifru.ifru_addr as *const libc::sockaddr as *const u8;
                let ip = [*p.add(4), *p.add(5), *p.add(6), *p.add(7)];
                libc::close(inet_fd);
                ip
            } else {
                if inet_fd >= 0 {
                    libc::close(inet_fd);
                }
                [0, 0, 0, 0]
            };

        // ARP REQUEST frame: 14-byte Ethernet header + 28-byte ARP payload = 42 bytes
        // Layout:
        //   [0..6]   dst MAC = ff:ff:ff:ff:ff:ff (broadcast)
        //   [6..12]  src MAC = our MAC
        //   [12..14] EtherType = 0x0806
        //   [14..16] hw type = 0x0001 (Ethernet)
        //   [16..18] proto type = 0x0800 (IPv4)
        //   [18]     hw addr len = 6
        //   [19]     proto addr len = 4
        //   [20..22] opcode = 0x0001 (REQUEST)
        //   [22..28] sender MAC
        //   [28..32] sender IP
        //   [32..38] target MAC = 0 (unknown)
        //   [38..42] target IP
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        frame[14] = 0x00;
        frame[15] = 0x01;
        frame[16] = 0x08;
        frame[17] = 0x00;
        frame[18] = 6;
        frame[19] = 4;
        frame[20] = 0x00;
        frame[21] = 0x01; // REQUEST
        frame[22..28].copy_from_slice(&src_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        // [32..38] already zero (target MAC unknown)
        frame[38..42].copy_from_slice(&target_ip.octets());

        let mut dst_sll: libc::sockaddr_ll = std::mem::zeroed();
        dst_sll.sll_family = libc::AF_PACKET as u16;
        dst_sll.sll_protocol = (0x0806u16).to_be();
        dst_sll.sll_ifindex = ifindex;
        dst_sll.sll_halen = 6;
        dst_sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);

        // 400 ms recv timeout per attempt
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 400_000,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let target_octets = target_ip.octets();
        let mut buf = [0u8; 256];

        for _ in 0..4 {
            // Send ARP Request
            libc::sendto(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &raw const dst_sll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );

            // Read packets until timeout or we find the ARP Reply
            loop {
                let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                if n < 0 {
                    break;
                } // EAGAIN/timeout → send another request
                if n < 42 {
                    continue;
                }
                // ARP REPLY (opcode=2) from target_ip
                // buf offsets: [12..14]=EtherType [20..22]=opcode [28..32]=senderIP
                if buf[12] == 0x08
                    && buf[13] == 0x06
                    && buf[20] == 0x00
                    && buf[21] == 0x02
                    && buf[28..32] == target_octets
                {
                    // Sender MAC is at [22..28]
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&buf[22..28]);
                    return Some(mac);
                }
            }
        }
        None
    }
}

/// Send an ARP Request (fire-and-forget, no reply capture).
/// Relies on the kernel to populate its own neighbor table when the reply arrives.
/// Use `arp_request_reply` instead when you need the MAC directly.
pub fn probe_arp_request(target_ip: std::net::Ipv4Addr, ifname: &str) {
    // Delegate — we just discard the reply.
    let _ = arp_request_reply(target_ip, ifname);
}

/// Send an IP/UDP frame with TTL=1 directly via AF_PACKET (bypasses kernel ARP),
/// then listen for ICMP TTL-Exceeded (type 11) coming back from `gateway_ip`.
///
/// This is a fallback for environments (e.g. RouterOS containers) where the
/// gateway silently ignores ARP requests.  The ICMP reply carries the gateway's
/// Ethernet source MAC, so we never need ARP to learn it.
///
/// `probe_dst_ip` must not equal `gateway_ip` (the packet must be forwarded by
/// the gateway so it decrements TTL and generates ICMP).  The peer IP works well.
///
/// 4 attempts × 400 ms.  Returns None if CAP_NET_RAW is absent or no reply arrives.
pub fn resolve_mac_via_ttl_probe(
    gateway_ip: std::net::Ipv4Addr,
    probe_dst_ip: std::net::Ipv4Addr,
    ifname: &str,
) -> Option<[u8; 6]> {
    unsafe {
        let eth_p_ip = (0x0800u16).to_be() as libc::c_int;
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            eth_p_ip,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let ifindex = match get_ifindex(ifname) {
            Ok(i) => i,
            Err(_) => return None,
        };

        // Bind to this interface + ETH_P_IP so we only see IPv4 frames
        let mut bind_sll: libc::sockaddr_ll = std::mem::zeroed();
        bind_sll.sll_family = libc::AF_PACKET as u16;
        bind_sll.sll_protocol = (0x0800u16).to_be();
        bind_sll.sll_ifindex = ifindex;
        if libc::bind(
            fd,
            &bind_sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) < 0
        {
            return None;
        }

        // Use an AF_INET socket for both SIOCGIFHWADDR (our MAC) and SIOCGIFADDR
        // (our IPv4 address used as IP source in the probe frame).
        let inet_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if inet_fd < 0 {
            return None;
        }
        let _guard_inet = FdGuard(inet_fd);

        let mut ifreq: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifreq.ifr_name, ifname);
        if libc::ioctl(inet_fd, SIOCGIFHWADDR as _, &raw mut ifreq) < 0 {
            return None;
        }
        let sd = ifreq.ifr_ifru.ifru_hwaddr.sa_data;
        let src_mac: [u8; 6] = [
            sd[0] as u8,
            sd[1] as u8,
            sd[2] as u8,
            sd[3] as u8,
            sd[4] as u8,
            sd[5] as u8,
        ];

        let mut ifreq2: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifreq2.ifr_name, ifname);
        let src_ip_b: [u8; 4] = if libc::ioctl(inet_fd, SIOCGIFADDR as _, &raw mut ifreq2) >= 0 {
            let p = &ifreq2.ifr_ifru.ifru_addr as *const libc::sockaddr as *const u8;
            [*p.add(4), *p.add(5), *p.add(6), *p.add(7)]
        } else {
            [0, 0, 0, 0]
        };

        let dst_ip_b = probe_dst_ip.octets();
        let gw_ip_b = gateway_ip.octets();

        // Build: 14-byte Ethernet + 20-byte IP + 8-byte UDP = 42 bytes
        //
        // Key fields:
        //   Ethernet dst = ff:ff:ff:ff:ff:ff  (broadcast — bypasses ARP for dst)
        //   IP TTL       = 1                  (gateway sends ICMP TTL-Exceeded back)
        let mut frame = [0u8; 42];

        // Ethernet header
        frame[0..6].copy_from_slice(&[0xff; 6]); // dst = broadcast
        frame[6..12].copy_from_slice(&src_mac); // src = our MAC
        frame[12] = 0x08;
        frame[13] = 0x00; // EtherType = IPv4

        // IP header (offset 14)
        {
            let ip = &mut frame[14..34];
            ip[0] = 0x45; // version=4, IHL=5 (20 bytes)
            ip[1] = 0; // DSCP/ECN
            ip[2] = 0;
            ip[3] = 28; // total length = 20+8 = 28
            ip[4] = 0;
            ip[5] = 1; // identification
            ip[6] = 0;
            ip[7] = 0; // flags / fragment offset
            ip[8] = 1; // TTL = 1  ← gateway will decrement to 0 → ICMP
            ip[9] = 17; // protocol = UDP
                        // ip[10..12] = checksum (zero for calculation)
            ip[12..16].copy_from_slice(&src_ip_b);
            ip[16..20].copy_from_slice(&dst_ip_b);
            // IP header checksum (ones-complement sum of the 10 16-bit words)
            let mut csum: u32 = 0;
            for i in (0..20).step_by(2) {
                csum += ((ip[i] as u32) << 8) | (ip[i + 1] as u32);
            }
            while csum >> 16 != 0 {
                csum = (csum & 0xffff) + (csum >> 16);
            }
            let csum = !(csum as u16);
            ip[10] = (csum >> 8) as u8;
            ip[11] = (csum & 0xff) as u8;
        }

        // UDP header (offset 34)
        {
            let udp = &mut frame[34..42];
            udp[0] = 0x30;
            udp[1] = 0x39; // src port = 12345
            udp[2] = 0x30;
            udp[3] = 0x39; // dst port = 12345
            udp[4] = 0;
            udp[5] = 8; // length = 8 (header only)
                        // udp[6..8] = checksum = 0 (optional for IPv4)
        }

        // Destination sockaddr_ll — broadcast
        let mut dst_sll: libc::sockaddr_ll = std::mem::zeroed();
        dst_sll.sll_family = libc::AF_PACKET as u16;
        dst_sll.sll_protocol = (0x0800u16).to_be();
        dst_sll.sll_ifindex = ifindex;
        dst_sll.sll_halen = 6;
        dst_sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);

        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 400_000,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );

        let mut buf = [0u8; 256];

        for _ in 0..4 {
            libc::sendto(
                fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &raw const dst_sll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            );

            loop {
                let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                if n < 0 {
                    break;
                } // EAGAIN / timeout → next attempt
                  // Minimum: 14 (eth) + 20 (ip) + 8 (icmp) = 42
                if (n as usize) < 42 {
                    continue;
                }
                // EtherType must be IPv4
                if buf[12] != 0x08 || buf[13] != 0x00 {
                    continue;
                }
                // IP protocol must be ICMP (1)
                if buf[14 + 9] != 1 {
                    continue;
                }
                // Source IP must be the gateway
                if buf[14 + 12..14 + 16] != gw_ip_b {
                    continue;
                }
                // ICMP type 11 = TTL Exceeded  (type 3 = Port Unreachable, also ok)
                let icmp_type = buf[14 + 20];
                if icmp_type == 11 || icmp_type == 3 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&buf[6..12]); // Ethernet source MAC
                    return Some(mac);
                }
            }
        }
        None
    }
}

pub fn probe_neighbor_udp(ip: std::net::IpAddr, ifname: &str) {
    use std::ffi::CString;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::io::AsRawFd;

    let target: SocketAddr = SocketAddr::new(ip, 1);
    let bind: SocketAddr = match ip {
        std::net::IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        std::net::IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return;
    };
    let fd = sock.as_raw_fd();

    // IP_UNICAST_IF: route outgoing packets via ifname without CAP_NET_RAW
    if let Ok(ifindex) = get_ifindex(ifname) {
        let idx_be = (ifindex as u32).to_be();
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                IP_UNICAST_IF,
                &idx_be as *const _ as *const libc::c_void,
                4,
            );
        }
    }
    // SO_BINDTODEVICE: also try this if CAP_NET_RAW is available (best-effort)
    if let Ok(c) = CString::new(ifname) {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c.as_ptr() as *const libc::c_void,
                (ifname.len() + 1) as libc::socklen_t,
            );
        }
    }
    let _ = sock.connect(target);
    // Actually send a byte — connect() alone does NOT trigger ARP; send() does.
    // NOTE: do NOT call probe_arp_request here — if the target is L3-routed
    // (not on the same L2), ARP for target IP will go unanswered. The kernel
    // correctly ARPs for the nexthop (gateway) when send() is called.
    let _ = sock.send(b"\x00");
}

/// Look up an IPv4 MAC address from the kernel ARP/neighbor table.
///
/// Primary: RTM_GETNEIGH netlink (works in all container namespaces).
/// Fallback: `/proc/net/arp` (legacy, may be absent/empty in some containers).
pub fn lookup_arp_cache(ip: std::net::Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    // Try netlink RTM_GETNEIGH first — does not depend on /proc visibility.
    if let Ok(ifindex) = get_ifindex(ifname) {
        if let Some(mac) = nl_get_neigh_v4(ip, ifindex as u32) {
            return Some(mac);
        }
        // Some kernels (container namespaces) ignore ndm_ifindex in NLM_F_DUMP
        // and return an empty response.  Retry with a full dump (ifindex=0) and
        // filter by ifindex in the parser.  This is a no-op if the first query
        // already returned results.
        if let Some(mac) = nl_get_neigh_v4(ip, 0) {
            return Some(mac);
        }
    }
    // Fallback: /proc/net/arp (unreliable in some container namespaces).
    let Ok(content) = std::fs::read_to_string("/proc/net/arp") else {
        return None;
    };
    let target = ip.to_string();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // columns: ip  hw_type  flags  mac  mask  dev
        if cols.len() < 6 {
            continue;
        }
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
        if cols[0] == target && cols[5] == ifname && flags != 0 {
            return parse_mac(cols[3]).ok();
        }
    }
    None
}

/// Look up an IPv6 neighbor MAC via `RTM_GETNEIGH` netlink dump.
pub fn lookup_ndp_cache(ip: std::net::Ipv6Addr, ifname: &str) -> Option<[u8; 6]> {
    let ifindex = get_ifindex(ifname).ok()? as u32;
    nl_get_neigh_v6(ip, ifindex)
}

// ── RTM_GETNEIGH + parse helpers ─────────────────────────────────────────────

/// Look up an IPv4 neighbor MAC via RTM_GETNEIGH netlink dump (AF_INET).
fn nl_get_neigh_v4(ip: std::net::Ipv4Addr, ifindex: u32) -> Option<[u8; 6]> {
    use std::os::fd::RawFd;
    unsafe {
        let fd: RawFd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE as libc::c_int,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return None;
        }

        #[repr(C)]
        struct NlMsgNdmsg {
            nlh: libc::nlmsghdr,
            ndm_family: u8,
            ndm_pad1: u8,
            ndm_pad2: u16,
            ndm_ifindex: i32,
            ndm_state: u16,
            ndm_flags: u8,
            ndm_type: u8,
        }
        let mut req: NlMsgNdmsg = std::mem::zeroed();
        req.nlh.nlmsg_len = std::mem::size_of::<NlMsgNdmsg>() as u32;
        req.nlh.nlmsg_type = libc::RTM_GETNEIGH;
        req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req.nlh.nlmsg_seq = 2;
        req.ndm_family = libc::AF_INET as u8;
        // When ifindex==0 we request a full dump; parse_neigh_nlmsg_v4 filters
        // by ifindex only when ifindex != 0, matching any interface otherwise.
        req.ndm_ifindex = ifindex as i32;

        if libc::send(
            fd,
            &req as *const NlMsgNdmsg as *const libc::c_void,
            req.nlh.nlmsg_len as libc::size_t,
            0,
        ) < 0
        {
            return None;
        }

        let target = ip.octets();
        let mut buf = [0u8; 8192];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                break;
            }
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= n as usize {
                let nlh = &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr);
                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > n as usize
                {
                    break;
                }
                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    return None;
                }
                if nlh.nlmsg_type == libc::RTM_NEWNEIGH {
                    if let Some(mac) =
                        parse_neigh_nlmsg_v4(buf.as_ptr().add(offset), msg_len, &target, ifindex)
                    {
                        return Some(mac);
                    }
                }
                offset += (msg_len + 3) & !3;
            }
        }
        None
    }
}

/// Parse RTM_NEWNEIGH for AF_INET (4-byte NDA_DST).
unsafe fn parse_neigh_nlmsg_v4(
    base: *const u8,
    msg_len: usize,
    target_ip4: &[u8; 4],
    ifindex: u32,
) -> Option<[u8; 6]> {
    #[repr(C)]
    struct Ndmsg {
        ndm_family: u8,
        ndm_pad1: u8,
        ndm_pad2: u16,
        ndm_ifindex: i32,
        ndm_state: u16,
        ndm_flags: u8,
        ndm_type: u8,
    }
    #[repr(C)]
    struct Rtattr {
        rta_len: u16,
        rta_type: u16,
    }

    let nlh_size = std::mem::size_of::<libc::nlmsghdr>();
    let ndm_size = std::mem::size_of::<Ndmsg>();
    if msg_len < nlh_size + ndm_size {
        return None;
    }

    let ndm = &*(base.add(nlh_size) as *const Ndmsg);
    const NUD_VALID: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80; // REACHABLE|STALE|DELAY|PROBE|PERMANENT
                                                             // ifindex==0 means "match any interface" (used for full-dump fallback).
    if (ifindex != 0 && ndm.ndm_ifindex as u32 != ifindex) || ndm.ndm_state & NUD_VALID == 0 {
        return None;
    }

    let rta_hdr = std::mem::size_of::<Rtattr>();
    let mut off = (nlh_size + ndm_size + 3) & !3;
    let mut found_ip = false;
    let mut mac: Option<[u8; 6]> = None;

    while off + rta_hdr <= msg_len {
        let rta = &*(base.add(off) as *const Rtattr);
        let rlen = rta.rta_len as usize;
        if rlen < rta_hdr || off + rlen > msg_len {
            break;
        }
        let dptr = base.add(off + rta_hdr);
        let dlen = rlen - rta_hdr;
        match rta.rta_type {
            1 /* NDA_DST */ => {
                if dlen == 4 {
                    let mut a = [0u8; 4];
                    std::ptr::copy_nonoverlapping(dptr, a.as_mut_ptr(), 4);
                    if &a == target_ip4 { found_ip = true; }
                }
            }
            2 /* NDA_LLADDR */ => {
                if dlen == 6 {
                    let mut m = [0u8; 6];
                    std::ptr::copy_nonoverlapping(dptr, m.as_mut_ptr(), 6);
                    mac = Some(m);
                }
            }
            _ => {}
        }
        off += (rlen + 3) & !3;
    }
    if found_ip {
        mac
    } else {
        None
    }
}

fn nl_get_neigh_v6(ip: std::net::Ipv6Addr, ifindex: u32) -> Option<[u8; 6]> {
    use std::os::fd::RawFd;
    unsafe {
        let fd: RawFd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE as libc::c_int,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) < 0
        {
            return None;
        }

        #[repr(C)]
        struct NlMsgNdmsg {
            nlh: libc::nlmsghdr,
            ndm_family: u8,
            ndm_pad1: u8,
            ndm_pad2: u16,
            ndm_ifindex: i32,
            ndm_state: u16,
            ndm_flags: u8,
            ndm_type: u8,
        }
        let mut req: NlMsgNdmsg = std::mem::zeroed();
        req.nlh.nlmsg_len = std::mem::size_of::<NlMsgNdmsg>() as u32;
        req.nlh.nlmsg_type = libc::RTM_GETNEIGH;
        req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req.nlh.nlmsg_seq = 1;
        req.ndm_family = libc::AF_INET6 as u8;
        req.ndm_ifindex = ifindex as i32;

        if libc::send(
            fd,
            &req as *const NlMsgNdmsg as *const libc::c_void,
            req.nlh.nlmsg_len as libc::size_t,
            0,
        ) < 0
        {
            return None;
        }

        let target = ip.octets();
        let mut buf = [0u8; 8192];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                break;
            }
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= n as usize {
                let nlh = &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr);
                let msg_len = nlh.nlmsg_len as usize;
                if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > n as usize
                {
                    break;
                }
                if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                    return None;
                }
                if nlh.nlmsg_type == libc::RTM_NEWNEIGH {
                    if let Some(mac) =
                        parse_neigh_nlmsg(buf.as_ptr().add(offset), msg_len, &target, ifindex)
                    {
                        return Some(mac);
                    }
                }
                offset += (msg_len + 3) & !3;
            }
        }
        None
    }
}

/// Parse a single `RTM_NEWNEIGH` message and return the MAC if it matches
/// `target_ip6` on `ifindex` and the entry is in a valid/reachable state.
unsafe fn parse_neigh_nlmsg(
    base: *const u8,
    msg_len: usize,
    target_ip6: &[u8; 16],
    ifindex: u32,
) -> Option<[u8; 6]> {
    #[repr(C)]
    struct Ndmsg {
        ndm_family: u8,
        ndm_pad1: u8,
        ndm_pad2: u16,
        ndm_ifindex: i32,
        ndm_state: u16,
        ndm_flags: u8,
        ndm_type: u8,
    }
    #[repr(C)]
    struct Rtattr {
        rta_len: u16,
        rta_type: u16,
    }

    let nlh_size = std::mem::size_of::<libc::nlmsghdr>();
    let ndm_size = std::mem::size_of::<Ndmsg>();
    if msg_len < nlh_size + ndm_size {
        return None;
    }

    let ndm = &*(base.add(nlh_size) as *const Ndmsg);

    // Accept: REACHABLE | STALE | DELAY | PROBE | PERMANENT
    const NUD_VALID: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;
    if ndm.ndm_ifindex as u32 != ifindex || ndm.ndm_state & NUD_VALID == 0 {
        return None;
    }

    let rta_hdr = std::mem::size_of::<Rtattr>();
    let mut off = (nlh_size + ndm_size + 3) & !3;
    let mut found_ip = false;
    let mut mac: Option<[u8; 6]> = None;

    while off + rta_hdr <= msg_len {
        let rta = &*(base.add(off) as *const Rtattr);
        let rlen = rta.rta_len as usize;
        if rlen < rta_hdr || off + rlen > msg_len {
            break;
        }
        let dptr = base.add(off + rta_hdr);
        let dlen = rlen - rta_hdr;
        match rta.rta_type {
            1 /* NDA_DST */ => {
                if dlen == 16 {
                    let mut a = [0u8; 16];
                    std::ptr::copy_nonoverlapping(dptr, a.as_mut_ptr(), 16);
                    if &a == target_ip6 { found_ip = true; }
                }
            }
            2 /* NDA_LLADDR */ => {
                if dlen == 6 {
                    let mut m = [0u8; 6];
                    std::ptr::copy_nonoverlapping(dptr, m.as_mut_ptr(), 6);
                    mac = Some(m);
                }
            }
            _ => {}
        }
        off += (rlen + 3) & !3;
    }

    if found_ip {
        mac
    } else {
        None
    }
}

/// Decode a 32-char lowercase hex string into 16 bytes (for `/proc/net/ipv6_route`).
pub fn hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(b)
}

/// Request the routing table for a given IP address via RTM_GETROUTE.
/// Returns a tuple of (output_interface_name, next_hop_ip, pmtu).
pub fn nl_get_route(
    ip: std::net::IpAddr,
) -> Option<(Option<String>, Option<std::net::IpAddr>, Option<u16>)> {
    use std::os::unix::io::RawFd;
    unsafe {
        let fd: RawFd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE as libc::c_int,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        ) < 0
        {
            return None;
        }

        #[repr(C)]
        struct NlMsgRtMsg {
            nlh: libc::nlmsghdr,
            rtm_family: u8,
            rtm_dst_len: u8,
            rtm_src_len: u8,
            rtm_tos: u8,
            rtm_table: u8,
            rtm_protocol: u8,
            rtm_scope: u8,
            rtm_type: u8,
            rtm_flags: u32,
        }

        #[repr(C)]
        struct Rtattr {
            rta_len: u16,
            rta_type: u16,
        }

        let is_v4 = matches!(ip, std::net::IpAddr::V4(_));
        let payload_len: u16 = if is_v4 { 4 } else { 16 };
        let rta_full_len = (std::mem::size_of::<Rtattr>() as u16 + payload_len + 3) & !3;

        let mut req: NlMsgRtMsg = std::mem::zeroed();
        req.nlh.nlmsg_len = std::mem::size_of::<NlMsgRtMsg>() as u32 + rta_full_len as u32;
        req.nlh.nlmsg_type = libc::RTM_GETROUTE;
        req.nlh.nlmsg_flags = libc::NLM_F_REQUEST as u16;
        req.nlh.nlmsg_seq = 1;
        req.rtm_family = if is_v4 {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        };
        req.rtm_dst_len = if is_v4 { 32 } else { 128 };

        let mut buf = [0u8; 8192];
        std::ptr::copy_nonoverlapping(
            &req as *const _ as *const u8,
            buf.as_mut_ptr(),
            std::mem::size_of::<NlMsgRtMsg>(),
        );

        let rta = buf.as_mut_ptr().add(std::mem::size_of::<NlMsgRtMsg>()) as *mut Rtattr;
        (*rta).rta_len = std::mem::size_of::<Rtattr>() as u16 + payload_len;
        (*rta).rta_type = 1; // RTA_DST

        match ip {
            std::net::IpAddr::V4(v4) => std::ptr::copy_nonoverlapping(
                v4.octets().as_ptr(),
                buf.as_mut_ptr()
                    .add(std::mem::size_of::<NlMsgRtMsg>() + std::mem::size_of::<Rtattr>()),
                4,
            ),
            std::net::IpAddr::V6(v6) => std::ptr::copy_nonoverlapping(
                v6.octets().as_ptr(),
                buf.as_mut_ptr()
                    .add(std::mem::size_of::<NlMsgRtMsg>() + std::mem::size_of::<Rtattr>()),
                16,
            ),
        }

        if libc::send(fd, buf.as_ptr() as *const _, req.nlh.nlmsg_len as usize, 0) < 0 {
            return None;
        }

        let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n <= 0 {
            return None;
        }

        let mut dev: Option<String> = None;
        let mut via: Option<std::net::IpAddr> = None;

        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::nlmsghdr>() <= n as usize {
            let nlh = &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr);
            let msg_len = nlh.nlmsg_len as usize;
            if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > n as usize {
                break;
            }
            if nlh.nlmsg_type == libc::NLMSG_DONE as u16
                || nlh.nlmsg_type == libc::NLMSG_ERROR as u16
            {
                break;
            }

            if nlh.nlmsg_type == libc::RTM_NEWROUTE {
                let mut attr_offset = offset + std::mem::size_of::<NlMsgRtMsg>();
                while attr_offset + std::mem::size_of::<Rtattr>() <= offset + msg_len {
                    let rta = &*(buf.as_ptr().add(attr_offset) as *const Rtattr);
                    let rta_len = rta.rta_len as usize;
                    if rta_len < std::mem::size_of::<Rtattr>()
                        || attr_offset + rta_len > offset + msg_len
                    {
                        break;
                    }

                    let data_ptr = buf
                        .as_ptr()
                        .add(attr_offset + std::mem::size_of::<Rtattr>());
                    let dlen = rta_len - std::mem::size_of::<Rtattr>();
                    match rta.rta_type {
                        4 /* RTA_OIF */ => {
                            if dlen == 4 {
                                let mut ifindex = [0u8; 4];
                                std::ptr::copy_nonoverlapping(data_ptr, ifindex.as_mut_ptr(), 4);
                                let idx = i32::from_ne_bytes(ifindex);
                                let mut ifname = [0 as libc::c_char; libc::IF_NAMESIZE];
                                if !libc::if_indextoname(idx as u32, ifname.as_mut_ptr()).is_null() {
                                    dev = Some(std::ffi::CStr::from_ptr(ifname.as_ptr()).to_string_lossy().into_owned());
                                }
                            }
                        }
                        5 /* RTA_GATEWAY */ => {
                            if is_v4 && dlen == 4 {
                                let mut octets = [0u8; 4];
                                std::ptr::copy_nonoverlapping(data_ptr, octets.as_mut_ptr(), 4);
                                via = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)));
                            } else if !is_v4 && dlen == 16 {
                                let mut octets = [0u8; 16];
                                std::ptr::copy_nonoverlapping(data_ptr, octets.as_mut_ptr(), 16);
                                via = Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                            }
                        }
                        _ => {}
                    }
                    attr_offset += (rta_len + 3) & !3;
                }
                return Some((dev, via, None));
            }
            offset += (msg_len + 3) & !3;
        }
        None
    }
}

/// Send a raw ICMPv6 Neighbor Solicitation directly via AF_PACKET and wait for a Neighbor Advertisement.
/// Bypasses the kernel neighbor cache. Returns the extracted MAC address on success.
pub fn ndp_request_reply(target_ip: std::net::Ipv6Addr, ifname: &str) -> Option<[u8; 6]> {
    use std::os::unix::io::AsRawFd;

    let ifindex = match get_ifindex(ifname) {
        Ok(i) => i,
        Err(_) => return None,
    };

    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (0x86DDu16).to_be() as i32,
        );
        if fd < 0 {
            return None;
        }
        let _guard = FdGuard(fd);

        let mut bind_sll: libc::sockaddr_ll = std::mem::zeroed();
        bind_sll.sll_family = libc::AF_PACKET as u16;
        bind_sll.sll_protocol = (0x86DDu16).to_be();
        bind_sll.sll_ifindex = ifindex;
        if libc::bind(
            fd,
            &bind_sll as *const _ as *const _,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        ) < 0
        {
            return None;
        }

        // Get MAC
        let mut ifreq: libc::ifreq = std::mem::zeroed();
        fill_ifname(&mut ifreq.ifr_name, ifname);
        if libc::ioctl(fd, 0x8927 /* SIOCGIFHWADDR */, &mut ifreq) < 0 {
            return None;
        }
        let sd = ifreq.ifr_ifru.ifru_hwaddr.sa_data;
        let mut src_mac = [0u8; 6];
        for i in 0..6 {
            src_mac[i] = sd[i] as u8;
        }

        // Get our Source IP
        let mut sender_ip = [0u8; 16];
        if let Ok(s) = std::net::UdpSocket::bind("[::]:0") {
            if let Ok(c) = std::ffi::CString::new(ifname) {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    c.as_ptr() as *const _,
                    (ifname.len() + 1) as _,
                );
            }
            if s.connect(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                target_ip, 1, 0, 0,
            )))
            .is_ok()
            {
                if let Ok(std::net::SocketAddr::V6(addr)) = s.local_addr() {
                    sender_ip = addr.ip().octets();
                }
            }
        }

        let target_octets = target_ip.octets();
        let dst_mac = [
            0x33,
            0x33,
            0xff,
            target_octets[13],
            target_octets[14],
            target_octets[15],
        ];
        let dst_ip = [
            0xff,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0xff,
            target_octets[13],
            target_octets[14],
            target_octets[15],
        ];

        let mut frame = [0u8; 86];
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12..14].copy_from_slice(&[0x86, 0xdd]); // EtherType: IPv6

        frame[14..18].copy_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame[18..20].copy_from_slice(&[0x00, 0x20]); // Payload length: 32 bytes
        frame[20] = 58; // Next header: ICMPv6
        frame[21] = 255; // Hop limit: 255 (mandatory for NDP)
        frame[22..38].copy_from_slice(&sender_ip);
        frame[38..54].copy_from_slice(&dst_ip);

        // ICMPv6 (starts at 54)
        frame[54] = 135; // Type: Neighbor Solicitation
        frame[55] = 0; // Code: 0
        frame[62..78].copy_from_slice(&target_octets);
        frame[78] = 1; // Option: source link-layer
        frame[79] = 1; // Length: 1 (*8 = 8 bytes)
        frame[80..86].copy_from_slice(&src_mac);

        let mut sum = 0u32;
        // Pseudo header
        for i in (0..16).step_by(2) {
            sum += u32::from(u16::from_be_bytes([sender_ip[i], sender_ip[i + 1]]));
        }
        for i in (0..16).step_by(2) {
            sum += u32::from(u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]));
        }
        sum += 32; // Upper layer length
        sum += 58; // Next header

        for i in (54..86).step_by(2) {
            sum += u32::from(u16::from_be_bytes([frame[i], frame[i + 1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        let chk = checksum.to_be_bytes();
        frame[56] = chk[0];
        frame[57] = chk[1];

        // Send
        libc::send(fd, frame.as_ptr() as *const _, frame.len(), 0);

        // Poll for reply
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let end_time = std::time::Instant::now() + std::time::Duration::from_millis(150);

        let mut buf = [0u8; 1500];
        loop {
            let timeout = end_time
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as i32;
            if timeout <= 0 {
                break;
            }
            if libc::poll(&mut pfd, 1, timeout) <= 0 {
                continue;
            }

            let n = libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            );
            if n < 86 {
                continue;
            }

            let eth_type = u16::from_be_bytes([buf[12], buf[13]]);
            if eth_type != 0x86dd {
                continue;
            } // must be ipv6

            // basic checking: NextHeader(20)==58, Type(54)==136 (Neighbor Advertisement)
            if buf[20] == 58 && buf[54] == 136 {
                let target_replied = &buf[62..78];
                if target_replied == target_octets {
                    // Extract MAC from target link-layer option (Type=2)
                    let mut idx = 78;
                    while idx + 1 < n as usize {
                        let opt_type = buf[idx];
                        let opt_len = buf[idx + 1] as usize * 8;
                        if opt_len == 0 || idx + opt_len > n as usize {
                            break;
                        }
                        // Target link-layer address is option type 2
                        if opt_type == 2 && opt_len >= 8 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&buf[idx + 2..idx + 8]);
                            return Some(mac);
                        }
                        idx += opt_len;
                    }
                    // For NA without TLLAO, fallback to src mac from Ethernet
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&buf[6..12]);
                    return Some(mac);
                }
            }
        }
        None
    }
}
