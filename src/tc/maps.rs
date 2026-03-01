//! BPF map definitions shared between Rust and eBPF C code
//!
//! These structures must exactly match `gut_common.h` definitions

use std::net::IpAddr;

pub const MAX_PORTS: usize = 16;
pub const GUT_KEY_SIZE: usize = 32;
pub const GUT_WIRE_HEADER_SIZE: u16 = 0; // payload-only mode: no extra GUT wire header
pub const PMTU_RESERVE_BYTES: u16 = 20;
pub const OUTER_OVERHEAD_IPV4: u16 = GUT_WIRE_HEADER_SIZE + 8 + 20 + PMTU_RESERVE_BYTES;
pub const OUTER_OVERHEAD_IPV6: u16 = GUT_WIRE_HEADER_SIZE + 8 + 40 + PMTU_RESERVE_BYTES;
pub const DEFAULT_INNER_MTU: u16 = 1492;

/// ChaCha round count — compile-time constant, must match BPF CHACHA_ROUNDS.
pub const CHACHA_ROUNDS: u8 = 4;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GutConfig {
    pub key: [u8; GUT_KEY_SIZE],
    pub ports: [u16; MAX_PORTS],
    pub num_ports: u32,
    pub outer_mtu: u16,
    pub inner_mtu_v4: u16,
    pub inner_mtu_v6: u16,
    pub peer_ip: u32,
    pub bind_ip: u32,
    pub egress_ifindex: u32,
    pub tun_ifindex: u32,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub tun_mac: [u8; 6],
    pub offload_flags: u16,
    // --- Precomputed by loader (avoid per-packet key expansion) ---
    pub chacha_init: [u32; 12], // ChaCha state[0..11]: constants(4) + key_words(8)
    pub chacha_rounds: u8,      // ChaCha rounds (2,4,6,...,20). Default: 4
    pub partial_ip_csum: u32,   // Precomputed partial IP header checksum (fixed fields)
    pub default_xdp_action: u8, // XDP action for non-GUT packets: 0=XDP_PASS, 1=XDP_DROP
    pub keepalive_drop_percent: u8, // Keepalive (WG type=4, payload=0) drop probability in %
    pub feistel_rk: [u32; 4],   // Feistel32 round keys (derived from key via ChaCha)
    pub peer_ip6: [u8; 16],     // Peer IPv6 address (network byte order, zero if v4)
    pub bind_ip6: [u8; 16],     // Local bind IPv6 (network byte order, zero if v4)
    pub tun_local_ip4: u32,     // Local veth (gut0) IP — XDP ingress rewrites dst to this
    pub tun_peer_ip4: u32,      // Remote veth peer IP — XDP ingress rewrites src to this
    pub tun_local_ip6: [u8; 16], // Local veth IPv6 (zero if v4 only)
    pub tun_peer_ip6: [u8; 16], // Remote veth peer IPv6 (zero if v4 only)
}

impl GutConfig {
    #[must_use]
    pub fn from_config(key: &[u8; 32], ports: &[u16], peer_ip: IpAddr, outer_mtu: u16) -> Self {
        // Precompute ChaCha init state: constants(4) + key_words(8)
        let chacha_init = compute_chacha_init(key);

        // Derive Feistel32 round keys from ChaCha block
        let feistel_rk = compute_feistel_rk(key, CHACHA_ROUNDS);

        // Extract IPv4/IPv6 addresses
        let (peer_ip4, peer_ip6) = match peer_ip {
            IpAddr::V4(ip) => (u32::from_ne_bytes(ip.octets()), [0u8; 16]),
            IpAddr::V6(ip) => (0u32, ip.octets()),
        };

        let mut cfg = Self {
            key: *key,
            ports: [0u16; MAX_PORTS],
            num_ports: u32::try_from(ports.len()).expect("ports.len() exceeds u32::MAX"),
            outer_mtu,
            inner_mtu_v4: DEFAULT_INNER_MTU,
            inner_mtu_v6: DEFAULT_INNER_MTU,
            peer_ip: peer_ip4,
            bind_ip: 0,
            egress_ifindex: 0,
            tun_ifindex: 0,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            tun_mac: [0u8; 6],
            offload_flags: 0,
            chacha_init,
            chacha_rounds: CHACHA_ROUNDS,
            partial_ip_csum: 0, // computed later in build_gut_config when bind_ip is known
            default_xdp_action: 0, // XDP_PASS by default; overridden by loader from config
            keepalive_drop_percent: 75,
            feistel_rk,
            peer_ip6,
            bind_ip6: [0u8; 16],
            tun_local_ip4: 0,
            tun_peer_ip4: 0,
            tun_local_ip6: [0u8; 16],
            tun_peer_ip6: [0u8; 16],
        };

        for (i, &port) in ports.iter().enumerate().take(MAX_PORTS) {
            cfg.ports[i] = port;
        }

        cfg
    }

    /// Compute partial IP header checksum from fixed fields (saddr, daddr, etc.).
    /// Must be called after bind_ip and peer_ip are set.
    pub fn compute_partial_ip_csum(&mut self) {
        let bind_bytes = self.bind_ip.to_ne_bytes();
        let peer_bytes = self.peer_ip.to_ne_bytes();
        // Sum fixed 16-bit words of IP header (in network/big-endian order):
        //   version+ihl+tos = 0x4500
        //   frag_off (DF)   = 0x4000
        //   ttl(64)+proto(17=UDP) = 0x4011
        //   saddr (2 words), daddr (2 words)
        self.partial_ip_csum = 0x4500u32
            + 0x4000
            + 0x4011
            + ((bind_bytes[0] as u32) << 8 | bind_bytes[1] as u32)
            + ((bind_bytes[2] as u32) << 8 | bind_bytes[3] as u32)
            + ((peer_bytes[0] as u32) << 8 | peer_bytes[1] as u32)
            + ((peer_bytes[2] as u32) << 8 | peer_bytes[3] as u32);
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GutStats {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub bytes_processed: u64,
    pub _reserved_stat: u64, // was mask_fast_count
    pub mask_count: u64,     // was mask_balanced_count; all masking is ChaCha now
    pub cookie_validation_failed: u64,
    pub packets_fragmented: u64,
    pub inner_tcp_seen: u64,
}

/// Offload capability flags — mirrors GUT_FLAG_* in gut_common.h
pub const GUT_FLAG_NEED_L4_CSUM: u16 = 1 << 0;

/// Derive 4 Feistel32 round keys from ChaCha block(counter=0xFFFFFFFE, nonce=0).
/// Domain-separated from data masking (nonce>=1) and ballast (block 99).
fn compute_feistel_rk(key: &[u8; 32], rounds: u8) -> [u32; 4] {
    let ks = crate::proto::mask_balanced::chacha_block(key, 0xFFFFFFFE, 0, rounds);
    [ks[0], ks[1], ks[2], ks[3]]
}

fn compute_chacha_init(key: &[u8; 32]) -> [u32; 12] {
    let mut init = [0u32; 12];
    // "expand 32-byte k" constants
    init[0] = 0x6170_7865;
    init[1] = 0x3320_646e;
    init[2] = 0x7962_2d32;
    init[3] = 0x6b20_6574;
    // Key words (8×u32 LE)
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    init
}

const _: [(); 253] = [(); std::mem::size_of::<GutConfig>()];
const _: [(); 64] = [(); std::mem::size_of::<GutStats>()];

impl GutStats {
    #[must_use]
    pub fn aggregate(per_cpu_stats: &[GutStats]) -> Self {
        let mut total = Self::default();
        for stat in per_cpu_stats {
            total.packets_processed += stat.packets_processed;
            total.packets_dropped += stat.packets_dropped;
            total.bytes_processed += stat.bytes_processed;
            total._reserved_stat += stat._reserved_stat;
            total.mask_count += stat.mask_count;
            total.cookie_validation_failed += stat.cookie_validation_failed;
            total.packets_fragmented += stat.packets_fragmented;
            total.inner_tcp_seen += stat.inner_tcp_seen;
        }
        total
    }
}
