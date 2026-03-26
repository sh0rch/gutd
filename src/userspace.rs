use std::collections::HashMap;
use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::feistel::sip_hash32;
use crate::proto::mask_balanced::{chacha_block_fast, chacha_init};

const GUT_QUIC_SHORT_HEADER_SIZE: usize = 16;
const GUT_GOST_HEADER_SIZE: usize = 10;
const GUT_QUIC_LONG_HEADER_SIZE: usize = 1200;
const SOCKET_BUF_SIZE: usize = 4 * 1024 * 1024; // 4 MiB send/recv buffer

/// Lock-free shared SocketAddr (IPv4 + IPv6) using AtomicU32.
/// Works on 32-bit targets (MIPS) where AtomicU64 is unavailable.
/// Write order: ip → port → family (Release); read order: family (Acquire) → port → ip.
struct SharedAddr {
    /// 0 = unset, 4 = IPv4, 6 = IPv6
    family: AtomicU32,
    /// IPv4: [ip, 0, 0, 0]. IPv6: 128-bit address as 4 big-endian words.
    ip: [AtomicU32; 4],
    port: AtomicU32,
}

impl SharedAddr {
    fn new() -> Self {
        Self {
            family: AtomicU32::new(0),
            ip: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            port: AtomicU32::new(0),
        }
    }

    fn store(&self, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => {
                self.ip[0].store(u32::from_be_bytes(v4.ip().octets()), Ordering::Relaxed);
                self.ip[1].store(0, Ordering::Relaxed);
                self.ip[2].store(0, Ordering::Relaxed);
                self.ip[3].store(0, Ordering::Relaxed);
                self.port.store(v4.port() as u32, Ordering::Relaxed);
                self.family.store(4, Ordering::Release);
            }
            SocketAddr::V6(v6) => {
                let o = v6.ip().octets();
                self.ip[0].store(
                    u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
                    Ordering::Relaxed,
                );
                self.ip[1].store(
                    u32::from_be_bytes([o[4], o[5], o[6], o[7]]),
                    Ordering::Relaxed,
                );
                self.ip[2].store(
                    u32::from_be_bytes([o[8], o[9], o[10], o[11]]),
                    Ordering::Relaxed,
                );
                self.ip[3].store(
                    u32::from_be_bytes([o[12], o[13], o[14], o[15]]),
                    Ordering::Relaxed,
                );
                self.port.store(v6.port() as u32, Ordering::Relaxed);
                self.family.store(6, Ordering::Release);
            }
        }
    }

    fn load(&self) -> Option<SocketAddr> {
        let fam = self.family.load(Ordering::Acquire);
        if fam == 0 {
            return None;
        }
        let port = self.port.load(Ordering::Relaxed) as u16;
        if fam == 4 {
            let o = self.ip[0].load(Ordering::Relaxed).to_be_bytes();
            Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])),
                port,
            ))
        } else {
            let mut octets = [0u8; 16];
            octets[0..4].copy_from_slice(&self.ip[0].load(Ordering::Relaxed).to_be_bytes());
            octets[4..8].copy_from_slice(&self.ip[1].load(Ordering::Relaxed).to_be_bytes());
            octets[8..12].copy_from_slice(&self.ip[2].load(Ordering::Relaxed).to_be_bytes());
            octets[12..16].copy_from_slice(&self.ip[3].load(Ordering::Relaxed).to_be_bytes());
            Some(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                port,
            ))
        }
    }

    /// XOR-folded fingerprint for compare-and-store optimization.
    fn load_raw(&self) -> u64 {
        let w0 = self.ip[0].load(Ordering::Relaxed) as u64;
        let w1 = self.ip[1].load(Ordering::Relaxed) as u64;
        let w2 = self.ip[2].load(Ordering::Relaxed) as u64;
        let w3 = self.ip[3].load(Ordering::Relaxed) as u64;
        let port = self.port.load(Ordering::Relaxed) as u64;
        ((w0 ^ w2) << 32 | (w1 ^ w3)) ^ port
    }

    /// Compute fingerprint for an address (matches load_raw layout).
    fn addr_fingerprint(&self, addr: SocketAddr) -> u64 {
        match addr {
            SocketAddr::V4(v4) => {
                let ip = u32::from_be_bytes(v4.ip().octets()) as u64;
                (ip << 32) ^ v4.port() as u64
            }
            SocketAddr::V6(v6) => {
                let o = v6.ip().octets();
                let w0 = u32::from_be_bytes([o[0], o[1], o[2], o[3]]) as u64;
                let w1 = u32::from_be_bytes([o[4], o[5], o[6], o[7]]) as u64;
                let w2 = u32::from_be_bytes([o[8], o[9], o[10], o[11]]) as u64;
                let w3 = u32::from_be_bytes([o[12], o[13], o[14], o[15]]) as u64;
                ((w0 ^ w2) << 32 | (w1 ^ w3)) ^ v6.port() as u64
            }
        }
    }
}

/// Best-effort SO_SNDBUF + SO_RCVBUF increase.
fn tune_udp_buffers(_sock: &UdpSocket) {
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = _sock.as_raw_fd();
        unsafe {
            let size = SOCKET_BUF_SIZE as libc::c_int;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(target_family = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        const SOL_SOCKET_WIN: i32 = 0xFFFF;
        const SO_SNDBUF_WIN: i32 = 0x1001;
        const SO_RCVBUF_WIN: i32 = 0x1002;
        extern "system" {
            fn setsockopt(
                s: usize,
                level: i32,
                optname: i32,
                optval: *const u8,
                optlen: i32,
            ) -> i32;
        }
        let fd = _sock.as_raw_socket() as usize;
        let size = SOCKET_BUF_SIZE as i32;
        unsafe {
            setsockopt(
                fd,
                SOL_SOCKET_WIN,
                SO_SNDBUF_WIN,
                &size as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
            setsockopt(
                fd,
                SOL_SOCKET_WIN,
                SO_RCVBUF_WIN,
                &size as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}

fn disable_df(_sock: &UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = _sock.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(target_family = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        const IPPROTO_IP: i32 = 0;
        const IPPROTO_IPV6: i32 = 41;
        const IP_DONTFRAGMENT: i32 = 14;
        const IPV6_DONTFRAG: i32 = 14;
        extern "system" {
            fn setsockopt(
                s: usize,
                level: i32,
                optname: i32,
                optval: *const u8,
                optlen: i32,
            ) -> i32;
        }
        let fd = _sock.as_raw_socket() as usize;
        let val: i32 = 0; // FALSE
        unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_DONTFRAGMENT,
                &val as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
            setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_DONTFRAG,
                &val as *const i32 as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}

fn wg_nonce32(wg: &[u8]) -> u32 {
    if wg.len() < 32 {
        return 0;
    }
    let n0 = u32::from_le_bytes(wg[16..20].try_into().unwrap());
    let n1 = u32::from_le_bytes(wg[20..24].try_into().unwrap());
    let n2 = u32::from_le_bytes(wg[24..28].try_into().unwrap());
    let n3 = u32::from_le_bytes(wg[28..32].try_into().unwrap());
    n0 ^ n1 ^ n2 ^ n3
}

fn xor16(p: &mut [u8], k: &[u8]) {
    for i in 0..16 {
        p[i] ^= k[i];
    }
}

#[allow(clippy::too_many_arguments)]
pub fn obfs_encap(
    buf: &mut [u8],
    orig_len: usize,
    key: &[u32; 12],
    rounds: u8,
    is_server: bool,
    wg_sport: u16,
    wg_dport: u16,
    obfs: crate::config::ObfsMode,
    sip_domain: &str,
) -> Option<(usize, u32)> {
    if orig_len < 16 {
        return None;
    }

    let wg_type = buf[0] & 0x1F;
    let quic_hdr_len = if obfs != crate::config::ObfsMode::Quic {
        GUT_GOST_HEADER_SIZE
    } else if wg_type == 3 {
        // Cookie Reply → QUIC Retry long header (must never be dropped)
        GUT_QUIC_LONG_HEADER_SIZE
    } else if is_server {
        GUT_QUIC_SHORT_HEADER_SIZE
    } else if wg_type == 1 {
        // Client handshake init → QUIC Initial long header
        GUT_QUIC_LONG_HEADER_SIZE
    } else {
        GUT_QUIC_SHORT_HEADER_SIZE
    };

    let mut wg_idx = 0u32;
    if wg_type == 2 && orig_len >= 12 {
        wg_idx = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    } else if orig_len >= 8 {
        wg_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    }

    // NONCE: Must be computed from MASKABLE part of WG payload,
    // and must be identical on both sides.
    // We compute it on the PLAIN payload here.
    let nonce = wg_nonce32(&buf[..orig_len]);

    // Shift payload forward to make room for QUIC header
    buf.copy_within(0..orig_len, quic_hdr_len);

    // Masking: We mask the WG payload IN-PLACE after it's moved
    let ks47 = chacha_block_fast(key, 47, nonce, rounds);
    let ks47_b: [u8; 64] = unsafe { std::mem::transmute(ks47) };

    let wg_off = quic_hdr_len;
    xor16(&mut buf[wg_off..wg_off + 16], &ks47_b[0..16]);

    if wg_type == 1 && orig_len >= 148 {
        xor16(&mut buf[wg_off + 132..wg_off + 148], &ks47_b[16..32]);
    } else if wg_type == 2 && orig_len >= 92 {
        xor16(&mut buf[wg_off + 76..wg_off + 92], &ks47_b[16..32]);
    }

    // Encrypt ports
    let plain_ports = ((wg_sport as u32) << 16) | (wg_dport as u32);
    let enc_ports = plain_ports ^ ks47[11];

    // PPn
    let ppn = ks47[10];

    // Compute Padding/Ballast
    let ks69 = chacha_block_fast(key, 69, nonce, rounds);
    let pad_block: [u8; 64] = unsafe { std::mem::transmute(ks69) };

    let mut pad_len = 0;
    if obfs == crate::config::ObfsMode::Gost {
        // GOST: 16-byte alignment for small packets (< 256 bytes) only
        if orig_len < 256 {
            let base_udp_size = 8 + quic_hdr_len + orig_len;
            let remainder = base_udp_size % 16;
            if remainder != 0 {
                pad_len = 16 - remainder;
            }
        }
    } else if obfs == crate::config::ObfsMode::Quic && orig_len >= 220 {
        // QUIC large packets: no padding — real QUIC has uniform MTU-sized data
        pad_len = 0;
    } else if (obfs == crate::config::ObfsMode::Syslog || obfs == crate::config::ObfsMode::Sip)
        && orig_len >= 220
    {
        // B64 large packets: small random padding [1..15]
        let raw = std::cmp::min((pad_block[63] & 0x0F) as usize, 14);
        pad_len = raw + 1;
    } else if obfs == crate::config::ObfsMode::Quic {
        // QUIC small packets: [1..64]
        let raw = (pad_block[63] & 0x3F) as usize;
        pad_len = raw + 1;
    } else {
        // B64 (syslog/sip) small packets: [1..32]
        let raw = (pad_block[63] & 0x1F) as usize;
        pad_len = raw + 1;
    }

    if pad_len > 0 {
        let raw = (pad_len - 1) as u8;
        // copy padding to the end
        for i in 0..pad_len {
            buf[wg_off + orig_len + i] = pad_block[i & 0x3F];
        }
        buf[quic_hdr_len - 1] = 0x40 | raw;
    } else {
        buf[quic_hdr_len - 1] = 0x00;
    }

    let dcid = ks47[9];

    if quic_hdr_len == GUT_GOST_HEADER_SIZE {
        write_gost_header(buf, ppn, enc_ports, pad_len);
    } else if quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        write_quic_short_header(buf, dcid, ppn, enc_ports, pad_len);
    } else {
        write_quic_long_header(
            buf, wg_type, wg_idx, dcid, ppn, enc_ports, pad_len, orig_len, wg_off, &pad_block,
            sip_domain,
        );
    }

    Some((quic_hdr_len + orig_len + pad_len, dcid))
}
/// Verify DCID and PPN in QUIC header match the crypto-derived values.
/// Returns `true` if the packet is authentic GUT traffic.
/// In gost mode, unmasking is applied to the first 6 bytes in-place on success;
/// on failure, the original bytes are restored.
#[inline]
fn write_gost_header(buf: &mut [u8], ppn: u32, enc_ports: u32, pad_len: usize) {
    buf[0..4].copy_from_slice(&ppn.to_le_bytes());
    buf[4..8].copy_from_slice(&enc_ports.to_le_bytes());
    buf[8] = 0x00;
    buf[9] = if pad_len > 0 {
        0x40 | ((pad_len as u8 - 1) & 0x3F)
    } else {
        0
    };
}

#[inline]
fn write_quic_short_header(buf: &mut [u8], dcid: u32, ppn: u32, enc_ports: u32, pad_len: usize) {
    buf[0] = 0x40; // Short
    buf[1..5].copy_from_slice(&dcid.to_le_bytes());
    buf[5] = 0x01; // DCID length byte in standard QUIC header
    buf[6..10].copy_from_slice(&ppn.to_le_bytes());
    buf[10..14].copy_from_slice(&enc_ports.to_le_bytes());
    buf[14] = 0x00; // Reserved
    buf[15] = if pad_len > 0 {
        0x40 | ((pad_len as u8 - 1) & 0x3F)
    } else {
        0
    };
}

#[inline]
#[allow(clippy::too_many_arguments)]
fn write_quic_long_header(
    buf: &mut [u8],
    wg_type: u8,
    wg_idx: u32,
    dcid: u32,
    ppn: u32,
    enc_ports: u32,
    pad_len: usize,
    orig_len: usize,
    wg_off: usize,
    pad_block: &[u8; 64],
    sip_domain: &str,
) {
    // 0xC3 = QUIC Initial (client Type 1) with 4-byte PN, 0xF0 = QUIC Retry (Cookie Reply Type 3)
    buf[0] = if wg_type == 3 { 0xF0 } else { 0xC3 };
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x01; // QUIC v1

    // Use the middle/end part of the (already masked) WG payload as entropy for the Long Header.
    // This avoids double-encryption and looks more random to DPI.
    let mut entropy_source = [0u8; 32];
    if orig_len >= 64 {
        entropy_source.copy_from_slice(&buf[wg_off + 32..wg_off + 64]);
    } else {
        entropy_source.copy_from_slice(&pad_block[0..32]);
    };

    let t_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    let time_gost = t_ns.wrapping_mul(0x9E3779B9u32).rotate_left(13);
    let gost_b = time_gost.to_le_bytes();

    let head = (GUT_QUIC_LONG_HEADER_SIZE / 2).min(200);
    for i in 1..head {
        buf[i] = entropy_source[i & 31] ^ gost_b[i & 3];
    }
    // Fill the rest with combination of entropy and pad_block
    for i in head..(GUT_QUIC_LONG_HEADER_SIZE - 1) {
        buf[i] = pad_block[(i * 13) & 0x3F] ^ entropy_source[i & 31] ^ gost_b[(i >> 2) & 3];
    }

    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x01; // QUIC v1

    let dcid2 = (wg_idx ^ 0xDEADBEEF).wrapping_mul(0x9E3779B9u32);
    let scid = (wg_idx ^ 0xCAFEBABE).wrapping_mul(0x6C62272Eu32);
    let scid2 = sip_hash32(
        wg_idx ^ 0x12345678,
        &[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5],
    );

    let mut actual_dcid = [0u8; 8];
    actual_dcid[0..4].copy_from_slice(&dcid.to_le_bytes());
    actual_dcid[4..8].copy_from_slice(&dcid2.to_le_bytes());

    buf[5] = 0x08; // DCID length 8
    buf[6..14].copy_from_slice(&actual_dcid);
    buf[14] = 0x08; // SCID length 8
    buf[15..19].copy_from_slice(&scid.to_le_bytes());
    buf[19..23].copy_from_slice(&scid2.to_le_bytes());

    buf[23] = 0x04; // Token length 4
    buf[24..28].copy_from_slice(&enc_ports.to_le_bytes()); // Hide enc_ports in Token

    // --- Build CRYPTO frame with TLS 1.3 ClientHello containing SNI ---
    let initial_secret = crate::proto::quic::derive_quic_initial_secret(&actual_dcid);
    let client_secret = crate::proto::quic::derive_client_initial_secret(&initial_secret);
    let (q_key, q_iv, q_hp) = crate::proto::quic::derive_quic_keys(&client_secret);

    let sni_pos = 34; // Immediately after PPN (pn_offset + 4 = 30 + 4)
    let mut crypto_frame = [0u8; 128];

    let domain_bytes = sip_domain.as_bytes();
    let domain_len = domain_bytes.len().min(32);

    // SNI extension: type(2) + ext_len(2) + list_len(2) + name_type(1) + name_len(2) + name
    let sni_ext_data_len = if domain_len > 0 { domain_len + 5 } else { 0 };
    let sni_ext_total = if domain_len > 0 {
        sni_ext_data_len + 4
    } else {
        0
    };
    // ALPN extension with "h3": type(2) + len(2) + list_len(2) + proto_len(1) + "h3"(2) = 9
    let alpn_ext_total = 9;
    // supported_versions: type(2) + len(2) + list_len(1) + version(2) = 7
    let sv_ext_total = 7;
    let extensions_len = sni_ext_total + alpn_ext_total + sv_ext_total;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len; // 43 + extensions_len
    let handshake_len = ch_body_len + 4; // +type(1)+length(3)
    let crypto_data_len = handshake_len;
    let crypto_frame_total = 4 + crypto_data_len; // CRYPTO frame header(4) + data

    // CRYPTO frame header
    crypto_frame[0] = 0x06; // Type: CRYPTO
    crypto_frame[1] = 0x00; // Offset 0
    crypto_frame[2] = 0x40 | ((crypto_data_len >> 8) & 0x3F) as u8;
    crypto_frame[3] = (crypto_data_len & 0xFF) as u8;
    // Handshake: ClientHello
    crypto_frame[4] = 0x01;
    crypto_frame[5] = 0;
    crypto_frame[6] = ((ch_body_len >> 8) & 0xFF) as u8;
    crypto_frame[7] = (ch_body_len & 0xFF) as u8;
    // Legacy version 0x0303
    crypto_frame[8] = 0x03;
    crypto_frame[9] = 0x03;
    // Random: 32 bytes [10..42]
    for i in 0..32 {
        crypto_frame[10 + i] = entropy_source[i & 31];
    }
    // Session ID length = 0
    crypto_frame[42] = 0x00;
    // Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301)
    crypto_frame[43] = 0x00;
    crypto_frame[44] = 0x02;
    crypto_frame[45] = 0x13;
    crypto_frame[46] = 0x01;
    // Compression Methods: null
    crypto_frame[47] = 0x01;
    crypto_frame[48] = 0x00;
    // Extensions length
    crypto_frame[49] = ((extensions_len >> 8) & 0xFF) as u8;
    crypto_frame[50] = (extensions_len & 0xFF) as u8;
    // SNI Extension (type 0x0000)
    let mut ext_off = 51;
    if domain_len > 0 {
        crypto_frame[ext_off] = 0x00;
        crypto_frame[ext_off + 1] = 0x00;
        crypto_frame[ext_off + 2] = ((sni_ext_data_len >> 8) & 0xFF) as u8;
        crypto_frame[ext_off + 3] = (sni_ext_data_len & 0xFF) as u8;
        let list_len = domain_len + 3;
        crypto_frame[ext_off + 4] = ((list_len >> 8) & 0xFF) as u8;
        crypto_frame[ext_off + 5] = (list_len & 0xFF) as u8;
        crypto_frame[ext_off + 6] = 0x00; // host_name type
        crypto_frame[ext_off + 7] = ((domain_len >> 8) & 0xFF) as u8;
        crypto_frame[ext_off + 8] = (domain_len & 0xFF) as u8;
        crypto_frame[ext_off + 9..ext_off + 9 + domain_len]
            .copy_from_slice(&domain_bytes[..domain_len]);
        ext_off += sni_ext_total;
    }
    // ALPN Extension (type 0x0010) with "h3"
    crypto_frame[ext_off] = 0x00;
    crypto_frame[ext_off + 1] = 0x10; // ALPN type
    crypto_frame[ext_off + 2] = 0x00;
    crypto_frame[ext_off + 3] = 0x05; // ext data len: list_len(2) + proto_len(1) + "h3"(2)
    crypto_frame[ext_off + 4] = 0x00;
    crypto_frame[ext_off + 5] = 0x03; // ALPN list len: proto_len(1) + "h3"(2)
    crypto_frame[ext_off + 6] = 0x02; // proto string len
    crypto_frame[ext_off + 7] = b'h';
    crypto_frame[ext_off + 8] = b'3';
    ext_off += alpn_ext_total;
    // supported_versions Extension (type 0x002b)
    crypto_frame[ext_off] = 0x00;
    crypto_frame[ext_off + 1] = 0x2b; // supported_versions type
    crypto_frame[ext_off + 2] = 0x00;
    crypto_frame[ext_off + 3] = 0x03; // ext data len: list_len(1) + version(2)
    crypto_frame[ext_off + 4] = 0x02; // list length
    crypto_frame[ext_off + 5] = 0x03;
    crypto_frame[ext_off + 6] = 0x04; // TLS 1.3 = 0x0304

    // Payload Length varint: PN(4) + ciphertext(crypto_frame_total) + GCM_tag(16)
    let quic_payload_len = (4 + crypto_frame_total + 16) as u16;
    buf[28] = 0x40 | ((quic_payload_len >> 8) as u8);
    buf[29] = (quic_payload_len & 0xFF) as u8;

    // AEAD nonce: IV XOR left-padded PPN in big-endian (RFC 9001 §5.3)
    let ppn_be = ppn.to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&q_iv);
    nonce[8] ^= ppn_be[0];
    nonce[9] ^= ppn_be[1];
    nonce[10] ^= ppn_be[2];
    nonce[11] ^= ppn_be[3];

    // AAD = unprotected header [0..30] + PN in big-endian (RFC 9001 §5.3)
    let mut aad = [0u8; 34];
    aad[..30].copy_from_slice(&buf[..30]);
    aad[30..34].copy_from_slice(&ppn_be);

    // AES-128-GCM encrypt
    let rk = crate::crypto::aes128_expand_key(&q_key);
    let mut gcm_tag = [0u8; 16];
    crate::crypto::aes128_gcm_encrypt(
        &rk,
        &nonce,
        &aad,
        &crypto_frame[..crypto_frame_total],
        &mut buf[sni_pos..sni_pos + crypto_frame_total],
        &mut gcm_tag,
    );
    buf[sni_pos + crypto_frame_total..sni_pos + crypto_frame_total + 16].copy_from_slice(&gcm_tag);

    // Header Protection (RFC 9001 §5.4)
    let hp_rk = crate::crypto::aes128_expand_key(&q_hp);
    let mut hp_mask = [0u8; 16];
    crate::crypto::aes128_encrypt_block(
        &hp_rk,
        &buf[sni_pos..sni_pos + 16].try_into().unwrap(),
        &mut hp_mask,
    );

    // Write PPN in big-endian, then mask with HP
    buf[30..34].copy_from_slice(&ppn_be);
    buf[0] ^= hp_mask[0] & 0x0F;
    for i in 0..4 {
        buf[30 + i] ^= hp_mask[1 + i];
    }

    buf[GUT_QUIC_LONG_HEADER_SIZE - 1] = if pad_len > 0 {
        0x40 | ((pad_len as u8 - 1) & 0x3F)
    } else {
        0
    };
}

pub fn obfs_verify(
    buf: &[u8],
    orig_len: usize,
    key: &[u32; 12],
    rounds: u8,
    obfs: crate::config::ObfsMode,
) -> bool {
    if orig_len == 0 {
        return false;
    }
    let first_byte = buf[0];
    let hdr_len = if obfs != crate::config::ObfsMode::Quic {
        GUT_GOST_HEADER_SIZE
    } else if (first_byte & 0xC0) == 0xC0 {
        if buf.len() <= 5 || buf[5] != 0x08 {
            return false;
        }
        GUT_QUIC_LONG_HEADER_SIZE
    } else if (first_byte & 0x40) == 0x40 {
        if buf.len() <= 5 || buf[5] != 0x01 {
            return false;
        }
        GUT_QUIC_SHORT_HEADER_SIZE
    } else {
        return false;
    };

    if orig_len < hdr_len + 32 {
        return false;
    }

    let pad_byte = buf[hdr_len - 1];
    let ballast_len = if (pad_byte & 0x40) != 0 {
        ((pad_byte & 0x3F) as usize) + 1
    } else {
        0
    };

    let wg_off = hdr_len;
    let wg_len = orig_len - hdr_len;
    if ballast_len > wg_len {
        return false;
    }
    let actual_wg_len = wg_len - ballast_len;
    if actual_wg_len < 32 {
        return false;
    }

    let nonce = wg_nonce32(&buf[wg_off..wg_off + actual_wg_len]);
    let ks47 = chacha_block_fast(key, 47, nonce, rounds);
    let expected_ppn = ks47[10];

    if obfs != crate::config::ObfsMode::Quic {
        let pkt_ppn = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        return pkt_ppn == expected_ppn;
    }

    let ks47_b: [u8; 64] = unsafe { std::mem::transmute(ks47) };
    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&buf[wg_off..wg_off + 16]);
    xor16(&mut hdr, &ks47_b[0..16]);

    let wg_type = hdr[0] & 0x1F;
    let _wg_idx = if wg_type == 2 {
        u32::from_le_bytes(hdr[8..12].try_into().unwrap())
    } else {
        u32::from_le_bytes(hdr[4..8].try_into().unwrap())
    };

    let expected_dcid = ks47[9];

    if hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        let pkt_dcid = u32::from_le_bytes(buf[1..5].try_into().unwrap());
        let pkt_ppn = u32::from_le_bytes(buf[6..10].try_into().unwrap());
        pkt_dcid == expected_dcid && pkt_ppn == expected_ppn
    } else {
        let mut actual_dcid = [0u8; 8];
        actual_dcid.copy_from_slice(&buf[6..14]);
        let initial_secret = crate::proto::quic::derive_quic_initial_secret(&actual_dcid);
        let client_secret = crate::proto::quic::derive_client_initial_secret(&initial_secret);
        let (_q_key, _q_iv, q_hp) = crate::proto::quic::derive_quic_keys(&client_secret);

        let hp_rk = crate::crypto::aes128_expand_key(&q_hp);
        let mut hp_mask = [0u8; 16];
        let sni_pos = 34; // Sample starts directly after PPN
        crate::crypto::aes128_encrypt_block(
            &hp_rk,
            &buf[sni_pos..sni_pos + 16].try_into().unwrap(),
            &mut hp_mask,
        );

        let fb_unmasked = buf[0] ^ (hp_mask[0] & 0x0F);
        if (fb_unmasked & 0x80) == 0 {
            return false;
        }

        // Use wrapping logic or direct bit logic instead of mutating buf!
        // PPN is stored in big-endian (RFC 9000 §17.1), so read as BE
        let pkt_ppn = u32::from_be_bytes(buf[30..34].try_into().unwrap())
            ^ u32::from_be_bytes(hp_mask[1..5].try_into().unwrap());
        let pkt_dcid = u32::from_le_bytes(buf[6..10].try_into().unwrap());

        pkt_dcid == expected_dcid && pkt_ppn == expected_ppn
    }
}

pub fn obfs_decap(
    buf: &mut [u8],
    orig_len: usize,
    key: &[u32; 12],
    rounds: u8,
    obfs: crate::config::ObfsMode,
) -> Option<(usize, u16, u16)> {
    if orig_len == 0 {
        return None;
    }
    let hdr_len = if obfs != crate::config::ObfsMode::Quic {
        GUT_GOST_HEADER_SIZE
    } else {
        let first_byte = buf[0];
        if (first_byte & 0x80) == 0x80 {
            GUT_QUIC_LONG_HEADER_SIZE
        } else if (first_byte & 0x40) == 0x40 {
            GUT_QUIC_SHORT_HEADER_SIZE
        } else {
            return None;
        }
    };

    if orig_len < hdr_len + 16 {
        return None;
    }

    let pad_byte = buf[hdr_len - 1];
    let ballast_len = if (pad_byte & 0x40) != 0 {
        ((pad_byte & 0x3F) as usize) + 1
    } else {
        0
    };

    let wg_off = hdr_len;
    let wg_len = orig_len - hdr_len;
    if ballast_len > wg_len {
        return None;
    }
    let actual_wg_len = wg_len - ballast_len;

    let enc_ports = if hdr_len == GUT_GOST_HEADER_SIZE {
        u32::from_le_bytes(buf[4..8].try_into().unwrap())
    } else if hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        u32::from_le_bytes(buf[10..14].try_into().unwrap())
    } else {
        u32::from_le_bytes(buf[24..28].try_into().unwrap()) // Ports hidden in Token in Long Header
    };

    let nonce = wg_nonce32(&buf[wg_off..wg_off + actual_wg_len]);
    let ks47 = chacha_block_fast(key, 47, nonce, rounds);
    let ks47_b: [u8; 64] = unsafe { std::mem::transmute(ks47) };

    let plain_ports = enc_ports ^ ks47[11];
    let wg_sport = (plain_ports >> 16) as u16;
    let wg_dport = (plain_ports & 0xFFFF) as u16;

    xor16(&mut buf[wg_off..wg_off + 16], &ks47_b[0..16]);
    let wg_type = buf[wg_off] & 0x1F;

    if wg_type == 1 && actual_wg_len >= 148 {
        xor16(&mut buf[wg_off + 132..wg_off + 148], &ks47_b[16..32]);
    } else if wg_type == 2 && actual_wg_len >= 92 {
        xor16(&mut buf[wg_off + 76..wg_off + 92], &ks47_b[16..32]);
    }

    buf.copy_within(wg_off..wg_off + actual_wg_len, 0);

    Some((actual_wg_len, wg_sport, wg_dport))
}

fn generate_quic_version_negotiation(buf: &[u8], size: usize, out: &mut [u8; 64]) -> Option<usize> {
    if size < 14 {
        return None;
    }
    let fb = buf[0];
    if (fb & 0x80) == 0 {
        return None; // Not a Long Header
    }

    let version = u32::from_be_bytes(buf[1..5].try_into().unwrap());
    if version == 0 || version == 0x6b3343cf {
        // VN packet itself or our native gutd version, do not respond with VN
        return None;
    }

    let dcid_len = buf[5] as usize;
    if 6 + dcid_len >= size {
        return None;
    }
    let dcid = &buf[6..6 + dcid_len];

    let scid_len = buf[6 + dcid_len] as usize;
    if 6 + dcid_len + 1 + scid_len > size {
        return None;
    }

    // RFC 9000 Version Negotiation restricts SCID to 255 bytes max technically,
    // but QUIC Initial enforces smaller lengths typically.
    let scid = &buf[6 + dcid_len + 1..6 + dcid_len + 1 + scid_len];

    // Capacity = 1 (header) + 4 (version 0) + 1 (dcid_len) + scid_len + 1 (scid_len) + dcid_len + 8 (supported versions)
    let total_len = 1 + 4 + 1 + scid.len() + 1 + dcid.len() + 8;
    if total_len > out.len() {
        return None;
    }
    let mut pos = 0;

    // Header Form (1) = 1, Fixed Bit (1) = 1, Random Unused (6 bits)
    let mut rand_bits = 0x0A;
    if !dcid.is_empty() {
        rand_bits = dcid[0] & 0x3F;
    }
    out[pos] = 0x80 | 0x40 | rand_bits;
    pos += 1;

    // Version = 0
    out[pos..pos + 4].copy_from_slice(&[0, 0, 0, 0]);
    pos += 4;

    // DCID Length is length of client's SCID
    out[pos] = scid.len() as u8;
    pos += 1;
    out[pos..pos + scid.len()].copy_from_slice(scid);
    pos += scid.len();

    // SCID Length is length of client's DCID
    out[pos] = dcid.len() as u8;
    pos += 1;
    out[pos..pos + dcid.len()].copy_from_slice(dcid);
    pos += dcid.len();

    // Supported Versions
    // Advertise our internal QUIC version first
    out[pos..pos + 4].copy_from_slice(&[0x6b, 0x33, 0x43, 0xcf]);
    pos += 4;
    // Advertise standard QUIC v1
    out[pos..pos + 4].copy_from_slice(&[0, 0, 0, 1]);
    pos += 4;

    Some(pos)
}

pub fn run(config: &crate::config::Config) -> crate::Result<()> {
    if config.peers.is_empty() {
        return Err("No peers configured in gutd.conf".into());
    }

    let peer = &config.peers[0];
    let key = peer.key;
    let key_init = chacha_init(&key);
    let rounds: u8 = 4;
    // auth_key: first 4 key words (key[0..16] as u32 LE) — same as BPF chacha_init[4..8]
    let auth_key: [u32; 4] = key_init[4..8].try_into().unwrap();

    let is_server = peer.responder;
    let obfs = match std::env::var("GUTD_OBFS").as_deref() {
        Ok("syslog") => crate::config::ObfsMode::Syslog,
        Ok("quic") => crate::config::ObfsMode::Quic,
        Ok("gost") | Ok("noise") => crate::config::ObfsMode::Gost,
        Ok(_) => peer.obfs,
        Err(_) => peer.obfs,
    };

    println!(
        "Starting gutd-userspace proxy (dual-thread). is_server={} obfs={:?}",
        is_server, obfs
    );

    let wg_host_str = env::var("GUTD_WG_HOST").unwrap_or_else(|_| peer.wg_host.clone());
    let wg_addr: SocketAddr = wg_host_str.parse()?;
    let wg_port: u16 = wg_addr.port();

    // Optional override for where to send egress traffic
    let peer_ip_str = env::var("GUTD_PEER_IP").unwrap_or_else(|_| peer.peer_ip.to_string());
    let dynamic_peer = peer.dynamic_peer
        || peer_ip_str.eq_ignore_ascii_case("dynamic")
        || peer_ip_str == "0.0.0.0";
    let peer_port = peer.ports.first().copied().unwrap_or(41000);
    let remote_peer_addr: Option<SocketAddr> = if dynamic_peer {
        None
    } else {
        Some(format!("{}:{}", peer_ip_str, peer_port).parse()?)
    };

    // ext_sockets: GUT traffic to/from remote peer (bound to all configured ports).
    let mut ext_sockets = Vec::new();
    for &port in &peer.ports {
        let ext_addr = SocketAddr::new(peer.bind_ip, port);
        let ext_socket = Arc::new(UdpSocket::bind(ext_addr)?);
        tune_udp_buffers(&ext_socket);
        disable_df(&ext_socket);
        println!("Listening (ext) on {}", ext_addr);
        ext_sockets.push(ext_socket);
    }

    // local_socket: WG-facing socket.
    // Client: binds to wg_addr (WG Endpoint = wg_addr).
    // Server: ephemeral port — WG daemon already owns wg_addr.
    let local_bind: SocketAddr = if !is_server {
        wg_addr
    } else {
        SocketAddr::new(peer.bind_ip, peer.bind_port)
    };
    let local_socket = Arc::new(UdpSocket::bind(local_bind)?);
    tune_udp_buffers(&local_socket);
    disable_df(&local_socket);
    println!("Local WG-facing socket on {}", local_bind);

    // Lock-free shared WG peer address (client mode: egress writes, ingress reads)
    let shared_wg_peer = Arc::new(SharedAddr::new());

    // Shared maps for dynamic_peer routing (egress reads client_map, ingress writes it; vice versa for session_map)
    let client_map: Arc<Mutex<HashMap<u32, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let session_map: Arc<Mutex<HashMap<u32, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Per-client gost mode (auto-detected by ingress, read by egress in server mode)
    let client_obfs: Arc<Mutex<HashMap<SocketAddr, crate::config::ObfsMode>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // ── Thread 1: EGRESS (WG → encap → remote peer) ──────────────────
    let egress_exts: Vec<Arc<UdpSocket>> = ext_sockets.iter().map(Arc::clone).collect();
    let egress_local = Arc::clone(&local_socket);
    let egress_wg_peer = Arc::clone(&shared_wg_peer);
    let egress_client_map = Arc::clone(&client_map);
    let egress_session_map = Arc::clone(&session_map);
    let egress_peer = peer.clone();
    let egress_client_obfs = Arc::clone(&client_obfs);
    let egress_handle = std::thread::Builder::new()
        .name("gutd-egress".into())
        .spawn(move || {
            let peer = &egress_peer;
            let mut buf = [0u8; 65536];
            let mut out_buf = [0u8; 65536];
            let mut sip_buf = [0u8; crate::proto::sip::MAX_SIP_HEADER_LEN];

            // NAT keepalive: client sends a minimal QUIC Short Header every 25s of idle
            let ka_interval = std::time::Duration::from_secs(25);
            if !is_server {
                let _ = egress_local.set_read_timeout(Some(ka_interval));
            }
            // Reusable keepalive packet: 0x40 (Short Header) + 15 zero bytes + 0x01 (PING frame)
            let ka_pkt: [u8; 17] = {
                let mut p = [0u8; 17];
                p[0] = 0x40;
                p[16] = 0x01; // QUIC PING frame type
                p
            };

            loop {
                let (size, src) = match egress_local.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Idle timeout → send NAT keepalive
                        if !is_server {
                            if let Some(dest) = remote_peer_addr {
                                let _ = egress_exts[0].send_to(&ka_pkt, dest);
                            }
                        }
                        continue;
                    }
                    Err(_) => continue,
                };

                // Client: always track WG peer address (handles port changes, NAT rebind)
                if !is_server {
                    let new_val = egress_wg_peer.addr_fingerprint(src);
                    if egress_wg_peer.load_raw() != new_val {
                        egress_wg_peer.store(src);
                    }
                }

                let egress_dest = if !dynamic_peer {
                    remote_peer_addr
                } else if size >= 4 {
                    let wg_type = buf[0] & 0x1F;
                    if wg_type == 1 {
                        eprintln!("[gutd] dropping server-initiated Type 1 rekey (dynamic mode)");
                        None
                    } else if wg_type == 2 && size >= 12 {
                        let s_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                        let c_idx = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                        egress_session_map.lock().unwrap().insert(s_idx, c_idx);
                        egress_client_map.lock().unwrap().get(&c_idx).copied()
                    } else if matches!(wg_type, 3 | 4) && size >= 8 {
                        let c_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                        egress_client_map.lock().unwrap().get(&c_idx).copied()
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(dest) = egress_dest {
                    let encap_obfs = if is_server {
                        *egress_client_obfs
                            .lock()
                            .unwrap()
                            .get(&dest)
                            .unwrap_or(&obfs)
                    } else {
                        obfs
                    };

                    let orig_wg_type = buf[0];
                    let orig_wg_size = size;

                    let sip_domain = peer.sip_domain.as_str();
                    if let Some((new_size, dcid)) = obfs_encap(
                        &mut buf,
                        size,
                        &key_init,
                        rounds,
                        is_server,
                        src.port(),
                        wg_port,
                        encap_obfs,
                        sip_domain,
                    ) {
                        let mut final_dest = dest;
                        let mut sock_idx = 0;

                        let final_buf = if encap_obfs == crate::config::ObfsMode::Syslog {
                            let hlen = crate::proto::syslog::write_header(&mut out_buf, sip_domain);
                            let b64_len = crate::proto::base64::encode(
                                &buf[..new_size],
                                &mut out_buf[hlen..],
                            );
                            &out_buf[..hlen + b64_len]
                        } else if encap_obfs == crate::config::ObfsMode::Sip {
                            if orig_wg_type == 4 && orig_wg_size > 32 {
                                // RTP - use DCID from QUIC header as SSRC
                                let ts = wg_nonce32(&buf[..new_size]);
                                let seq = (ts & 0xFFFF) as u16;
                                let ssrc = dcid; // DCID from QUIC = unique session identifier
                                crate::proto::sip::write_rtp_header(&mut out_buf, seq, ts, ssrc);
                                out_buf[crate::proto::sip::RTP_HEADER_LEN
                                    ..crate::proto::sip::RTP_HEADER_LEN + new_size]
                                    .copy_from_slice(&buf[..new_size]);

                                if peer.ports.len() > 1 {
                                    sock_idx = 1 + (ts as usize % (peer.ports.len() - 1));
                                    final_dest.set_port(peer.ports[sock_idx]);
                                }

                                &out_buf[..crate::proto::sip::RTP_HEADER_LEN + new_size]
                            } else {
                                let sip_kind = match orig_wg_type {
                                    1 => crate::proto::sip::SipKind::Register,
                                    2 => crate::proto::sip::SipKind::Response200,
                                    3 => crate::proto::sip::SipKind::Response401,
                                    4 if orig_wg_size == 32 => crate::proto::sip::SipKind::Options,
                                    _ => crate::proto::sip::SipKind::Message,
                                };
                                let b64_len =
                                    if matches!(sip_kind, crate::proto::sip::SipKind::Options) {
                                        0
                                    } else {
                                        crate::proto::base64::encode(
                                            &buf[..new_size],
                                            &mut out_buf[crate::proto::sip::MAX_SIP_HEADER_LEN..],
                                        )
                                    };
                                sip_buf.fill(0);
                                let src_ip_str = src.ip().to_string();
                                let dst_ip_str = dest.ip().to_string();
                                let rtp_port = peer.ports.get(1).copied().unwrap_or(10000);
                                let date_str = crate::tc::maps::format_sip_date_only(
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                );
                                let sip_header_len = crate::proto::sip::write_header(
                                    &mut sip_buf,
                                    sip_kind,
                                    sip_domain,
                                    &src_ip_str,
                                    &dst_ip_str,
                                    src.port(),
                                    dest.port(),
                                    rtp_port,
                                    b64_len,
                                    &auth_key,
                                    &date_str,
                                );
                                out_buf.copy_within(
                                    crate::proto::sip::MAX_SIP_HEADER_LEN
                                        ..crate::proto::sip::MAX_SIP_HEADER_LEN + b64_len,
                                    sip_header_len,
                                );
                                out_buf[..sip_header_len]
                                    .copy_from_slice(&sip_buf[..sip_header_len]);

                                final_dest.set_port(peer.ports[0]);
                                println!("[gutd] sending SIP to port {}", peer.ports[0]);
                                sock_idx = 0;

                                &out_buf[..sip_header_len + b64_len]
                            }
                        } else {
                            &buf[..new_size]
                        };

                        let _ = egress_exts[sock_idx].send_to(final_buf, final_dest);
                    }
                }
            }
        })?;

    // ── Thread 2: INGRESS (remote peer → decap → WG) ─────────────────
    let mut ingress_handles = Vec::new();
    for (port_idx, ext_sock) in ext_sockets.iter().enumerate() {
        let ingress_ext = Arc::clone(ext_sock);
        let ingress_local = Arc::clone(&local_socket);
        let ingress_wg_peer = Arc::clone(&shared_wg_peer);
        let ingress_client_map = Arc::clone(&client_map);
        let ingress_session_map = Arc::clone(&session_map);
        let ingress_client_obfs = Arc::clone(&client_obfs);
        let ingress_peer = peer.clone();

        let ingress_handle = std::thread::Builder::new()
            .name(format!("gutd-ingress-{}", port_idx))
            .spawn(move || {
                let mut buf = [0u8; 65536];
                let mut out_buf = [0u8; 65536];
                let mut sip_resp = [0u8; crate::proto::sip::MAX_SIP_HEADER_LEN];

                loop {
                    let (mut size, src) = match ingress_ext.recv_from(&mut buf) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    // Decode Prepend+Base64 before any QUIC detection
                    let mut detected_prepend = None;
                    let mut was_sip_probe = false;
                    let mut was_rtp = false;
                    let mut sip_probe_kind = crate::proto::sip::SipKind::Response401;

                    if let Some(syslog_hdr_len) = crate::proto::syslog::check_header(&buf[..size]) {
                        if let Some(decoded_len) =
                            crate::proto::base64::decode(&buf[syslog_hdr_len..size], &mut out_buf)
                        {
                            buf[..decoded_len].copy_from_slice(&out_buf[..decoded_len]);
                            size = decoded_len;
                            detected_prepend = Some(crate::config::ObfsMode::Syslog);
                        } else {
                            continue;
                        }
                    } else if let Some(sip_len) = crate::proto::sip::check_header(&buf[..size]) {
                        if buf[..size].starts_with(b"OPTIONS ") {
                            sip_probe_kind = crate::proto::sip::SipKind::Response200;
                        } else if buf[..size].starts_with(b"REGISTER ") {
                            sip_probe_kind = crate::proto::sip::SipKind::Response401;
                        } else {
                            sip_probe_kind = crate::proto::sip::SipKind::Response403;
                        }

                        if let Some(decoded_len) =
                            crate::proto::base64::decode(&buf[sip_len..size], &mut out_buf)
                        {
                            if decoded_len > 0 {
                                buf[..decoded_len].copy_from_slice(&out_buf[..decoded_len]);
                                size = decoded_len;
                                detected_prepend = Some(crate::config::ObfsMode::Sip);
                            } else {
                                was_sip_probe = true;
                            }
                        } else {
                            was_sip_probe = true;
                        }
                    } else if crate::proto::sip::check_rtp_header(&buf[..size]) {
                        buf.copy_within(crate::proto::sip::RTP_HEADER_LEN..size, 0);
                        size -= crate::proto::sip::RTP_HEADER_LEN;
                        detected_prepend = Some(crate::config::ObfsMode::Sip);
                        was_rtp = true;
                    }

                    if was_sip_probe {
                        if is_server {
                            sip_resp.fill(0);
                            let src_ip_str = ingress_peer.bind_ip.to_string();
                            let dst_ip_str = src.ip().to_string();
                            let date_str = crate::tc::maps::format_sip_date_only(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            );
                            let hlen = crate::proto::sip::write_header(
                                &mut sip_resp,
                                sip_probe_kind,
                                ingress_peer.sip_domain.as_str(),
                                &src_ip_str,
                                &dst_ip_str,
                                5060,
                                src.port(),
                                10000,
                                0,
                                &auth_key,
                                &date_str,
                            );
                            let _ = ingress_ext.send_to(&sip_resp[..hlen], src);
                        }
                        continue;
                    }

                    // Verify this is GUT traffic — auto-detect gost mode in server mode
                    let (is_gut, detected_obfs) = if is_server {
                        // Save first 6 bytes for fallback, as obfs_verify(Gost) modifies them
                        let mut original_start = [0u8; 6];
                        original_start.copy_from_slice(&buf[..6]);

                        // Try plain QUIC first
                        if ((buf[0] & 0x40) == 0x40 || (buf[0] & 0x80) == 0x80)
                            && obfs_verify(
                                &buf,
                                size,
                                &key_init,
                                rounds,
                                crate::config::ObfsMode::Quic,
                            )
                        {
                            (true, crate::config::ObfsMode::Quic)
                        } else {
                            // Restore and try GOST/Sip/Syslog (they all use gost_mask)
                            buf[..6].copy_from_slice(&original_start);
                            if obfs_verify(
                                &buf,
                                size,
                                &key_init,
                                rounds,
                                crate::config::ObfsMode::Gost,
                            ) {
                                (
                                    true,
                                    detected_prepend.unwrap_or(crate::config::ObfsMode::Gost),
                                )
                            } else {
                                (false, crate::config::ObfsMode::Quic)
                            }
                        }
                    } else if obfs != crate::config::ObfsMode::Quic {
                        let ok = size >= GUT_QUIC_SHORT_HEADER_SIZE + 16
                            && obfs_verify(
                                &buf,
                                size,
                                &key_init,
                                rounds,
                                crate::config::ObfsMode::Gost,
                            );
                        (ok, obfs)
                    } else {
                        let fb = buf[0];
                        let ok = ((fb & 0x80) == 0x80 || (fb & 0x40) == 0x40)
                            && obfs_verify(
                                &buf,
                                size,
                                &key_init,
                                rounds,
                                crate::config::ObfsMode::Quic,
                            );
                        (ok, crate::config::ObfsMode::Quic)
                    };

                    if !is_gut {
                        if is_server {
                            if detected_prepend == Some(crate::config::ObfsMode::Sip) && !was_rtp {
                                sip_resp.fill(0);
                                let src_ip_str = ingress_peer.bind_ip.to_string();
                                let dst_ip_str = src.ip().to_string();
                                let date_str = crate::tc::maps::format_sip_date_only(
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                );
                                let hlen = crate::proto::sip::write_header(
                                    &mut sip_resp,
                                    sip_probe_kind,
                                    ingress_peer.sip_domain.as_str(),
                                    &src_ip_str,
                                    &dst_ip_str,
                                    4500,
                                    src.port(),
                                    10000,
                                    0,
                                    &auth_key,
                                    &date_str,
                                );
                                let _ = ingress_ext.send_to(&sip_resp[..hlen], src);
                            } else if obfs == crate::config::ObfsMode::Quic {
                                let mut vn_buf = [0u8; 64];
                                if let Some(vn_len) =
                                    generate_quic_version_negotiation(&buf, size, &mut vn_buf)
                                {
                                    let _ = ingress_ext.send_to(&vn_buf[..vn_len], src);
                                }
                            }
                        }
                        continue;
                    }

                    // Store detected gost mode per client
                    if is_server {
                        ingress_client_obfs
                            .lock()
                            .unwrap()
                            .insert(src, detected_obfs);
                    }

                    if let Some((new_size, _wg_sport, _wg_dport)) =
                        obfs_decap(&mut buf, size, &key_init, rounds, detected_obfs)
                    {
                        if dynamic_peer && new_size >= 8 {
                            let wg_type = buf[0] & 0x1F;
                            if wg_type == 1 {
                                let c_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                if c_idx != 0 {
                                    ingress_client_map.lock().unwrap().insert(c_idx, src);
                                }
                            } else if wg_type == 4 {
                                let s_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                if let Some(&c_idx) =
                                    ingress_session_map.lock().unwrap().get(&s_idx)
                                {
                                    ingress_client_map.lock().unwrap().insert(c_idx, src);
                                }
                            }
                        }

                        let dest = if is_server {
                            Some(wg_addr)
                        } else {
                            ingress_wg_peer.load()
                        };

                        if let Some(d) = dest {
                            let _ = ingress_local.send_to(&buf[..new_size], d);
                        }
                    }
                }
            })?;
        ingress_handles.push(ingress_handle);
    }

    egress_handle.join().map_err(|_| "egress thread panicked")?;
    for h in ingress_handles {
        h.join().map_err(|_| "ingress thread panicked")?;
    }
    Ok(())
}
