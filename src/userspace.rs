use std::collections::HashMap;
use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::feistel::{feistel32, feistel32_inv, FEISTEL_SALT_PORTS};
use crate::proto::mask_balanced::{chacha_block, chacha_block_fast, chacha_init};

const GUT_QUIC_SHORT_HEADER_SIZE: usize = 14;
const GUT_QUIC_LONG_HEADER_SIZE: usize = 100;
const BALLAST_THRESHOLD: usize = 220;
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

pub fn compute_feistel_rk(key: &[u8; 32], rounds: u8) -> [u32; 4] {
    let ks = chacha_block(key, 0xFFFFFFFE, 0, rounds);
    [ks[0], ks[1], ks[2], ks[3]]
}

fn xor16(p: &mut [u8], k: &[u8]) {
    for i in 0..16 {
        p[i] ^= k[i];
    }
}

/// Noise mode: XOR first 6 bytes with bytes [6..12] to hide QUIC signatures.
fn noise_mask(buf: &mut [u8]) {
    for i in 0..6 {
        buf[i] ^= buf[6 + i];
    }
}

#[allow(clippy::too_many_arguments)]
pub fn quic_encap(
    buf: &mut [u8],
    orig_len: usize,
    key: &[u32; 12],
    feistel_rk: &[u32; 4],
    rounds: u8,
    is_server: bool,
    wg_sport: u16,
    wg_dport: u16,
    noise: bool,
) -> Option<usize> {
    if orig_len < 16 {
        return None;
    }

    let wg_type = buf[0] & 0x1F;
    let quic_hdr_len = if wg_type == 3 {
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

    let nonce = wg_nonce32(&buf[..orig_len]);

    // Shift payload forward to make room for QUIC header
    buf.copy_within(0..orig_len, quic_hdr_len);

    // Masking
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
    let enc_ports = feistel32(plain_ports ^ FEISTEL_SALT_PORTS, feistel_rk);

    // PPn
    let ppn = ks47[10];

    // Compute Ballast
    let ks69 = chacha_block_fast(key, 69, nonce, rounds);
    let pad_block: [u8; 64] = unsafe { std::mem::transmute(ks69) };

    let pad_len;
    if orig_len < BALLAST_THRESHOLD {
        let raw = pad_block[63] & 0x3F;
        pad_len = (raw as usize) + 1;
        // copy padding to the end
        for i in 0..pad_len {
            buf[wg_off + orig_len + i] = pad_block[i & 0x3F];
        }
        buf[quic_hdr_len - 1] = 0x40 | raw;
    } else {
        pad_len = 0;
        buf[quic_hdr_len - 1] = 0x00;
    }

    if quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        buf[0] = 0x40; // Short
        let dcid = feistel32(wg_idx, feistel_rk);
        buf[1..5].copy_from_slice(&dcid.to_le_bytes());
        buf[5..9].copy_from_slice(&ppn.to_le_bytes());
        buf[9..13].copy_from_slice(&enc_ports.to_le_bytes());
    } else {
        // 0xC0 = QUIC Initial (client Type 1), 0xF0 = QUIC Retry (Cookie Reply Type 3)
        buf[0] = if wg_type == 3 { 0xF0 } else { 0xC0 };
        buf[1] = 0x6b;
        buf[2] = 0x33;
        buf[3] = 0x43;
        buf[4] = 0xcf;

        let t_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u32;
        let time_noise = feistel32(t_ns, feistel_rk);
        let noise_b = time_noise.to_le_bytes();

        for i in 1..90 {
            buf[i] = pad_block[(i * 7) & 0x3F] ^ noise_b[i & 3];
        }

        buf[1] = 0x6b;
        buf[2] = 0x33;
        buf[3] = 0x43;
        buf[4] = 0xcf;

        let dcid = feistel32(wg_idx, feistel_rk);
        let dcid2 = feistel32(wg_idx ^ 0xDEADBEEF, feistel_rk);
        let scid = feistel32(wg_idx ^ 0xCAFEBABE, feistel_rk);
        let scid2 = feistel32(wg_idx ^ 0x12345678, feistel_rk);

        buf[5] = 0x08;
        buf[6..10].copy_from_slice(&dcid.to_le_bytes());
        buf[10..14].copy_from_slice(&dcid2.to_le_bytes());
        buf[14] = 0x08;
        buf[15..19].copy_from_slice(&scid.to_le_bytes());
        buf[19..23].copy_from_slice(&scid2.to_le_bytes());
        buf[23] = 0x00;
        buf[24] = 0x40;
        buf[25] = 0x00;
        buf[26..30].copy_from_slice(&ppn.to_le_bytes());
        buf[30..34].copy_from_slice(&enc_ports.to_le_bytes());
        buf[99] = if pad_len > 0 {
            0x40 | ((pad_len as u8 - 1) & 0x3F)
        } else {
            0
        };
    }

    // Noise mode: XOR first 6 bytes with bytes [6..12] to hide QUIC signatures
    if noise {
        noise_mask(buf);
    }

    Some(quic_hdr_len + orig_len + pad_len)
}
/// Verify DCID and PPN in QUIC header match the crypto-derived values.
/// Returns `true` if the packet is authentic GUT traffic.
/// In noise mode, unmasking is applied to the first 6 bytes in-place on success;
/// on failure, the original bytes are restored.
pub fn quic_verify(
    buf: &mut [u8],
    orig_len: usize,
    key: &[u32; 12],
    feistel_rk: &[u32; 4],
    rounds: u8,
    noise: bool,
) -> bool {
    if orig_len < GUT_QUIC_SHORT_HEADER_SIZE + 16 {
        return false;
    }

    // Noise mode: save first 6 bytes, unmask, restore on failure
    let saved = if noise {
        let mut s = [0u8; 6];
        s.copy_from_slice(&buf[..6]);
        noise_mask(buf);
        Some(s)
    } else {
        None
    };

    let verify_result = quic_verify_inner(buf, orig_len, key, feistel_rk, rounds);

    // On failure in noise mode, restore original bytes
    if !verify_result {
        if let Some(s) = saved {
            buf[..6].copy_from_slice(&s);
        }
    }

    verify_result
}

fn quic_verify_inner(
    buf: &[u8],
    orig_len: usize,
    key: &[u32; 12],
    feistel_rk: &[u32; 4],
    rounds: u8,
) -> bool {
    let first_byte = buf[0];
    let quic_hdr_len = if (first_byte & 0xC0) == 0xC0 {
        GUT_QUIC_LONG_HEADER_SIZE
    } else if (first_byte & 0x40) == 0x40 {
        GUT_QUIC_SHORT_HEADER_SIZE
    } else {
        return false;
    };

    if orig_len < quic_hdr_len + 32 {
        return false;
    }

    let pad_byte = buf[quic_hdr_len - 1];
    let ballast_len = if (pad_byte & 0x40) != 0 {
        ((pad_byte & 0x3F) as usize) + 1
    } else {
        0
    };

    let wg_off = quic_hdr_len;
    let wg_len = orig_len - quic_hdr_len;
    if ballast_len > wg_len {
        return false;
    }
    let actual_wg_len = wg_len - ballast_len;
    if actual_wg_len < 32 {
        return false;
    }

    // Compute nonce from masked WG payload (nonce bytes 16..32 are NOT masked by ks47[0..16])
    let nonce = wg_nonce32(&buf[wg_off..wg_off + actual_wg_len]);

    let ks47 = chacha_block_fast(key, 47, nonce, rounds);
    let ks47_b: [u8; 64] = unsafe { std::mem::transmute(ks47) };

    // Temporarily decrypt first 16 bytes to get wg_type and wg_idx
    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&buf[wg_off..wg_off + 16]);
    xor16(&mut hdr, &ks47_b[0..16]);

    let wg_type = hdr[0] & 0x1F;
    let wg_idx = if wg_type == 2 {
        u32::from_le_bytes(hdr[8..12].try_into().unwrap())
    } else {
        u32::from_le_bytes(hdr[4..8].try_into().unwrap())
    };

    let expected_dcid = feistel32(wg_idx, feistel_rk);
    let expected_ppn = ks47[10];

    if quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        let pkt_dcid = u32::from_le_bytes(buf[1..5].try_into().unwrap());
        let pkt_ppn = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        pkt_dcid == expected_dcid && pkt_ppn == expected_ppn
    } else {
        let pkt_dcid = u32::from_le_bytes(buf[6..10].try_into().unwrap());
        let pkt_ppn = u32::from_le_bytes(buf[26..30].try_into().unwrap());
        pkt_dcid == expected_dcid && pkt_ppn == expected_ppn
    }
}

pub fn quic_decap(
    buf: &mut [u8],
    orig_len: usize,
    key: &[u32; 12],
    feistel_rk: &[u32; 4],
    rounds: u8,
) -> Option<(usize, u16, u16)> {
    if orig_len < GUT_QUIC_SHORT_HEADER_SIZE + 16 {
        return None;
    }

    let first_byte = buf[0];
    let quic_hdr_len = if (first_byte & 0xC0) == 0xC0 {
        GUT_QUIC_LONG_HEADER_SIZE
    } else if (first_byte & 0x40) == 0x40 {
        GUT_QUIC_SHORT_HEADER_SIZE
    } else {
        return None;
    };

    if orig_len < quic_hdr_len + 16 {
        return None;
    }

    let pad_byte = buf[quic_hdr_len - 1];
    let ballast_len = if (pad_byte & 0x40) != 0 {
        ((pad_byte & 0x3F) as usize) + 1
    } else {
        0
    };

    // We can decrypt ports from QUIC Header
    let enc_ports = if quic_hdr_len == GUT_QUIC_SHORT_HEADER_SIZE {
        u32::from_le_bytes(buf[9..13].try_into().unwrap())
    } else {
        u32::from_le_bytes(buf[30..34].try_into().unwrap())
    };

    let plain_ports = feistel32_inv(enc_ports, feistel_rk) ^ FEISTEL_SALT_PORTS;
    let wg_sport = (plain_ports >> 16) as u16;
    let wg_dport = (plain_ports & 0xFFFF) as u16;

    let wg_off = quic_hdr_len;
    let wg_len = orig_len - quic_hdr_len;

    if ballast_len > wg_len {
        return None;
    }
    let actual_wg_len = wg_len - ballast_len;

    let nonce = wg_nonce32(&buf[wg_off..wg_off + actual_wg_len]);

    let ks47 = chacha_block_fast(key, 47, nonce, rounds);
    let ks47_b: [u8; 64] = unsafe { std::mem::transmute(ks47) };

    // Decrypt first 16 bytes
    xor16(&mut buf[wg_off..wg_off + 16], &ks47_b[0..16]);
    let wg_type = buf[wg_off] & 0x1F;

    if wg_type == 1 && actual_wg_len >= 148 {
        xor16(&mut buf[wg_off + 132..wg_off + 148], &ks47_b[16..32]);
    } else if wg_type == 2 && actual_wg_len >= 92 {
        xor16(&mut buf[wg_off + 76..wg_off + 92], &ks47_b[16..32]);
    }

    // Shift the unwrapped payload back to the start
    buf.copy_within(wg_off..wg_off + actual_wg_len, 0);

    Some((actual_wg_len, wg_sport, wg_dport))
}

pub fn run(config: &crate::config::Config) -> crate::Result<()> {
    if config.peers.is_empty() {
        return Err("No peers configured in gutd.conf".into());
    }

    let peer = &config.peers[0];
    let key = peer.key;
    let key_init = chacha_init(&key);
    let rounds: u8 = 4;
    let feistel_rk = compute_feistel_rk(&key, rounds);

    let is_server = peer.responder;
    let noise = match std::env::var("GUTD_OBFS").as_deref() {
        Ok("noise") => true,
        Ok(_) => peer.obfs == crate::config::ObfsMode::Noise,
        Err(_) => peer.obfs == crate::config::ObfsMode::Noise,
    };

    println!(
        "Starting gutd-userspace proxy (dual-thread). is_server={} obfs={}",
        is_server,
        if noise { "noise" } else { "quic" }
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

    // ext_socket: GUT traffic to/from remote peer (first configured port).
    let ext_addr = SocketAddr::new(peer.bind_ip, peer.ports[0]);
    let ext_socket = Arc::new(UdpSocket::bind(ext_addr)?);
    tune_udp_buffers(&ext_socket);
    println!("Listening (ext) on {}", ext_addr);

    // local_socket: WG-facing socket.
    // Client: binds to wg_addr (WG Endpoint = wg_addr).
    // Server: ephemeral port — WG daemon already owns wg_addr.
    let local_bind: SocketAddr = if !is_server {
        wg_addr
    } else {
        SocketAddr::new(peer.bind_ip, 0)
    };
    let local_socket = Arc::new(UdpSocket::bind(local_bind)?);
    tune_udp_buffers(&local_socket);
    println!("Local WG-facing socket on {}", local_bind);

    // Lock-free shared WG peer address (client mode: egress writes, ingress reads)
    let shared_wg_peer = Arc::new(SharedAddr::new());

    // Shared maps for dynamic_peer routing (egress reads client_map, ingress writes it; vice versa for session_map)
    let client_map: Arc<Mutex<HashMap<u32, SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));
    let session_map: Arc<Mutex<HashMap<u32, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Per-client noise mode (auto-detected by ingress, read by egress in server mode)
    let client_noise: Arc<Mutex<HashMap<SocketAddr, bool>>> = Arc::new(Mutex::new(HashMap::new()));

    // ── Thread 1: EGRESS (WG → encap → remote peer) ──────────────────
    let egress_ext = Arc::clone(&ext_socket);
    let egress_local = Arc::clone(&local_socket);
    let egress_wg_peer = Arc::clone(&shared_wg_peer);
    let egress_client_map = Arc::clone(&client_map);
    let egress_session_map = Arc::clone(&session_map);
    let egress_client_noise = Arc::clone(&client_noise);
    let egress_handle = std::thread::Builder::new()
        .name("gutd-egress".into())
        .spawn(move || {
            let mut buf = [0u8; 65536];

            loop {
                let (size, src) = match egress_local.recv_from(&mut buf) {
                    Ok(r) => r,
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
                    // In server mode, use per-client noise mode (auto-detected by ingress)
                    let encap_noise = if is_server {
                        *egress_client_noise
                            .lock()
                            .unwrap()
                            .get(&dest)
                            .unwrap_or(&noise)
                    } else {
                        noise
                    };
                    if let Some(new_size) = quic_encap(
                        &mut buf,
                        size,
                        &key_init,
                        &feistel_rk,
                        rounds,
                        is_server,
                        src.port(),
                        wg_port,
                        encap_noise,
                    ) {
                        let _ = egress_ext.send_to(&buf[..new_size], dest);
                    }
                }
            }
        })?;

    // ── Thread 2: INGRESS (remote peer → decap → WG) ─────────────────
    let ingress_ext = Arc::clone(&ext_socket);
    let ingress_local = Arc::clone(&local_socket);
    let ingress_wg_peer = Arc::clone(&shared_wg_peer);
    let ingress_client_map = Arc::clone(&client_map);
    let ingress_session_map = Arc::clone(&session_map);
    let ingress_client_noise = Arc::clone(&client_noise);
    let ingress_handle = std::thread::Builder::new()
        .name("gutd-ingress".into())
        .spawn(move || {
            let mut buf = [0u8; 65536];

            loop {
                let (size, src) = match ingress_ext.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Verify this is GUT traffic — auto-detect noise mode in server mode
                let (is_gut, detected_noise) = if is_server {
                    // Try plain QUIC first, then noise
                    if quic_verify(&mut buf, size, &key_init, &feistel_rk, rounds, false) {
                        (true, false)
                    } else if quic_verify(&mut buf, size, &key_init, &feistel_rk, rounds, true) {
                        (true, true)
                    } else {
                        (false, false)
                    }
                } else if noise {
                    let ok = size >= GUT_QUIC_SHORT_HEADER_SIZE + 16
                        && quic_verify(&mut buf, size, &key_init, &feistel_rk, rounds, true);
                    (ok, true)
                } else {
                    let fb = buf[0];
                    let ok = ((fb & 0xC0) == 0xC0 || (fb & 0x40) == 0x40)
                        && quic_verify(&mut buf, size, &key_init, &feistel_rk, rounds, false);
                    (ok, false)
                };

                if !is_gut {
                    continue;
                }

                // Store detected noise mode per client
                if is_server {
                    ingress_client_noise
                        .lock()
                        .unwrap()
                        .insert(src, detected_noise);
                }

                if let Some((new_size, _wg_sport, _wg_dport)) =
                    quic_decap(&mut buf, size, &key_init, &feistel_rk, rounds)
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
                            if let Some(&c_idx) = ingress_session_map.lock().unwrap().get(&s_idx) {
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

    egress_handle.join().map_err(|_| "egress thread panicked")?;
    ingress_handle
        .join()
        .map_err(|_| "ingress thread panicked")?;
    Ok(())
}
