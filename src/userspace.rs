use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::proto::feistel::{feistel32, feistel32_inv, FEISTEL_SALT_PORTS};
use crate::proto::mask_balanced::{chacha_block, chacha_block_fast, chacha_init};

const GUT_QUIC_SHORT_HEADER_SIZE: usize = 14;
const GUT_QUIC_LONG_HEADER_SIZE: usize = 100;
const BALLAST_THRESHOLD: usize = 220;

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

fn compute_feistel_rk(key: &[u8; 32], rounds: u8) -> [u32; 4] {
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
fn quic_encap(
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
fn quic_verify(
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

fn quic_decap(
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
        "Starting gutd-userspace proxy (MIO event loop). is_server={} obfs={}",
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
    // For ports, use the first one from config
    let peer_port = peer.ports.first().copied().unwrap_or(41000);
    let remote_peer_addr: Option<SocketAddr> = if dynamic_peer {
        None
    } else {
        Some(format!("{}:{}", peer_ip_str, peer_port).parse()?)
    };

    // Dynamic peer: multi-client maps (keyed by WG index)
    //   client_map: C_idx → learned SocketAddr
    //   session_map: S_idx → C_idx (bridged on Type 2 egress)
    let mut client_map: HashMap<u32, SocketAddr> = HashMap::new();
    let mut session_map: HashMap<u32, u32> = HashMap::new();

    if is_server {
        // Server: wg_addr is where we PUSH decapsulated packets (WG daemon listens there)
        println!(
            "Local WireGuard daemon at {} (server will push decapped packets there)",
            wg_addr
        );
    } else {
        // Client: wg_addr.port() = server's WG ListenPort, embedded in QUIC enc_ports.
        // XDP on the server restores this as udp->dest, delivering to the right WG port.
        // The client's own WG address is learned automatically from incoming packets.
        // Configure: wg_host = <any>:<SERVER_WG_LISTENPORT>  (e.g. 127.0.0.1:51820)
        println!(
            "Server WireGuard listen port: {} (encoded in QUIC headers so XDP delivers to correct port)",
            wg_addr.port()
        );
    }
    if let Some(ref addr) = remote_peer_addr {
        println!("Remote peer: {}", addr);
    } else {
        println!("Remote peer: dynamic (learned from inbound QUIC packets)");
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    let mut ext_sockets = HashMap::new();
    let mut current_token_id = 0;

    for &port in &peer.ports {
        let ext_addr = SocketAddr::new(peer.bind_ip, port);
        let std_sock = match std::net::UdpSocket::bind(ext_addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: Failed to bind to {}: {}", ext_addr, e);
                continue;
            }
        };
        let _ = std_sock.set_nonblocking(true);
        #[cfg(target_family = "unix")]
        let _ = std::os::unix::io::AsRawFd::as_raw_fd(&std_sock);
        /* we'll use libc if available later, for now ignore OS limits for std_sock */

        match Ok::<_, std::io::Error>(mio::net::UdpSocket::from_std(std_sock)) {
            Ok(mut socket) => {
                let token = Token(current_token_id);
                current_token_id += 1;
                poll.registry()
                    .register(&mut socket, token, Interest::READABLE)?;
                ext_sockets.insert(token, socket);
                println!("Listening on port: {}", ext_addr);
            }
            Err(e) => {
                eprintln!("Warning: Failed to bind to {}: {}", ext_addr, e);
            }
        }
    }

    if ext_sockets.is_empty() {
        return Err("Could not bind to any external ports".into());
    }

    // Ordered list of ext socket tokens for round-robin port rotation
    let ext_tokens: Vec<Token> = ext_sockets.keys().copied().collect();
    let mut ext_rr_idx: usize = 0;

    let mut buf = [0u8; 65536];

    // For sending back to WG clients with the right ephemeral source port
    let std_local = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let _ = std_local.set_nonblocking(true);

    let mut local_socket = UdpSocket::from_std(std_local);
    let local_token = Token(current_token_id);
    poll.registry()
        .register(&mut local_socket, local_token, Interest::READABLE)?;

    // Client mode: WG tells us its address on the first packet it sends to ext_socket.
    // Updated on every new handshake (Type 1) → reconnects always work.
    // Server mode: wg_addr from config is authoritative (MikroTik, Linux WG daemon etc.)
    let mut learned_wg_addr: Option<SocketAddr> = None;

    loop {
        let _ = poll.poll(&mut events, None);

        for event in events.iter() {
            let token = event.token();

            if token == local_token {
                loop {
                    match local_socket.recv_from(&mut buf) {
                        Ok((size, src)) => {
                            // It's EGRESS traffic from local WG
                            // Multi-client routing: determine destination by WG index
                            let egress_dest = if !dynamic_peer {
                                remote_peer_addr
                            } else {
                                if size < 4 {
                                    None
                                } else {
                                    let wg_type = buf[0] & 0x1F;
                                    if wg_type == 1 {
                                        // Server-initiated rekey: no receiver_index to route.
                                        // Drop — client will re-initiate.
                                        eprintln!("[gutd] dropping server-initiated Type 1 rekey (dynamic mode)");
                                        None
                                    } else if wg_type == 2 && size >= 12 {
                                        // Type 2: sender=S_idx[4..8], receiver=C_idx[8..12]
                                        let s_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        let c_idx =
                                            u32::from_le_bytes(buf[8..12].try_into().unwrap());
                                        session_map.insert(s_idx, c_idx);
                                        client_map.get(&c_idx).copied()
                                    } else if wg_type == 3 && size >= 8 {
                                        // Type 3 (Cookie Reply): receiver=C_idx[4..8]
                                        // Critical for handshake completion under rate-limiting
                                        let c_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        client_map.get(&c_idx).copied()
                                    } else if wg_type == 4 && size >= 8 {
                                        // Type 4: receiver=C_idx[4..8]
                                        let c_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        client_map.get(&c_idx).copied()
                                    } else {
                                        None
                                    }
                                }
                            };
                            if let Some(dest) = egress_dest {
                                if let Some(new_size) = quic_encap(
                                    &mut buf,
                                    size,
                                    &key_init,
                                    &feistel_rk,
                                    rounds,
                                    is_server,
                                    src.port(),
                                    wg_port,
                                    noise,
                                ) {
                                    let tok = ext_tokens[ext_rr_idx % ext_tokens.len()];
                                    ext_rr_idx = ext_rr_idx.wrapping_add(1);
                                    if let Some(ext_sock) = ext_sockets.get(&tok) {
                                        let _ = ext_sock.send_to(&buf[..new_size], dest);
                                    }
                                }
                            } else if dynamic_peer && size >= 1 {
                                let wg_type = buf[0] & 0x1F;
                                if wg_type != 1 {
                                    eprintln!(
                                        "[gutd] egress: no route for WG type {} (size={}, client_map={})",
                                        wg_type, size, client_map.len()
                                    );
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            } else if ext_sockets.contains_key(&token) {
                let ext_socket = ext_sockets.get_mut(&token).unwrap();
                loop {
                    match ext_socket.recv_from(&mut buf) {
                        Ok((size, src)) => {
                            // Determine if this is inbound GUT traffic or local WG egress.
                            // In quic mode: check QUIC first-byte pattern.
                            // In noise mode: first byte is masked, so try quic_verify
                            //   (which unmaskes in-place) — success = GUT ingress.
                            let is_gut_ingress = if noise {
                                size >= GUT_QUIC_SHORT_HEADER_SIZE + 16
                                    && quic_verify(
                                        &mut buf,
                                        size,
                                        &key_init,
                                        &feistel_rk,
                                        rounds,
                                        true,
                                    )
                            } else {
                                let first_byte = buf[0];
                                ((first_byte & 0xC0) == 0xC0 || (first_byte & 0x40) == 0x40)
                                    && quic_verify(
                                        &mut buf,
                                        size,
                                        &key_init,
                                        &feistel_rk,
                                        rounds,
                                        false,
                                    )
                            };
                            if is_gut_ingress {
                                // INGRESS traffic (GUT) from Remote Peer — already verified
                                // Dynamic peer: learn endpoint from validated packet (multi-client)
                                // We decap first, then parse WG type/index from the inner payload.
                                if let Some((new_size, _wg_sport, _wg_dport)) =
                                    quic_decap(&mut buf, size, &key_init, &feistel_rk, rounds)
                                {
                                    if dynamic_peer && new_size >= 8 {
                                        let wg_type = buf[0] & 0x1F;
                                        if wg_type == 1 {
                                            // Type 1: sender_index[4..8] = C_idx
                                            let c_idx =
                                                u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                            if c_idx != 0 {
                                                client_map.insert(c_idx, src);
                                            }
                                        } else if wg_type == 4 {
                                            // Type 4: receiver_index[4..8] = S_idx → session_map → C_idx
                                            let s_idx =
                                                u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                            if let Some(&c_idx) = session_map.get(&s_idx) {
                                                client_map.insert(c_idx, src);
                                            }
                                        }
                                    }
                                    if is_server {
                                        // Server: forward decapped packet to local WireGuard daemon
                                        let _ = local_socket.send_to(&buf[..new_size], wg_addr);
                                    } else {
                                        // Client: send back from ext_socket to WG's actual address.
                                        // Use learned address (updated on every new handshake) so
                                        // reconnects work even if WG changes its source port.
                                        // Sending from ext_socket prevents WG endpoint roaming.
                                        let dest = learned_wg_addr.unwrap_or(wg_addr);
                                        let _ = ext_socket.send_to(&buf[..new_size], dest);
                                    }
                                }
                            } else {
                                // Prevent treating server's unreachable/error packets as WG egress
                                if let Some(peer_addr) = remote_peer_addr {
                                    if src.ip() == peer_addr.ip() && !is_server {
                                        continue;
                                    }
                                }
                                // Non-QUIC on ext_socket = WG traffic (Endpoint = 127.0.0.1:ext_port).
                                // Learn WG's current address so we always reply to the right port,
                                // including after reconnects where WG may use a different source port.
                                if !is_server {
                                    // Update on Type 1 (new handshake) always; otherwise only if unknown
                                    let wg_type = if size >= 1 { buf[0] & 0x1F } else { 0 };
                                    if wg_type == 1 || learned_wg_addr.is_none() {
                                        learned_wg_addr = Some(src);
                                    }
                                }
                                let egress_dest = if !dynamic_peer {
                                    remote_peer_addr
                                } else if size >= 12 {
                                    let wg_type = buf[0] & 0x1F;
                                    if wg_type == 2 {
                                        let s_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        let c_idx =
                                            u32::from_le_bytes(buf[8..12].try_into().unwrap());
                                        session_map.insert(s_idx, c_idx);
                                        client_map.get(&c_idx).copied()
                                    } else if wg_type == 3 && size >= 8 {
                                        // Type 3 (Cookie Reply): receiver=C_idx[4..8]
                                        let c_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        client_map.get(&c_idx).copied()
                                    } else if wg_type == 4 && size >= 8 {
                                        let c_idx =
                                            u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                        client_map.get(&c_idx).copied()
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };
                                if let Some(dest) = egress_dest {
                                    if let Some(new_size) = quic_encap(
                                        &mut buf,
                                        size,
                                        &key_init,
                                        &feistel_rk,
                                        rounds,
                                        is_server,
                                        src.port(),
                                        wg_port,
                                        noise,
                                    ) {
                                        let _ = ext_socket.send_to(&buf[..new_size], dest);
                                    }
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }
}
