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
) -> Option<usize> {
    if orig_len < 16 {
        return None;
    }

    let wg_type = buf[0] & 0x1F;
    let quic_hdr_len = if is_server {
        GUT_QUIC_SHORT_HEADER_SIZE
    } else {
        if wg_type == 1 {
            GUT_QUIC_LONG_HEADER_SIZE
        } else {
            GUT_QUIC_SHORT_HEADER_SIZE
        }
    };

    let mut wg_idx = 0u32;
    if wg_type == 1 && orig_len >= 8 {
        wg_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    } else if orig_len >= 12 {
        wg_idx = u32::from_le_bytes(buf[8..12].try_into().unwrap());
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
        buf[0] = 0xC0; // Initial
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

    Some(quic_hdr_len + orig_len + pad_len)
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

    let addr = &peer.address;
    let is_server = {
        let parts: Vec<&str> = addr.split('/').collect();
        let ip_parts: Vec<&str> = parts[0].split('.').collect();
        if ip_parts.len() == 4 {
            let last_octet: u8 = ip_parts[3].parse().unwrap_or(0);
            (last_octet & 1) == 1
        } else {
            false
        }
    };

    println!(
        "Starting gutd-userspace proxy (MIO event loop). is_server={}",
        is_server
    );

    let wg_port_str = env::var("WG_PORT").unwrap_or_else(|_| "51820".to_string());
    let wg_port: u16 = wg_port_str.parse()?;
    let wg_addr: SocketAddr = format!("127.0.0.1:{}", wg_port_str).parse()?;

    // Optional override for where to send egress traffic
    let peer_ip_str = env::var("GUTD_PEER_IP").unwrap_or_else(|_| peer.peer_ip.to_string());
    // For ports, use the first one from config
    let peer_port = peer.ports.first().copied().unwrap_or(41000);
    let remote_peer_addr: SocketAddr = format!("{}:{}", peer_ip_str, peer_port).parse()?;

    println!("Forwarding INGRESS to local WireGuard at {}", wg_addr);
    println!("Forwarding EGRESS to remote Peer at {}", remote_peer_addr);

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);

    let mut ext_sockets = HashMap::new();
    let mut current_token_id = 0;

    for &port in &peer.ports {
        let ext_addr = SocketAddr::new(peer.bind_ip, port);
        let std_sock = std::net::UdpSocket::bind(ext_addr).unwrap();
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

    let mut buf = [0u8; 65536];

    // For sending back to WG clients with the right ephemeral source port
    let std_local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let _ = std_local.set_nonblocking(true);

    let mut local_socket = UdpSocket::from_std(std_local);
    let local_token = Token(current_token_id);
    poll.registry()
        .register(&mut local_socket, local_token, Interest::READABLE)?;

    // We remember the WG client ephemeral ports
    let mut last_wg_client_addr: Option<SocketAddr> = None;

    loop {
        let _ = poll.poll(&mut events, None);

        for event in events.iter() {
            let token = event.token();

            if token == local_token {
                loop {
                    match local_socket.recv_from(&mut buf) {
                        Ok((size, src)) => {
                            last_wg_client_addr = Some(src);
                            // It's EGRESS traffic from local WG
                            if let Some(new_size) = quic_encap(
                                &mut buf,
                                size,
                                &key_init,
                                &feistel_rk,
                                rounds,
                                is_server,
                                src.port(),
                                wg_port,
                            ) {
                                if let Some(ext_sock) = ext_sockets.values().next() {
                                    let _ = ext_sock.send_to(&buf[..new_size], remote_peer_addr);
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
                            let first_byte = buf[0];
                            if (first_byte & 0xC0) == 0xC0 || (first_byte & 0x40) == 0x40 {
                                // INGRESS traffic (QUIC) from Remote Peer
                                if let Some((new_size, _wg_sport, _wg_dport)) =
                                    quic_decap(&mut buf, size, &key_init, &feistel_rk, rounds)
                                {
                                    if is_server {
                                        let _ = local_socket.send_to(&buf[..new_size], wg_addr);
                                    } else {
                                        if let Some(addr) = last_wg_client_addr {
                                            let _ = local_socket.send_to(&buf[..new_size], addr);
                                        } else {
                                            let _ = local_socket.send_to(&buf[..new_size], wg_addr);
                                        }
                                    }
                                }
                            } else {
                                // It could be WG traffic sent explicitly to the external socket!
                                // (If WG was configured to point to 127.0.0.1:41000 instead of ephemeral local_socket)
                                last_wg_client_addr = Some(src);
                                if let Some(new_size) = quic_encap(
                                    &mut buf,
                                    size,
                                    &key_init,
                                    &feistel_rk,
                                    rounds,
                                    is_server,
                                    src.port(),
                                    wg_port,
                                ) {
                                    let _ = ext_socket.send_to(&buf[..new_size], remote_peer_addr);
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
