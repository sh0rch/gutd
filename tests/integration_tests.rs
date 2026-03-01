//! Integration tests for GUT v1 BPF-only architecture
//!
//! Wire protocol encoding/decoding happens entirely in BPF.
//! These tests verify Rust-side helpers: ChaCha ID derivation,
//! config building, metrics, and MAC generation.

#[cfg(test)]
mod chacha_tests {
    use gutd::proto::mask_balanced::chacha_next_ids;

    #[test]
    fn test_chacha_next_ids_deterministic() {
        let key = [0x42u8; 32];
        let nonce = 0x1234_5678u32;
        let rounds = 4u8;

        let (n1, p1) = chacha_next_ids(&key, nonce, rounds);
        let (n2, p2) = chacha_next_ids(&key, nonce, rounds);

        assert_eq!(n1, n2, "Same input must produce same nonce");
        assert_eq!(p1, p2, "Same input must produce same pkt_id");
        assert_ne!(n1, 0, "Nonce must be non-zero");
        assert_ne!(p1, 0, "PktId must be non-zero");
    }

    #[test]
    fn test_chacha_next_ids_different_nonces() {
        let key = [0x42u8; 32];
        let rounds = 4u8;

        let (n1, p1) = chacha_next_ids(&key, 1, rounds);
        let (n2, p2) = chacha_next_ids(&key, 2, rounds);

        assert_ne!(n1, n2, "Different nonces must produce different results");
        assert_ne!(p1, p2, "Different nonces must produce different pkt_ids");
    }

    #[test]
    fn test_chacha_chain_never_zero() {
        let key = [0xFFu8; 32];
        let rounds = 4u8;
        let mut nonce = 1u32;

        for _ in 0..1000 {
            let (next_nonce, next_pkt_id) = chacha_next_ids(&key, nonce, rounds);
            assert_ne!(next_nonce, 0, "Chained nonce must never be zero");
            assert_ne!(next_pkt_id, 0, "Chained pkt_id must never be zero");
            nonce = next_nonce;
        }
    }
}

#[cfg(test)]
mod mac_tests {
    use gutd::tun::mac_from_ipv4;

    #[test]
    fn test_mac_deterministic() {
        let mac1 = mac_from_ipv4("10.0.0.1").unwrap();
        let mac2 = mac_from_ipv4("10.0.0.1").unwrap();
        assert_eq!(mac1, mac2, "Same IP must produce same MAC");
    }

    #[test]
    fn test_mac_locally_administered() {
        let mac = mac_from_ipv4("10.0.0.1").unwrap();

        // Locally-administered bit set, multicast bit clear
        assert_eq!(mac[0] & 0x02, 0x02, "MAC must be locally-administered");
        assert_eq!(mac[0] & 0x01, 0x00, "MAC must be unicast");

        // GUT marker byte
        assert_eq!(mac[1], 0x47, "MAC must have GUT marker (0x47 = 'G')");
    }

    #[test]
    fn test_mac_embeds_ip() {
        let mac = mac_from_ipv4("10.0.0.1").unwrap();
        assert_eq!(mac, [0x02, 0x47, 10, 0, 0, 1]);

        let mac2 = mac_from_ipv4("192.168.1.100").unwrap();
        assert_eq!(mac2, [0x02, 0x47, 192, 168, 1, 100]);
    }

    #[test]
    fn test_mac_different_ips() {
        let mac_a = mac_from_ipv4("10.0.0.1").unwrap();
        let mac_b = mac_from_ipv4("10.0.0.2").unwrap();
        assert_ne!(mac_a, mac_b, "Different IPs must produce different MACs");
    }
}

#[cfg(test)]
mod config_tests {
    #[test]
    fn test_config_defaults() {
        // Verify config can parse minimal valid config
        let config_str = "\
[peer]
name = gut0
nic = eth0
address = 10.254.0.1/30
bind_ip = 0.0.0.0
peer_ip = 10.0.0.2
ports = 51820
key = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
";
        let tmp = std::env::temp_dir().join("test_gutd_config.conf");
        std::fs::write(&tmp, config_str).unwrap();
        let config = gutd::config::load_config(tmp.to_str().unwrap()).unwrap();
        assert_eq!(config.peer().ports, vec![51820]);
        assert_eq!(config.peer().name, "gut0");
        std::fs::remove_file(&tmp).ok();
    }
}

#[cfg(test)]
mod p2p_tests {
    use gutd::tun::compute_p2p_peer;

    #[test]
    fn test_p2p_30_host1() {
        let (local, peer, prefix) = compute_p2p_peer("10.0.0.1/30").unwrap();
        assert_eq!(local, "10.0.0.1");
        assert_eq!(peer, "10.0.0.2");
        assert_eq!(prefix, 30);
    }

    #[test]
    fn test_p2p_30_host2() {
        let (local, peer, prefix) = compute_p2p_peer("10.0.0.2/30").unwrap();
        assert_eq!(local, "10.0.0.2");
        assert_eq!(peer, "10.0.0.1");
        assert_eq!(prefix, 30);
    }

    #[test]
    fn test_p2p_31() {
        let (local, peer, prefix) = compute_p2p_peer("10.0.0.0/31").unwrap();
        assert_eq!(local, "10.0.0.0");
        assert_eq!(peer, "10.0.0.1");
        assert_eq!(prefix, 31);
    }

    #[test]
    fn test_p2p_network_addr_rejected() {
        assert!(compute_p2p_peer("10.0.0.0/30").is_err());
        assert!(compute_p2p_peer("10.0.0.3/30").is_err());
    }

    #[test]
    fn test_p2p_non_p2p_prefix_rejected() {
        assert!(compute_p2p_peer("10.0.0.1/24").is_err());
    }
}
