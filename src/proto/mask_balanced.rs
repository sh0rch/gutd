/// Balanced masking using pure Rust ChaCha with configurable rounds.
/// Compatible with BPF path (same keystream, same block layout).
/// Default: ChaCha4 = 2 double rounds (configurable via `rounds`)
///
/// Mask data using ChaCha with configurable rounds (pure Rust).
/// `rounds` = ChaCha round count (2,4,6,...,20). Default: 4 (2 double-rounds)
/// Self-inverse: mask == unmask. Matches BPF `mask_data_chacha` exactly.
pub fn mask_data(data: &mut [u8], key: &[u8; 32], nonce: u32, rounds: u8) {
    let mut offset = 0usize;
    let mut counter = 0u32;

    while offset < data.len() {
        let ks = chacha_block(key, counter, nonce, rounds);
        let ks_bytes: [u8; 64] = unsafe { std::mem::transmute(ks) };
        let remain = data.len() - offset;
        let n = remain.min(64);
        // XOR keystream into data
        for i in 0..n {
            data[offset + i] ^= ks_bytes[i];
        }
        offset += 64;
        counter += 1;
    }
}

// --- ChaCha quarter-round (pure Rust, for utility blocks only) --------

#[inline]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// Generate a single ChaCha keystream block with arbitrary counter.
/// Used for nonce-chain (block 111), ballast (block 99), and bulk masking.
///
/// Returns 16 × u32 words of keystream.
pub fn chacha_block(key: &[u8; 32], counter: u32, nonce: u32, rounds: u8) -> [u32; 16] {
    let mut s = [0u32; 16];
    // "expand 32-byte k"
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    s[12] = counter;
    s[13] = nonce;
    s[14] = 0;
    s[15] = 0;

    let initial = s;
    let dr = (rounds / 2).max(1);
    for _ in 0..dr {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        s[i] = s[i].wrapping_add(initial[i]);
    }
    s
}

/// Derive (next_nonce, next_pkt_id) from ChaCha block 111.
/// Both values are guaranteed non-zero.
pub fn chacha_next_ids(key: &[u8; 32], nonce: u32, rounds: u8) -> (u32, u32) {
    let ks = chacha_block(key, 111, nonce, rounds);
    let nn = if ks[0] == 0 { 1 } else { ks[0] };
    let np = if ks[1] == 0 { 1 } else { ks[1] };
    (nn, np)
}

/// Compute ballast data + length from ChaCha block 99.
/// Returns (ballast_bytes, ballast_len) where ballast_len ∈ [0, 63].
/// Only meaningful when inner_len < `BALLAST_THRESHOLD` (caller checks).
pub fn chacha_ballast(key: &[u8; 32], nonce: u32, rounds: u8) -> ([u8; 63], usize) {
    let ks = chacha_block(key, 99, nonce, rounds);
    let bytes: [u8; 64] = unsafe { std::mem::transmute(ks) };
    let blen = (bytes[63] & 0x3F) as usize; // 0..63
    let mut out = [0u8; 63];
    out.copy_from_slice(&bytes[..63]);
    (out, blen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_unmask() {
        let key = [0x42u8; 32];
        let nonce = 0x1234_5678;
        let original = b"Test data for ChaCha4".to_vec();

        let mut data = original.clone();
        mask_data(&mut data, &key, nonce, 4);
        assert_ne!(&data[..], &original[..]);

        mask_data(&mut data, &key, nonce, 4);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_different_nonce() {
        let key = [0x42u8; 32];
        let original = b"Test data".to_vec();

        let mut data1 = original.clone();
        mask_data(&mut data1, &key, 1, 4);

        let mut data2 = original.clone();
        mask_data(&mut data2, &key, 2, 4);

        assert_ne!(data1, data2);
    }

    #[test]
    fn test_chacha_next_ids_nonzero() {
        let key = [0x42u8; 32];
        let (nn, np) = chacha_next_ids(&key, 1, 4);
        assert_ne!(nn, 0);
        assert_ne!(np, 0);
    }

    #[test]
    fn test_chacha_ballast() {
        let key = [0x42u8; 32];
        let (data, blen) = chacha_ballast(&key, 1, 4);
        assert!(blen <= 63);
        // ballast should be deterministic
        let (data2, blen2) = chacha_ballast(&key, 1, 4);
        assert_eq!(blen, blen2);
        assert_eq!(data, data2);
    }
}
