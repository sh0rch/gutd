//! SHA-256 + HMAC-SHA256 + HKDF-SHA256 — zero external dependencies.
//!
//! Provides `derive_key(passphrase) -> [u8; 32]` for passphrase-based
//! key derivation via HKDF-SHA256 (RFC 5869).
//!
//! Reference: FIPS 180-4 (SHA-256), RFC 2104 (HMAC), RFC 5869 (HKDF)

// ──── SHA-256 (FIPS 180-4) ──────────────────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            h: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buf_len > 0 {
            let fill = 64 - self.buf_len;
            let take = data.len().min(fill);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset = take;
            if self.buf_len == 64 {
                let block = self.buf;
                compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            compress(&mut self.h, &block);
            offset += 64;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = (self.total_len * 8).to_be_bytes();
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for i in self.buf_len..64 {
                self.buf[i] = 0;
            }
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf_len = 0;
        }

        for i in self.buf_len..56 {
            self.buf[i] = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len);
        let block = self.buf;
        compress(&mut self.h, &block);

        let mut out = [0u8; 32];
        for (i, &word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// ──── HMAC-SHA256 (RFC 2104) ────────────────────────────────────────

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = sha256(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ──── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────

pub fn hkdf_extract(salt: &[u8], ikm: &[u8], prk: &mut [u8; 32]) {
    *prk = hmac_sha256(salt, ikm);
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    let n = okm.len().div_ceil(32);
    let mut t = [0u8; 32];
    let mut t_len: usize = 0;
    let mut offset = 0;
    // Max msg size: 32 (prev T) + info + 1 (counter byte)
    let mut msg = [0u8; 256];

    for i in 1..=n {
        let msg_len = t_len + info.len() + 1;
        assert!(msg_len <= msg.len());
        msg[..t_len].copy_from_slice(&t[..t_len]);
        msg[t_len..t_len + info.len()].copy_from_slice(info);
        msg[t_len + info.len()] = i as u8;
        t = hmac_sha256(prk, &msg[..msg_len]);
        t_len = 32;

        let copy_len = (okm.len() - offset).min(32);
        okm[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
    }
}

pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], okm: &mut [u8]) {
    // Max info: 2 (length) + 1 (label_len) + 6 ("tls13 ") + label + 1 (ctx_len) + context
    let mut info = [0u8; 256];
    let mut pos = 0;
    let length = okm.len() as u16;
    info[pos..pos + 2].copy_from_slice(&length.to_be_bytes());
    pos += 2;
    let full_label_len = 6 + label.len();
    info[pos] = full_label_len as u8;
    pos += 1;
    info[pos..pos + 6].copy_from_slice(b"tls13 ");
    pos += 6;
    info[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    info[pos] = context.len() as u8;
    pos += 1;
    info[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();
    hkdf_expand(secret, &info[..pos], okm);
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut prk = [0u8; 32];
    hkdf_extract(salt, ikm, &mut prk);
    hkdf_expand(&prk, info, okm);
}

// ──── AES-128 (FIPS 197) ───────────────────────────────────────────
// Minimal AES-128 core for Header Protection.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

pub fn aes128_expand_key(key: &[u8; 16]) -> [u32; 44] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    let rcon = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        0x80000000, 0x1b000000, 0x36000000,
    ];
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = sub_word(rot_word(temp)) ^ rcon[i / 4 - 1];
        }
        w[i] = w[i - 4] ^ temp;
    }
    w
}

fn mix_columns(s: &mut [u32; 4]) {
    for col_val in s.iter_mut() {
        let col = col_val.to_be_bytes();
        let a = col[0];
        let b = col[1];
        let c = col[2];
        let d = col[3];
        let h = |x: u8| {
            if (x & 0x80) != 0 {
                (x << 1) ^ 0x1b
            } else {
                x << 1
            }
        };
        *col_val = u32::from_be_bytes([
            h(a) ^ (h(b) ^ b) ^ c ^ d,
            a ^ h(b) ^ (h(c) ^ c) ^ d,
            a ^ b ^ h(c) ^ (h(d) ^ d),
            (h(a) ^ a) ^ b ^ c ^ h(d),
        ]);
    }
}

pub fn aes128_encrypt_block(round_keys: &[u32; 44], block: &[u8; 16], out: &mut [u8; 16]) {
    let mut s = [0u32; 4];
    for (i, v) in s.iter_mut().take(4).enumerate() {
        *v = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
        *v ^= round_keys[i];
    }

    fn state_bytes(s: &[u32; 4]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&s[0].to_be_bytes());
        b[4..8].copy_from_slice(&s[1].to_be_bytes());
        b[8..12].copy_from_slice(&s[2].to_be_bytes());
        b[12..16].copy_from_slice(&s[3].to_be_bytes());
        b
    }

    for r in 1..10 {
        // SubBytes + ShiftRows
        let mut ns = [0u32; 4];
        let bytes = state_bytes(&s);
        let sb = |idx: usize| SBOX[bytes[idx] as usize];
        ns[0] = u32::from_be_bytes([sb(0), sb(5), sb(10), sb(15)]);
        ns[1] = u32::from_be_bytes([sb(4), sb(9), sb(14), sb(3)]);
        ns[2] = u32::from_be_bytes([sb(8), sb(13), sb(2), sb(7)]);
        ns[3] = u32::from_be_bytes([sb(12), sb(1), sb(6), sb(11)]);

        if r < 10 {
            mix_columns(&mut ns);
        }
        for i in 0..4 {
            s[i] = ns[i] ^ round_keys[r * 4 + i];
        }
    }
    // Final round (no mix columns)
    let mut ns = [0u32; 4];
    let bytes = state_bytes(&s);
    let sb = |idx: usize| SBOX[bytes[idx] as usize];
    ns[0] = u32::from_be_bytes([sb(0), sb(5), sb(10), sb(15)]);
    ns[1] = u32::from_be_bytes([sb(4), sb(9), sb(14), sb(3)]);
    ns[2] = u32::from_be_bytes([sb(8), sb(13), sb(2), sb(7)]);
    ns[3] = u32::from_be_bytes([sb(12), sb(1), sb(6), sb(11)]);
    for i in 0..4 {
        let final_w = ns[i] ^ round_keys[40 + i];
        out[4 * i..4 * i + 4].copy_from_slice(&final_w.to_be_bytes());
    }
}

// ──── AES-128-GCM (RFC 5116 / NIST SP 800-38D) ────────────────────

/// Multiply two 128-bit blocks in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1.
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let carry = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if carry == 1 {
            v[0] ^= 0xE1;
        }
    }
    z
}

/// Compute GHASH(H, aad, ciphertext) for AES-GCM.
fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];

    // Process AAD blocks (zero-padded to 16-byte boundary)
    let aad_blocks = aad.len().div_ceil(16);
    for i in 0..aad_blocks {
        let start = i * 16;
        let end = (start + 16).min(aad.len());
        let mut block = [0u8; 16];
        block[..end - start].copy_from_slice(&aad[start..end]);
        for j in 0..16 {
            x[j] ^= block[j];
        }
        x = gf128_mul(&x, h);
    }

    // Process ciphertext blocks (zero-padded to 16-byte boundary)
    let ct_blocks = ct.len().div_ceil(16);
    for i in 0..ct_blocks {
        let start = i * 16;
        let end = (start + 16).min(ct.len());
        let mut block = [0u8; 16];
        block[..end - start].copy_from_slice(&ct[start..end]);
        for j in 0..16 {
            x[j] ^= block[j];
        }
        x = gf128_mul(&x, h);
    }

    // Length block: len(A) in bits (8 bytes BE) || len(C) in bits (8 bytes BE)
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ct.len() as u64) * 8;
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    for j in 0..16 {
        x[j] ^= len_block[j];
    }
    gf128_mul(&x, h)
}

/// AES-128-GCM encrypt. Writes ciphertext (same length as plaintext) and 16-byte tag.
pub fn aes128_gcm_encrypt(
    rk: &[u32; 44],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) {
    assert_eq!(ciphertext.len(), plaintext.len());

    // H = AES_K(0^128)
    let mut h = [0u8; 16];
    let zero = [0u8; 16];
    aes128_encrypt_block(rk, &zero, &mut h);

    // J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Encrypt plaintext with counter starting at J0+1 (= nonce || 0x00000002)
    let n_blocks = plaintext.len().div_ceil(16);
    for i in 0..n_blocks {
        let counter = (i as u32 + 2).to_be_bytes();
        let mut ctr_block = [0u8; 16];
        ctr_block[..12].copy_from_slice(nonce);
        ctr_block[12..16].copy_from_slice(&counter);
        let mut ks = [0u8; 16];
        aes128_encrypt_block(rk, &ctr_block, &mut ks);
        let start = i * 16;
        let end = (start + 16).min(plaintext.len());
        for j in start..end {
            ciphertext[j] = plaintext[j] ^ ks[j - start];
        }
    }

    // GHASH(H, AAD, ciphertext)
    let ghash_result = ghash(&h, aad, ciphertext);

    // Tag = AES_K(J0) XOR GHASH
    let mut enc_j0 = [0u8; 16];
    aes128_encrypt_block(rk, &j0, &mut enc_j0);
    for i in 0..16 {
        tag[i] = enc_j0[i] ^ ghash_result[i];
    }
}

// ──── Public API ────────────────────────────────────────────────────

const HKDF_SALT: &[u8] = b"gutd-v1";
const HKDF_INFO: &[u8] = b"gutd-chacha-key";

/// Derive a 32-byte ChaCha key from a passphrase via HKDF-SHA256.
pub fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut okm = [0u8; 32];
    hkdf_sha256(HKDF_SALT, passphrase.as_bytes(), HKDF_INFO, &mut okm);
    okm
}

/// Format a 32-byte key as a 64-char hex string.
pub fn key_to_hex(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in key {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let h = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(key_to_hex(&h), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(key_to_hex(&h), expected);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let k1 = derive_key("test-passphrase");
        let k2 = derive_key("test-passphrase");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_different() {
        let k1 = derive_key("password-one");
        let k2 = derive_key("password-two");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_key_to_hex() {
        let key = [0u8; 32];
        assert_eq!(key_to_hex(&key).len(), 64);
        assert_eq!(
            key_to_hex(&key),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
