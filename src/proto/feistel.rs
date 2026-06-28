/// Fast pseudo-random hash for auth tokens (MurmurHash3-like mixing)
#[inline(always)]
pub fn sip_hash32(x: u32, rk: &[u32; 4]) -> u32 {
    let mut h = x;
    h = h.wrapping_mul(0xcc9e2d51).wrapping_add(rk[0]);
    h = h.rotate_left(15);
    h = h.wrapping_mul(0x1b873593).wrapping_add(rk[1]);
    h = h.rotate_left(13);
    h = h.wrapping_mul(0xe6546b64).wrapping_add(rk[2]);
    h = h.rotate_left(10);
    h = h.wrapping_mul(0x85ebca6b).wrapping_add(rk[3]);
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}
