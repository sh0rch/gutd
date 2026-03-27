pub const FEISTEL_SALT_PORTS: u32 = 0xB7E15163;

/// Fast pseudo-random hash for auth tokens (not reversible like Feistel)
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

#[inline(always)]
pub fn feistel32(x: u32, rk: &[u32; 4]) -> u32 {
    let mut lo = (x & 0xFFFF) as u16;
    let mut hi = (x >> 16) as u16;

    for &k in rk {
        let f = ((lo as u32).wrapping_mul(0x9E37).wrapping_add(k))
            ^ ((lo as u32) << 3)
            ^ ((lo as u32) >> 5);
        let new_lo = hi ^ (f & 0xFFFF) as u16;
        hi = lo;
        lo = new_lo;
    }

    ((hi as u32) << 16) | (lo as u32)
}

#[inline(always)]
pub fn feistel32_inv(x: u32, rk: &[u32; 4]) -> u32 {
    let mut lo = (x & 0xFFFF) as u16;
    let mut hi = (x >> 16) as u16;

    for i in (0..4).rev() {
        let lo_old = hi;
        let f = ((hi as u32).wrapping_mul(0x9E37).wrapping_add(rk[i]))
            ^ ((hi as u32) << 3)
            ^ ((hi as u32) >> 5);
        let hi_old = lo ^ (f & 0xFFFF) as u16;
        lo = lo_old;
        hi = hi_old;
    }

    ((hi as u32) << 16) | (lo as u32)
}
