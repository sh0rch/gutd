pub const FEISTEL_SALT_PORTS: u32 = 0xB7E15163;

#[inline(always)]
pub fn feistel32(x: u32, rk: &[u32; 4]) -> u32 {
    let mut lo = (x & 0xFFFF) as u16;
    let mut hi = (x >> 16) as u16;

    for i in 0..4 {
        let f = ((lo as u32).wrapping_mul(0x9E37).wrapping_add(rk[i]))
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
