use std::time::{SystemTime, UNIX_EPOCH};

pub const SYSLOG_HEADER_LEN: usize = 41;

/// Writes a dynamic syslog header into the buffer.
/// Always writes exactly 41 bytes.
#[inline]
pub fn write_header(buf: &mut [u8]) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let sec = now % 60;
    let min = (now / 60) % 60;
    let hour = (now / 3600) % 24;

    // Format: "<165>1 2026-03-16T15:00:00Z nginx - - -  "
    // Length: exactly 41 bytes
    buf[0..18].copy_from_slice(b"<165>1 2026-03-16T");
    
    buf[18] = b'0' + (hour / 10) as u8;
    buf[19] = b'0' + (hour % 10) as u8;
    buf[20] = b':';
    
    buf[21] = b'0' + (min / 10) as u8;
    buf[22] = b'0' + (min % 10) as u8;
    buf[23] = b':';
    
    buf[24] = b'0' + (sec / 10) as u8;
    buf[25] = b'0' + (sec % 10) as u8;
    
    buf[26..41].copy_from_slice(b"Z nginx - - -  ");
}

/// Checks if the buffer starts with the syslog header footprint.
#[inline]
pub fn check_header(buf: &[u8]) -> bool {
    if buf.len() < SYSLOG_HEADER_LEN {
        return false;
    }
    // minimal check for performance, we know our header starts with this 
    // ends with "Z nginx - - -  "
    &buf[0..7] == b"<165>1 " && &buf[26..41] == b"Z nginx - - -  "
}
