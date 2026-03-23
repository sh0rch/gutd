use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SYSLOG_HEADER_LEN: usize = 41;

/// Writes a dynamic syslog header into the buffer.
/// Always writes exactly 41 bytes.
#[inline]
pub fn write_header(buf: &mut [u8]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sec = now % 60;
    let min = (now / 60) % 60;
    let hour = (now / 3600) % 24;

    // Civil date from days since 1970-01-01 (Howard Hinnant algorithm)
    let z = (now / 86400) as u32 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }

    // Format: "<165>1 YYYY-MM-DDTHH:MM:SSZ nginx - - -  "
    // Length: exactly 41 bytes
    let _ = write!(
        &mut buf[0..41],
        "<165>1 {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z nginx - - -  ",
        y,
        m,
        d,
        hour,
        min,
        sec
    );
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
