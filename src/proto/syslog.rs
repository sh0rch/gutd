use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SYSLOG_HDR_BASE: usize = 36;

/// Returns header length for a given service name.
#[inline]
pub fn header_len(service_name: &str) -> usize {
    SYSLOG_HDR_BASE + service_name.len()
}

/// Writes a dynamic syslog header into the buffer.
/// Returns the number of bytes written = 36 + service_name.len().
#[inline]
pub fn write_header(buf: &mut [u8], service_name: &str) -> usize {
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

    // Format: "<165>1 YYYY-MM-DDTHH:MM:SSZ <name> - - -  "
    let hlen = SYSLOG_HDR_BASE + service_name.len();
    let _ = write!(
        &mut buf[0..hlen],
        "<165>1 {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z {} - - -  ",
        y,
        m,
        d,
        hour,
        min,
        sec,
        service_name,
    );
    hlen
}

/// Checks if the buffer starts with the syslog header footprint.
/// Scans for " - - -  " marker to handle variable-length service names.
/// Returns Some(header_len) on success, None on failure.
#[inline]
pub fn check_header(buf: &[u8]) -> Option<usize> {
    if buf.len() < SYSLOG_HDR_BASE {
        return None;
    }
    if &buf[0..7] != b"<165>1 " {
        return None;
    }
    // Scan for " - - -  " marker starting at position 28
    let end = buf.len().min(68);
    for i in 28..end.saturating_sub(7) {
        if &buf[i..i + 8] == b" - - -  " {
            return Some(i + 8);
        }
    }
    None
}
