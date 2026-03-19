#![allow(clippy::write_with_newline)]
#![allow(clippy::format_in_format_args)]

use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

pub const MAX_SIP_HEADER_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipKind {
    Register,
    Message,
    Options,
    Response200,
    Response401,
    Response403,
}

// Packed date storage: bits 0-15: year, bits 16-19: month, bits 20-24: day, bits 25-27: weekday
static CACHED_DATE: AtomicU32 = AtomicU32::new(0);

/// Initialize or update the cached date. Should be called at startup and checked periodically.
#[allow(dead_code)]
pub fn update_cached_date() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let days_since_epoch = now / 86400;
    let weekday = ((days_since_epoch + 4) % 7) as u8; // 0=Mon, 6=Sun
    
    // Calculate calendar date
    let days = days_since_epoch as i64 + 719468;
    let era = (if days >= 0 { days } else { days - 146096 }) / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = (yoe as i32 + era as i32 * 400) as u16;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = if month <= 2 { year + 1 } else { year };
    
    // Pack: year(16) | month(4) | day(5) | weekday(3)
    let packed = (year as u32) | ((month as u32) << 16) | ((day as u32) << 20) | ((weekday as u32) << 25);
    CACHED_DATE.store(packed, Ordering::Relaxed);
}

/// Check if we need to update the date (called on packet processing)
#[inline]
#[allow(dead_code)]
pub fn check_and_update_date(current_time_us: u64) {
    let _current_day = (current_time_us / 1_000_000) / 86400;
    let packed = CACHED_DATE.load(Ordering::Relaxed);
    if packed == 0 {
        update_cached_date();
        return;
    }
    
    // Check if it's a new day
    let stored_year = (packed & 0xFFFF) as u16;
    let stored_month = ((packed >> 16) & 0xF) as u8;
    let stored_day = ((packed >> 20) & 0x1F) as u8;
    
    let now_secs = current_time_us / 1_000_000;
    let days_since_epoch = now_secs / 86400;
    let days = days_since_epoch as i64 + 719468;
    let era = (if days >= 0 { days } else { days - 146096 }) / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = (yoe as i32 + era as i32 * 400) as u16;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = if month <= 2 { year + 1 } else { year };
    
    if year != stored_year || month != stored_month || day != stored_day {
        update_cached_date();
    }
}

/// Format Date header using cached date + current time
#[allow(dead_code)]
fn format_date_header(time_us: u64) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    
    let packed = CACHED_DATE.load(Ordering::Relaxed);
    let year = (packed & 0xFFFF) as u16;
    let month = ((packed >> 16) & 0xF) as usize;
    let day = ((packed >> 20) & 0x1F) as u8;
    let weekday = ((packed >> 25) & 0x7) as usize;
    
    let secs_today = (time_us / 1_000_000) % 86400;
    let hour = (secs_today / 3600) as u8;
    let minute = ((secs_today % 3600) / 60) as u8;
    let second = (secs_today % 60) as u8;
    
    format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday], day, MONTHS[month - 1], year, hour, minute, second)
}

pub fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n").map(|p| p + 4)
}

/// Checks if the buffer starts with a generic SIP footprint and returns the header length.
#[inline]
pub fn check_header(buf: &[u8]) -> Option<usize> {
    if buf.len() < 16 {
        return None;
    }
    let starts_valid = buf.starts_with(b"INVITE ") || 
                       buf.starts_with(b"REGISTER ") ||
                       buf.starts_with(b"MESSAGE ") ||
                       buf.starts_with(b"OPTIONS ") ||
                       buf.starts_with(b"SIP/2.0 ");
                       
    if !starts_valid {
        return None;
    }
    
    let hl = find_crlf_crlf(buf)?;
    let marker = b"a=fmtp:0 ";
    if let Some(pos) = buf[hl..].windows(marker.len()).position(|w| w == marker) {
        return Some(hl + pos + marker.len());
    }
    
    Some(hl)
}

/// Parses numeric value from SIP Date header by concatenating all digits
/// Format: "Date: Mon, 17 Mar 2026 15:23:45.123456 GMT"
/// Result: 172026152345123456 (day+year+hour+min+sec+microsec, no month)
/// This is NOT cryptographic - just a fast maskquerade identifier
pub fn parse_timestamp_from_date_header(buf: &[u8]) -> Option<u64> {
    // Find "Date: " header
    let date_marker = b"Date: ";
    let date_pos = buf.windows(date_marker.len()).position(|w| w == date_marker)?;
    let date_start = date_pos + date_marker.len();
    
    // Find end of line
    let date_end = buf[date_start..].windows(2).position(|w| w == b"\r\n")? + date_start;
    let date_line = &buf[date_start..date_end];
    
    // Extract all digits and concatenate them
    let mut result = 0u64;
    for &byte in date_line {
        if byte.is_ascii_digit() {
            result = result.saturating_mul(10).saturating_add((byte - b'0') as u64);
        }
    }
    
    Some(result)
}

/// Generates authentication token using Feistel cipher from timestamp (microseconds)
/// Uses 100ms granularity for efficiency while maintaining tight security
#[inline]
fn generate_auth_token(timestamp_us: u64, feistel_key: &[u32; 4]) -> u32 {
    // Round to 100ms granularity (100,000 microseconds)
    // This gives 10 unique tokens per second, tight enough for security
    let ts_100ms = (timestamp_us / 100_000) as u32;
    crate::proto::feistel::feistel32(ts_100ms, feistel_key)
}

/// Fast hex encoding into buffer (8 chars for u32)
#[inline]
fn write_hex8(buf: &mut [u8], val: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    buf[0] = HEX[((val >> 28) & 0xF) as usize];
    buf[1] = HEX[((val >> 24) & 0xF) as usize];
    buf[2] = HEX[((val >> 20) & 0xF) as usize];
    buf[3] = HEX[((val >> 16) & 0xF) as usize];
    buf[4] = HEX[((val >> 12) & 0xF) as usize];
    buf[5] = HEX[((val >> 8) & 0xF) as usize];
    buf[6] = HEX[((val >> 4) & 0xF) as usize];
    buf[7] = HEX[(val & 0xF) as usize];
}

/// Verifies authentication token by extracting timestamp from the packet itself
/// The timestamp numeric value is in clear text in Date header, used as "salt"
/// packet_timestamp_value is the concatenated digits from Date header (not real epoch time)
pub fn verify_auth_token_from_timestamp(
    token_str: &str, 
    packet_timestamp_value: u64, 
    feistel_key: &[u32; 4]
) -> bool {
    if token_str.len() != 8 {
        return false;
    }
    
    let token = match u32::from_str_radix(token_str, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };
    
    // Calculate expected token from packet's timestamp value (concatenated digits)
    // Use 100ms granularity by dividing concatenated value by 10000
    let ts_100ms = (packet_timestamp_value / 10000) as u32;
    let expected_token = crate::proto::feistel::feistel32(ts_100ms, feistel_key);
    
    token == expected_token
}

/// Fast path for OPTIONS keepalive (NAT hole punching)
#[inline]
fn write_options_keepalive(
    buf: &mut [u8],
    src_ip: &str,
    sport: u16,
    dport: u16,
    domain: &str,
    feistel_key: &[u32; 4],
    date_str: &str,
) -> usize {
    let timestamp_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let auth_token = generate_auth_token(timestamp_us, feistel_key);
    let from_tag_val = crate::proto::feistel::feistel32(((timestamp_us / 1000) ^ sport as u64) as u32, feistel_key);
    
    let time_of_day_us = timestamp_us % 86_400_000_000;
    let hour = (time_of_day_us / 3_600_000_000) as u8;
    let minute = ((time_of_day_us % 3_600_000_000) / 60_000_000) as u8;
    let second = ((time_of_day_us % 60_000_000) / 1_000_000) as u8;
    let microsecond = (time_of_day_us % 1_000_000) as u32;
    
    let mut cursor = std::io::Cursor::new(buf);
    write!(cursor, "OPTIONS sip:{}@{}:{} SIP/2.0\r\nVia: SIP/2.0/UDP {}:{};branch=z9hG4bK-", 
        dport, domain, dport, src_ip, sport).unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], auth_token);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "\r\nMax-Forwards: 70\r\nFrom: <sip:{}@{}>;tag=", sport, domain).unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], from_tag_val);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "\r\nTo: <sip:{}@{}>\r\nCall-ID: ", dport, domain).unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], auth_token);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "@{}\r\nCSeq: {} OPTIONS\r\nDate: {} {:02}:{:02}:{:02}.{:06} GMT\r\nContact: <sip:{}@{}:{}>\r\nUser-Agent: Asterisk PBX 16.2.0\r\nContent-Length: 0\r\n\r\n",
        domain, ((timestamp_us / 1000) % 1000) + 1, date_str, hour, minute, second, microsecond, sport, src_ip, sport).unwrap();
    cursor.position() as usize
}

/// Writes a dynamic SIP header into the buffer with real data.
/// Returns the number of bytes written.
#[allow(clippy::too_many_arguments)]
pub fn write_header(
    buf: &mut [u8],
    kind: SipKind,
    domain: &str,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
    rtp_port: u16,
    payload_len: usize,
    feistel_key: &[u32; 4],
    date_str: &str, // Pre-formatted date string (e.g., "Mon, 17 Mar 2026")
) -> usize {
    // Fast path for OPTIONS keepalive (empty payload, very frequent)
    if matches!(kind, SipKind::Options) && payload_len == 0 {
        return write_options_keepalive(buf, src_ip, sport, dport, domain, feistel_key, date_str);
    }
    
    let mut cursor = std::io::Cursor::new(buf);
    
    // Generate timestamp-based authentication (microseconds for Feistel)
    let timestamp_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let auth_token = generate_auth_token(timestamp_us, feistel_key);
    
    // Generate dynamic identifiers
    let session_id = timestamp_us / 1000; // milliseconds for session ID
    let from_tag_val = crate::proto::feistel::feistel32(((timestamp_us / 1000) ^ sport as u64) as u32, feistel_key);
    let to_tag_val = crate::proto::feistel::feistel32(((timestamp_us / 1000) ^ dport as u64) as u32, feistel_key);

    match kind {
        SipKind::Register => {
            write!(cursor, "REGISTER sip:{} SIP/2.0\r\n", domain).unwrap();
        },
        SipKind::Message => {
            write!(cursor, "MESSAGE sip:{}@{}:{} SIP/2.0\r\n", dport, domain, dport).unwrap();
        },
        SipKind::Options => {
            write!(cursor, "OPTIONS sip:{}@{}:{} SIP/2.0\r\n", dport, domain, dport).unwrap();
        },
        SipKind::Response200 => {
            write!(cursor, "SIP/2.0 200 OK\r\n").unwrap();
        },
        SipKind::Response401 => {
            write!(cursor, "SIP/2.0 401 Unauthorized\r\n").unwrap();
            let nonce_val = crate::proto::feistel::feistel32((timestamp_us / 1000) as u32, feistel_key);
            write!(cursor, "WWW-Authenticate: Digest realm=\"{}\", nonce=\"", domain).unwrap();
            let pos = cursor.position() as usize;
            write_hex8(&mut cursor.get_mut()[pos..pos+8], nonce_val);
            cursor.set_position(pos as u64 + 8);
            write!(cursor, "\", algorithm=MD5\r\n").unwrap();
        }
        SipKind::Response403 => {
            write!(cursor, "SIP/2.0 403 Forbidden\r\n").unwrap();
        }
    }

    write!(cursor, "Via: SIP/2.0/UDP {}:{};branch=z9hG4bK-", src_ip, sport).unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], auth_token);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "\r\nMax-Forwards: 70\r\nFrom: <sip:{}@{}>;tag=", sport, domain).unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], from_tag_val);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "\r\nTo: <sip:{}@{}>", dport, domain).unwrap();
    
    if matches!(kind, SipKind::Response200 | SipKind::Response401 | SipKind::Response403) {
        write!(cursor, ";tag=").unwrap();
        let pos = cursor.position() as usize;
        write_hex8(&mut cursor.get_mut()[pos..pos+8], to_tag_val);
        cursor.set_position(pos as u64 + 8);
        write!(cursor, "\r\n").unwrap();
    } else {
        write!(cursor, "\r\n").unwrap();
    }
    
    write!(cursor, "Call-ID: ").unwrap();
    let pos = cursor.position() as usize;
    write_hex8(&mut cursor.get_mut()[pos..pos+8], auth_token);
    cursor.set_position(pos as u64 + 8);
    write!(cursor, "@{}\r\n", domain).unwrap();
    
    let cseq_method = match kind {
        SipKind::Register | SipKind::Response401 => "REGISTER",
        SipKind::Response200 => "OPTIONS",
        SipKind::Response403 => "INVITE",
        SipKind::Message => "MESSAGE",
        SipKind::Options => "OPTIONS",
    };
    write!(cursor, "CSeq: {} {}\r\n", ((timestamp_us / 1000) % 1000) + 1, cseq_method).unwrap();
    
    // Add Date header: date_str + time (HH:MM:SS.uuuuuu GMT) with microseconds for Feistel verification
    let time_of_day_us = timestamp_us % 86_400_000_000;
    let hour = time_of_day_us / 3_600_000_000;
    let minute = (time_of_day_us % 3_600_000_000) / 60_000_000;
    let second = (time_of_day_us % 60_000_000) / 1_000_000;
    let microsecond = time_of_day_us % 1_000_000;
    write!(cursor, "Date: {} {:02}:{:02}:{:02}.{:06} GMT\r\n", date_str, hour, minute, second, microsecond).unwrap();
    
    write!(cursor, "Contact: <sip:{}@{}:{}>\r\n", sport, src_ip, sport).unwrap();
    write!(cursor, "User-Agent: Asterisk PBX 16.2.0\r\n").unwrap();
    
    if payload_len > 0 {
        let sdp_preamble = format!(
            "v=0\r\no=- {} {} IN IP4 {}\r\ns=SIP Call\r\nc=IN IP4 {}\r\nt=0 0\r\nm=audio {} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=ptime:20\r\na=sendrecv\r\na=fmtp:0 ",
            session_id, session_id, src_ip, dst_ip, rtp_port
        );
        write!(cursor, "Content-Type: application/sdp\r\n").unwrap();
        write!(cursor, "Content-Length: {}\r\n\r\n{}", sdp_preamble.len() + payload_len, sdp_preamble).unwrap();
    } else {
        write!(cursor, "Content-Length: 0\r\n\r\n").unwrap();
    }

    cursor.position() as usize
}

pub const RTP_HEADER_LEN: usize = 12;

#[inline]
pub fn check_rtp_header(buf: &[u8]) -> bool {
    if buf.len() < RTP_HEADER_LEN {
        return false;
    }
    (buf[0] & 0xC0) == 0x80 && (buf[1] & 0x7F) == 0x60
}

pub fn write_rtp_header(buf: &mut [u8], seq: u16, ts: u32, ssrc: u32) -> usize {
    buf[0] = 0x80;
    buf[1] = 0x60;
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    buf[4..8].copy_from_slice(&ts.to_be_bytes());
    buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
    RTP_HEADER_LEN
}
