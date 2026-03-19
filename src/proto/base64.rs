pub const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn build_decode_table() -> [u8; 256] {
    let mut table = [0xFF; 256];
    let mut i = 0;
    while i < 64 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table[b'=' as usize] = 0;
    table
}

static DECODE_TABLE: [u8; 256] = build_decode_table();

/// Encodes data into pure Base64. Returns number of bytes written.
pub fn encode(input: &[u8], output: &mut [u8]) -> usize {
    let mut i = 0;
    let mut o = 0;
    let len = input.len();

    while i < len {
        let b0 = input[i];
        let b1 = if i + 1 < len { input[i + 1] } else { 0 };
        let b2 = if i + 2 < len { input[i + 2] } else { 0 };

        output[o] = ALPHABET[(b0 >> 2) as usize];
        output[o + 1] = ALPHABET[(((b0 & 0x3) << 4) | (b1 >> 4)) as usize];
        
        if i + 1 < len {
            output[o + 2] = ALPHABET[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize];
        } else {
            output[o + 2] = b'=';
        }
        
        if i + 2 < len {
            output[o + 3] = ALPHABET[(b2 & 0x3F) as usize];
        } else {
            output[o + 3] = b'=';
        }

        i += 3;
        o += 4;
    }
    o
}

/// Decodes Base64 data. Returns number of bytes written or None on invalid input.
pub fn decode(input: &[u8], output: &mut [u8]) -> Option<usize> {
    if !input.len().is_multiple_of(4) {
        return None;
    }

    let mut i = 0;
    let mut o = 0;
    let len = input.len();

    while i < len {
        let v0 = DECODE_TABLE[input[i] as usize];
        let v1 = DECODE_TABLE[input[i + 1] as usize];
        let v2 = DECODE_TABLE[input[i + 2] as usize];
        let v3 = DECODE_TABLE[input[i + 3] as usize];

        if v0 == 0xFF || v1 == 0xFF || v2 == 0xFF || v3 == 0xFF {
            return None; // Invalid base64 character
        }

        output[o] = (v0 << 2) | (v1 >> 4);
        let mut written = 1;
        
        if input[i + 2] != b'=' {
            output[o + 1] = (v1 << 4) | (v2 >> 2);
            written += 1;
        }
        if input[i + 3] != b'=' {
            output[o + 2] = (v2 << 6) | v3;
            written += 1;
        }
        o += written;
        i += 4;
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let input = b"Hello, World, 12345! ";
        let mut enc = [0u8; 100];
        let mut dec = [0u8; 100];
        let n = encode(input, &mut enc);
        let m = decode(&enc[..n], &mut dec).unwrap();
        assert_eq!(&input[..], &dec[..m]);
    }
}
