pub const GUT_QUIC_SHORT_HEADER_SIZE: usize = 16;
pub const GUT_QUIC_LONG_HEADER_SIZE: usize = 1200;

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

pub fn derive_quic_initial_secret(dcid: &[u8]) -> [u8; 32] {
    let mut initial_secret = [0u8; 32];
    crate::crypto::hkdf_extract(&QUIC_V1_SALT, dcid, &mut initial_secret);
    initial_secret
}

pub fn derive_client_initial_secret(initial_secret: &[u8; 32]) -> [u8; 32] {
    let mut client_initial_secret = [0u8; 32];
    let label = b"client in";
    crate::crypto::hkdf_expand_label(initial_secret, label, &[], &mut client_initial_secret);
    client_initial_secret
}

pub fn derive_server_initial_secret(initial_secret: &[u8; 32]) -> [u8; 32] {
    let mut server_initial_secret = [0u8; 32];
    let label = b"server in";
    crate::crypto::hkdf_expand_label(initial_secret, label, &[], &mut server_initial_secret);
    server_initial_secret
}

pub fn derive_quic_keys(secret: &[u8; 32]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    crate::crypto::hkdf_expand_label(secret, b"quic key", &[], &mut key);
    crate::crypto::hkdf_expand_label(secret, b"quic iv", &[], &mut iv);
    crate::crypto::hkdf_expand_label(secret, b"quic hp", &[], &mut hp);
    (key, iv, hp)
}
