pub const GUT_QUIC_SHORT_HEADER_SIZE: usize = 14;
pub const GUT_QUIC_LONG_HEADER_SIZE: usize = 1200;

const QUIC_V1_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x47, 0x83, 0x20, 0x3d, 0x64, 0x22, 0x07,
    0xfd, 0x33, 0x8c, 0xc1,
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
