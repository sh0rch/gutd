#!/usr/bin/env python3
"""                                                                              
Decrypt and verify a gutd QUIC Long Header packet from a pcap.

Usage:
    sudo python3 tests/decrypt_sni.py <gutd_key_hex> [pcap_file] [frame_number] [sni_domain]

    gutd_key_hex  — 64-hex-char shared key (same as `key = ...` in gutd.conf)
    pcap_file     — defaults to /tmp/gutd_ndpi.pcap
    frame_number  — tshark frame number to inspect (default: 1)
    sni_domain    — expected SNI string to search in decrypted ClientHello

Protocol notes (Long Header layout):
  [0]        Header byte (0xC3 = Initial / 0xF3 = Cookie)
  [1..4]     QUIC version 0x00000001
  [5]        DCID length = 0x08
  [6..13]    DCID = fixed_dcid = ChaCha20(key, block=99, nonce=0)[0..8]  ← used for AEAD keys
  [14]       SCID length = 0x08
  [15..18]   PPN (plain-text, little-endian — read directly, no HP unmask needed)
  [19..22]   SCID2 (random, derived from wg_idx)
  [23]       Token length = 0x04
  [24..27]   enc_ports (little-endian)
  [28..29]   Payload length varint
  [30..33]   Packet number (HP-masked, big-endian)
  [34..]     AES-128-GCM ciphertext + 16-byte GCM tag

AEAD key derivation:
  fixed_dcid = ChaCha20(key, block=99, nonce=0)[0..8]  (same as DCID in header)
  → QUIC initial secret (RFC 9001 §5.2) → client secret → key / iv / hp
  → nDPI / Wireshark see the same DCID and can derive the same keys → SNI decrypts
"""

import sys
import struct
import subprocess
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── ChaCha20 block (RFC 7539) — for fixed_dcid derivation ────────────────────

def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = _rotl32(s[d],  8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = _rotl32(s[b],  7)

def chacha20_block(key_bytes: bytes, block_count: int, nonce: int, rounds: int = 4) -> list:
    """Return 16 u32 output words of a single ChaCha block (rounds=4 matches gutd default)."""
    assert len(key_bytes) == 32
    k = struct.unpack_from("<8I", key_bytes)
    # gutd chacha_init layout: [k0..k7, block_count, nonce, 0, 0]
    s = list(k) + [block_count & 0xFFFFFFFF, nonce & 0xFFFFFFFF, 0, 0]
    orig = s[:]
    for _ in range(rounds // 2):
        _quarter_round(s, 0, 4, 8, 12)
        _quarter_round(s, 1, 5, 9, 13)
        _quarter_round(s, 2, 6, 10, 14)
        _quarter_round(s, 3, 7, 11, 15)
        _quarter_round(s, 0, 5, 10, 15)
        _quarter_round(s, 1, 6, 11, 12)
        _quarter_round(s, 2, 7,  8, 13)
        _quarter_round(s, 3, 4,  9, 14)
    return [(s[i] + orig[i]) & 0xFFFFFFFF for i in range(16)]

def derive_fixed_dcid(key_hex: str) -> bytes:
    """Compute the stable DCID used for AEAD key derivation (ChaCha block 99, nonce 0)."""
    key_bytes = bytes.fromhex(key_hex)
    ks99 = chacha20_block(key_bytes, 99, 0)
    return struct.pack("<II", ks99[0], ks99[1])  # first 8 bytes, little-endian

# ── QUIC RFC 9001 key derivation ─────────────────────────────────────────────

QUIC_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 §5.2

def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand_label(secret, label, context, length):
    label_bytes = b"tls13 " + label
    hkdf_label = struct.pack("!HB", length, len(label_bytes)) + label_bytes + struct.pack("!B", len(context)) + context
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label)
    return hkdf.derive(secret)

def derive_quic_keys(fixed_dcid: bytes):
    initial_secret = hkdf_extract(QUIC_SALT, fixed_dcid)
    client_secret  = hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key    = hkdf_expand_label(client_secret, b"quic key", b"", 16)
    iv     = hkdf_expand_label(client_secret, b"quic iv",  b"", 12)
    hp_key = hkdf_expand_label(client_secret, b"quic hp",  b"", 16)
    return key, iv, hp_key

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    key_hex      = sys.argv[1]
    pcap_file    = sys.argv[2] if len(sys.argv) > 2 else "/tmp/gutd_ndpi.pcap"
    frame_number = sys.argv[3] if len(sys.argv) > 3 else "1"

    # ── Load packet from pcap ─────────────────────────────────────────────
    pcap_hex = subprocess.check_output([
        "sudo", "tshark", "-r", pcap_file,
        "-Y", f"frame.number == {frame_number}", "-x"
    ]).decode()

    hex_str = ""
    for line in pcap_hex.split('\n'):
        if line.startswith('0'):
            parts = line.split('  ')
            if len(parts) >= 2:
                hex_str += parts[1].replace(' ', '')
            elif ' ' in line:
                hex_str += (line[6:53]).replace(' ', '')

    pkt = bytes.fromhex(hex_str)[42:]  # Skip 14 eth + 20 IP + 8 UDP

    print(f"[*] Total QUIC payload: {len(pkt)} bytes")
    print(f"[*] Header byte: 0x{pkt[0]:02x}")

    # ── Parse Long Header fields ──────────────────────────────────────────
    dcid_len  = pkt[5]
    pkt_dcid  = pkt[6 : 6 + dcid_len]          # fixed_dcid — same value used for AEAD keys
    scid_len  = pkt[6 + dcid_len]
    scid_off  = 6 + dcid_len + 1
    scid      = pkt[scid_off : scid_off + scid_len]

    # PPN is stored unmasked at SCID[0..4] = pkt[15..18] (little-endian)
    # HP masking at pkt[30..33] is cosmetic only; ingress reads PPN from here.
    pkt_ppn_le = pkt[15:19]
    pkt_ppn = struct.unpack("<I", pkt_ppn_le)[0]

    token_off  = scid_off + scid_len
    token_len  = pkt[token_off]
    enc_ports  = struct.unpack("<I", pkt[token_off + 1 : token_off + 5])[0] if token_len >= 4 else 0

    plen_off   = token_off + 1 + token_len
    plen       = ((pkt[plen_off] & 0x3f) << 8) | pkt[plen_off + 1]
    pn_offset  = plen_off + 2   # always 30 in our implementation

    print(f"[*] DCID (fixed, key-derived): {pkt_dcid.hex()}  ← used for AEAD keys")
    print(f"[*] SCID raw: {scid.hex()}")
    print(f"[*] PPN (from SCID[0..4], unmasked): {pkt_ppn} (0x{pkt_ppn:08x})")
    print(f"[*] enc_ports (Token): 0x{enc_ports:08x}")
    print(f"[*] pn_offset={pn_offset}")

    # ── Derive AEAD keys from fixed_dcid (= DCID visible in packet) ──────
    fixed_dcid = derive_fixed_dcid(key_hex)
    print(f"[*] fixed_dcid (ChaCha block 99): {fixed_dcid.hex()}")
    if pkt_dcid[:8] == fixed_dcid:
        print(f"    ✓ Packet DCID matches fixed_dcid")
    else:
        print(f"    ✗ Packet DCID {pkt_dcid.hex()} ≠ fixed_dcid {fixed_dcid.hex()} (wrong key?)")

    q_key, q_iv, q_hp = derive_quic_keys(fixed_dcid)
    print(f"[*] QUIC key:    {q_key.hex()}")
    print(f"[*] QUIC IV:     {q_iv.hex()}")

    # ── HP unmask (cosmetic — verify pkt[30..33] packet number field) ────
    sample_offset = pn_offset + 4
    sample = pkt[sample_offset : sample_offset + 16]
    cipher = Cipher(algorithms.AES(q_hp), modes.ECB())
    mask = cipher.encryptor().update(sample)

    first_byte = pkt[0] ^ (mask[0] & 0x0f)
    pn_len = (first_byte & 0x03) + 1
    pn_bytes = bytearray(pkt[pn_offset : pn_offset + pn_len])
    for i in range(pn_len):
        pn_bytes[i] ^= mask[1 + i]
    pn_hp = int.from_bytes(pn_bytes, byteorder='big')
    print(f"[*] Packet number (HP-unmasked from [30..33]): {pn_hp}")
    if pn_hp == pkt_ppn:
        print(f"    ✓ HP-unmasked PN matches SCID PPN")
    else:
        print(f"    ✗ HP-unmasked PN {pn_hp} ≠ SCID PPN {pkt_ppn} (mismatch — normal if HP is cosmetic)")

    # ── AES-128-GCM decrypt ───────────────────────────────────────────────
    # Nonce: IV XOR left-padded PPN in big-endian (RFC 9001 §5.3)
    ppn_be = struct.pack(">I", pkt_ppn)
    nonce = bytearray(q_iv)
    for i in range(4):
        nonce[8 + i] ^= ppn_be[i]

    # AAD = header[0..30] with first byte and PN unmasked (RFC 9001 §5.3)
    aad_header = bytearray(pkt[:pn_offset + pn_len])
    aad_header[0] = first_byte
    for i in range(pn_len):
        aad_header[pn_offset + i] = pn_bytes[i]
    aad = bytes(aad_header[:pn_offset + 4])  # fixed 34 bytes in gutd

    payload_offset = pn_offset + pn_len
    sni_pos = 34   # gutd always writes payload starting at byte 34

    # Ciphertext + 16-byte GCM tag starting at sni_pos
    ct_with_tag = pkt[sni_pos:]
    ct_len = len(ct_with_tag) - 16
    if ct_len <= 0:
        print("[FAIL] Packet too short for GCM tag")
        sys.exit(1)
    ct  = ct_with_tag[:ct_len]
    tag = ct_with_tag[ct_len:]

    print(f"\n[*] AAD ({len(aad)} bytes): {aad.hex()}")
    print(f"[*] Nonce: {bytes(nonce).hex()}")
    print(f"[*] CT ({len(ct)} bytes): {ct[:32].hex()}...")
    print(f"[*] GCM tag: {tag.hex()}")

    # ── GCM decrypt ───────────────────────────────────────────────────────
    try:
        aesgcm = AESGCM(q_key)
        plaintext = aesgcm.decrypt(bytes(nonce), ct + tag, aad)
        print(f"\n[GCM] Tag verified OK!")
        print(f"Plaintext (hex): {plaintext.hex()}")

        # Search for SNI domain in the decrypted TLS ClientHello
        sni_domain_env = None
        for arg in sys.argv[4:]:
            sni_domain_env = arg.encode()
        targets = [sni_domain_env] if sni_domain_env else [b"discord.com", b"example.com"]
        found = False
        for t in targets:
            if t in plaintext:
                print(f"\n=> SUCCESS! '{t.decode()}' found in decrypted ClientHello!")
                found = True
                break
        if not found:
            printable = bytes([b if 32 <= b < 127 else ord('.') for b in plaintext])
            print(f"Printable: {printable.decode()}")
            print(f"\n=> WARNING: expected SNI not found in plaintext")

    except Exception as e:
        print(f"\n[GCM] Tag verification FAILED: {e}")
        print("      Possible causes: wrong key, packet corruption, mismatched fixed_dcid")
        sys.exit(1)


if __name__ == "__main__":
    main()

