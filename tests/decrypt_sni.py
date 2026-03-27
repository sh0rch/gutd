import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import subprocess

# This pulls the raw bytes of packet #4 (the first Long Header packet) and strips the UDP/IP headers (42 bytes)
pcap_hex = subprocess.check_output(["sudo", "tshark", "-r", "/tmp/gutd_ndpi.pcap", "-Y", "frame.number == 1", "-x"]).decode()
lines = pcap_hex.split('\n')
hex_str = ""
for line in lines:
    if line.startswith('0'):
        # Extract the hex part, which is between the offset and the ascii dump
        parts = line.split('  ')
        if len(parts) >= 2:
            hex_str += parts[1].replace(' ', '')
        elif ' ' in line:
            hex_str += (line[6:53]).replace(' ', '')


pkt = bytes.fromhex(hex_str)[42:] # Skip 42 bytes: 14 eth + 20 IP + 8 UDP

QUIC_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 §5.2

def hkdf_extract(salt, ikm):
    import hmac, hashlib
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand_label(secret, label, context, length):
    label_bytes = b"tls13 " + label
    hkdf_label = struct.pack("!HB", length, len(label_bytes)) + label_bytes + struct.pack("!B", len(context)) + context
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label)
    return hkdf.derive(secret)

print(f"Total QUIC payload length: {len(pkt)}")

# 1 byte Header
# 4 bytes Version
# 1 byte DCID Len
dcid_len = pkt[5]
dcid = pkt[6:6+dcid_len]
print(f"Extracted DCID: {dcid.hex()}")

initial_secret = hkdf_extract(QUIC_SALT, dcid)
client_secret = hkdf_expand_label(initial_secret, b"client in", b"", 32)

key = hkdf_expand_label(client_secret, b"quic key", b"", 16)
iv = hkdf_expand_label(client_secret, b"quic iv", b"", 12)
hp_key = hkdf_expand_label(client_secret, b"quic hp", b"", 16)

scid_len = pkt[6+dcid_len]
offset = 6 + dcid_len + 1 + scid_len

# Token len
token_len = pkt[offset]
print(f"token_len_byte_offset={offset}, token_len={token_len}")
offset += 1 + token_len

# Length
plen = ((pkt[offset] & 0x3f) << 8) | pkt[offset+1]
print(f"length_offset={offset}, plen={plen}")
offset += 2

pn_offset = offset
print(f"pn_offset={pn_offset}")
sample_offset = pn_offset + 4
sample = pkt[sample_offset : sample_offset+16]

cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
encryptor = cipher.encryptor()
mask = encryptor.update(sample)

first_byte = pkt[0] ^ (mask[0] & 0x0f)
pn_len = (first_byte & 0x03) + 1
print(f"masked_first_byte=0x{pkt[0]:02x}, mask[0]=0x{mask[0]:02x}, first_byte=0x{first_byte:02x}, pn_len={pn_len}")

pn_bytes = bytearray(pkt[pn_offset : pn_offset+pn_len])
for i in range(pn_len):
    pn_bytes[i] ^= mask[1+i]

pn = int.from_bytes(pn_bytes, byteorder='big')
print(f"Unmasked PN: {pn}")

pn_padded = pn.to_bytes(12, byteorder='big')
nonce = bytes([a ^ b for a, b in zip(iv, pn_padded)])

# Build AAD from the unprotected header (first byte unmasked + rest of header up to payload)
aad_header = bytearray(pkt[:pn_offset + pn_len])
aad_header[0] = first_byte
for i in range(pn_len):
    aad_header[pn_offset + i] = pn_bytes[i]
# AAD is always 34 bytes in our implementation (up to and including 4-byte PN)
aad = bytes(aad_header[:pn_offset + 4])

payload_offset = pn_offset + pn_len
# Ciphertext = 128 bytes, Tag = 16 bytes
ct = pkt[payload_offset : payload_offset+128]
tag = pkt[payload_offset+128 : payload_offset+128+16]

print(f"\nAAD ({len(aad)} bytes): {aad.hex()}")
print(f"Nonce: {nonce.hex()}")
print(f"CT ({len(ct)} bytes): {ct[:32].hex()}...")
print(f"Tag ({len(tag)} bytes): {tag.hex()}")

# Try GCM decryption with tag verification
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct + tag, aad)
    print(f"\n[GCM] Tag verified OK!")
    print(f"Decrypted payload (hex): {plaintext.hex()}")
    # Search for SNI
    sni_domain = b"discord.com"
    if sni_domain in plaintext:
        print(f"\n=> SUCCESS! '{sni_domain.decode()}' found in decrypted ClientHello!")
    else:
        # Try to find any readable text
        printable = bytes([b if 32 <= b < 127 else ord('.') for b in plaintext])
        print(f"Printable: {printable.decode()}")
        print(f"\n=> WARNING: SNI '{sni_domain.decode()}' not found in payload")
except Exception as e:
    print(f"\n[GCM] Tag verification FAILED: {e}")
    # Fall back to CTR to see what's there
    cipher_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00\x00\x00\x02"))
    decryptor = cipher_ctr.decryptor()
    decrypted = decryptor.update(ct)
    print(f"[CTR fallback] Decrypted: {decrypted[:64].hex()}...")
    printable = bytes([b if 32 <= b < 127 else ord('.') for b in decrypted])
    print(f"Printable: {printable.decode()}")

