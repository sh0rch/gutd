#!/usr/bin/env python3
"""
QUIC Version Negotiation probe for gutd anti-probing (own_http3) test.

Sends a minimal QUIC Initial (Long Header) packet to the target host:port and
checks that the response is a valid QUIC Version Negotiation packet containing:
  - QUIC v2  (0x6b3343cf)
  - QUIC v1  (0x00000001)
  - DCID  == probe's SCID  (RFC 9000 §17.2.1)
  - SCID  == probe's DCID

Usage:
  sudo python3 tests/probe_quic.py <host> <port>
  sudo python3 tests/probe_quic.py 10.0.0.2 41000

Root/CAP_NET_RAW is required for raw UDP receive (SOCK_DGRAM is fine, no root
needed when not spoofing source — we bind a random local port and listen).
"""

import socket
import struct
import os
import sys
import time

# ── Build QUIC Initial (Long Header) ─────────────────────────────────────────
#
# Layout (RFC 9000 §17.2.2):
#   1 byte   Header Byte  = 0xC0 (Long Header + Initial type bits)
#   4 bytes  Version      = 0x00000001  (QUIC v1)
#   1 byte   DCID Len
#   n bytes  DCID
#   1 byte   SCID Len
#   m bytes  SCID
#   1 byte   Token Len    = 0
#   2 bytes  Length (varint) = payload length
#   payload  (zeros; pad to ≥1200 bytes per RFC 9000 §14.1)
#
# gut_common.h only checks:
#   - quic[0] & 0xC0 == 0xC0
#   - quic[5] (dcid_len) ≤ 20
#   - packet reachable up to quic[31]
# So a minimal synthetic Initial is enough.

DCID = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])  # 8 bytes
SCID = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])  # 8 bytes

def build_quic_initial() -> bytes:
    header_byte  = 0xC3          # Long Header | Fixed | Initial
    version      = 0x00000001   # QUIC v1
    token_len    = 0

    # Payload: just zeros → pad total packet to 1200 bytes
    # Header size: 1 + 4 + 1 + len(DCID) + 1 + len(SCID) + 1 + 2 = 18 + DCID + SCID
    hdr_before_payload = (
        struct.pack("!B", header_byte) +
        struct.pack("!I", version) +
        struct.pack("!B", len(DCID)) + DCID +
        struct.pack("!B", len(SCID)) + SCID +
        struct.pack("!B", token_len)       # token len
    )
    # payload length varint (2-byte form, bit6 set): 0x40 | high, low
    payload_size = max(0, 1200 - len(hdr_before_payload) - 2 - 4)  # -4 for PKN
    length_varint = struct.pack("!H", 0x4000 | (payload_size + 4))  # +4 for PKN
    pkt_num = struct.pack("!I", 1)
    payload = bytes(payload_size)

    return hdr_before_payload + length_varint + pkt_num + payload


# ── Parse Version Negotiation response ───────────────────────────────────────
#
# Layout (RFC 9000 §17.2.1):
#   1 byte   Header Byte  (bit7=1, others random)
#   4 bytes  Version      = 0x00000000
#   1 byte   DCID Len (= probe's SCID Len)
#   DCID bytes
#   1 byte   SCID Len (= probe's DCID Len)
#   SCID bytes
#   4+ bytes Supported versions (4 bytes each)

def parse_version_neg(data: bytes, probe_dcid: bytes, probe_scid: bytes):
    ok = True
    errors = []

    if len(data) < 7:
        return False, ["Response too short"]

    header_byte = data[0]
    if not (header_byte & 0x80):
        errors.append(f"Header byte 0x{header_byte:02x}: Long Header bit not set")
        ok = False

    version = struct.unpack("!I", data[1:5])[0]
    if version != 0:
        errors.append(f"Version field = 0x{version:08x}, expected 0x00000000 (Version Negotiation)")
        ok = False

    off = 5
    dcid_len = data[off]; off += 1
    resp_dcid = data[off:off+dcid_len]; off += dcid_len
    scid_len = data[off]; off += 1
    resp_scid = data[off:off+scid_len]; off += scid_len

    # RFC 9000 §17.2.1: VN.DCID = Initial.SCID, VN.SCID = Initial.DCID
    if resp_dcid != probe_scid:
        errors.append(f"Response DCID {resp_dcid.hex()} != probe SCID {probe_scid.hex()}")
        ok = False
    if resp_scid != probe_dcid:
        errors.append(f"Response SCID {resp_scid.hex()} != probe DCID {probe_dcid.hex()}")
        ok = False

    supported = []
    while off + 4 <= len(data):
        v = struct.unpack("!I", data[off:off+4])[0]
        supported.append(v)
        off += 4

    QUIC_V1 = 0x00000001
    QUIC_V2 = 0x6b3343cf

    if QUIC_V2 not in supported:
        errors.append(f"QUIC v2 (0x6b3343cf) missing from supported versions: {[hex(v) for v in supported]}")
        ok = False
    if QUIC_V1 not in supported:
        errors.append(f"QUIC v1 (0x00000001) missing from supported versions: {[hex(v) for v in supported]}")
        ok = False

    return ok, errors, supported


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <host> <port>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    pkt = build_quic_initial()
    print(f"[*] Sending QUIC Initial ({len(pkt)} bytes) to {host}:{port}")
    print(f"    DCID={DCID.hex()}  SCID={SCID.hex()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    sock.connect((host, port))
    sock.send(pkt)

    try:
        resp, addr = sock.recvfrom(4096)
    except socket.timeout:
        print("[FAIL] No response within 3 seconds.")
        print("       → Is gutd running with own_http3 = true, and is this the GUT port?")
        sys.exit(1)
    finally:
        sock.close()

    print(f"[*] Got {len(resp)} bytes from {addr}")

    result = parse_version_neg(resp, DCID, SCID)
    if len(result) == 3:
        ok, errors, supported = result
    else:
        ok, errors = result
        supported = []

    if ok:
        print(f"[OK] Valid QUIC Version Negotiation response.")
        print(f"     Supported versions: {[hex(v) for v in supported]}")
    else:
        print("[FAIL] Response validation failed:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
