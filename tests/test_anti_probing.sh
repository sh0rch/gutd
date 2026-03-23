#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUTD_BINARY="$SCRIPT_DIR/../target/release/gutd"

# Build gutd
echo "Building gutd release..."
cargo build --release > /dev/null 2>&1

echo "Configuring gutd server..."
cat <<CONF > /tmp/gutd_ap_s.conf
[global]
userspace_only = true

[peer]
name = gut0
bind_ip = 127.0.0.1
peer_ip = 127.0.0.1
ports = 5060
key = 0000000000000000000000000000000000000000000000000000000000000000
obfs = sip
sni = example.com
responder = true
wg_host = 127.0.0.1:51820
bind_port = 51821
CONF

echo "Starting gutd server..."
$GUTD_BINARY -c /tmp/gutd_ap_s.conf > /tmp/gutd_ap_s.log 2>&1 &
PID=$!
sleep 1

function cleanup {
    echo "Stopping gutd server..."
    kill $PID 2>/dev/null || true
    rm -f /tmp/gutd_ap_s.conf
}
trap cleanup EXIT

echo "Running probe tests via python..."

cat << 'PYEOF' > /tmp/run_probes.py
import socket
import sys

fail = False

def test_probe(name, payload, expected_status, port=5060):
    global fail
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.sendto(payload, ("127.0.0.1", port))
    try:
        data, _ = sock.recvfrom(4096)
        if expected_status is None:
            print(f"[FAIL] {name}: Expected no response, but got {len(data)} bytes")
            fail = True
        elif expected_status in data:
            print(f"[OK] {name}: Received expected '{expected_status.decode()}'")
        else:
            print(f"[FAIL] {name}: Did not find '{expected_status.decode()}' in response.")
            print(f"       Got: {data[:100]}")
            fail = True
    except socket.timeout:
        if expected_status is None:
            print(f"[OK] {name}: Dropped (no response, as expected)")
        else:
            print(f"[FAIL] {name}: Expected '{expected_status.decode()}', but got timeout")
            fail = True

# 1. SIP OPTIONS
test_probe("SIP OPTIONS", b"OPTIONS sip:user@example.com SIP/2.0\r\n\r\n", b"200 OK")

# 2. SIP REGISTER
test_probe("SIP REGISTER", b"REGISTER sip:user@example.com SIP/2.0\r\n\r\n", b"401 Unauthorized")

# 3. SIP INVITE (Forbidden Catch-all)
test_probe("SIP INVITE (Catch-all)", b"INVITE sip:user@example.com SIP/2.0\r\n\r\n", b"403 Forbidden")

# 4. SIP GARBAGE (Not starting with valid keyword but parsing as sip header somehow, or just pure SIP drop)
# If it doesn't match check_header it will be tested against GOST/QUIC and dropped
test_probe("RANDOM GARBAGE", b"\xff\xff\xff\xff", None)

# 5. RTP Probe (0x80 0x60...)
rtp_payload = b"\x80\x60\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
test_probe("RTP PROBE", rtp_payload, None)

# 6. Syslog Fake Probe (starts with <134> but invalid payload)
syslog_payload = b"<134>Just some random fake syslog text here..."
test_probe("SYSLOG PROBE", syslog_payload, None)

if fail:
    sys.exit(1)
else:
    sys.exit(0)
PYEOF

python3 /tmp/run_probes.py

