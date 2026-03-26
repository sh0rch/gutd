#!/bin/bash
# tests/test_ndpi_all_modes.sh — Run nDPI evasion test for all supported obfuscation modes
#
# Iterates through quic, gost, sip, syslog modes and verifies that
# nDPI must not classify the obfuscated traffic by its real protocol.
#
# Usage:
#   sudo bash tests/test_ndpi_all_modes.sh                      # all modes, userspace
#   sudo bash tests/test_ndpi_all_modes.sh quic syslog           # specific modes
#   sudo GUTD_US=false bash tests/test_ndpi_all_modes.sh         # eBPF mode
#   sudo GUTD_BINARY=/path/to/gutd bash tests/test_ndpi_all_modes.sh
#
# Environment:
#   GUTD_BINARY   — path to gutd binary (default: ../target/release/gutd)
#   GUTD_US       — "true" for userspace, "false" for eBPF (default: true)
#   IPERF_SIZE    — traffic volume per mode (default: 100M for CI, override with e.g. 1000M)
#
# Exit code:
#   0 — all modes passed
#   1 — at least one mode failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALL_MODES="quic gost sip syslog"
MODES="${*:-$ALL_MODES}"
export GUTD_US="${GUTD_US:-true}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[*]${NC} $1"; }
err()  { echo -e "${RED}[!]${NC} $1" >&2; }
step() { echo -e "\n${CYAN}════════════════════════════════════════${NC}"; echo -e "${CYAN} $1${NC}"; echo -e "${CYAN}════════════════════════════════════════${NC}"; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Please run as root"
    exit 1
fi

# Pre-build nDPI once (test_ndpi_evasion.sh will reuse it)
NDPI_DIR="/tmp/nDPI"
if ! command -v ndpiReader &> /dev/null && [ ! -f "$NDPI_DIR/example/ndpiReader" ]; then
    step "Building nDPI from source (one-time)"
    if command -v apt-get &> /dev/null; then
        apt-get update -qq
        apt-get install -y -qq libnuma-dev librrd-dev libpcap-dev libtool-bin autoconf automake make gcc pkg-config git 2>/dev/null
    fi
    rm -rf "$NDPI_DIR"
    git clone --depth 1 https://github.com/ntop/nDPI.git "$NDPI_DIR"
    cd "$NDPI_DIR"
    ./autogen.sh
    ./configure
    make -j"$(nproc)"
    cd -
    log "nDPI built successfully"
fi

step "nDPI Evasion Test — All Modes"
log "Modes to test: $MODES"
log "Transport:     $([ "$GUTD_US" = "true" ] && echo "userspace" || echo "eBPF")"
log "Binary:        ${GUTD_BINARY:-$SCRIPT_DIR/../target/release/gutd}"

PASSED=0
FAILED=0
RESULTS=""
FAIL_MODES=""

for mode in $MODES; do
    step "Testing mode: $mode"

    export GUTD_OBFS="$mode"

    if bash "$SCRIPT_DIR/test_ndpi_evasion.sh"; then
        RESULTS="${RESULTS}\n  ${GREEN}✓${NC} $mode"
        PASSED=$((PASSED + 1))
    else
        RESULTS="${RESULTS}\n  ${RED}✗${NC} $mode"
        FAILED=$((FAILED + 1))
        FAIL_MODES="${FAIL_MODES} $mode"
    fi

    # Save per-mode results
    if [ -f /tmp/ndpi_results.txt ]; then
        cp /tmp/ndpi_results.txt "/tmp/ndpi_results_${mode}.txt"
    fi

    # Brief cooldown between modes for namespace cleanup
    sleep 2
done

step "nDPI Evasion Test Summary"
echo ""
echo -e "  Transport: $([ "$GUTD_US" = "true" ] && echo "userspace" || echo "eBPF")"
echo -e "$RESULTS"
echo ""
echo -e "  Total: $((PASSED + FAILED))  Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
echo ""

if [ "$FAILED" -gt 0 ]; then
    err "FAILED modes:$FAIL_MODES"
    exit 1
fi

log "All $PASSED modes passed nDPI evasion test"
exit 0
