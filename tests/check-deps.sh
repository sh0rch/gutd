#!/bin/bash
# Check if all dependencies for integration tests are installed

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_command() {
    local cmd=$1
    local package=$2
    
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $cmd"
        return 0
    else
        echo -e "${RED}✗${NC} $cmd (install: $package)"
        return 1
    fi
}

check_kernel_module() {
    local module=$1
    
    if lsmod | grep -q "^$module"; then
        echo -e "${GREEN}✓${NC} kernel module: $module"
        return 0
    elif modprobe -n "$module" 2>/dev/null; then
        echo -e "${YELLOW}⚠${NC} kernel module: $module (available but not loaded)"
        return 0
    else
        echo -e "${RED}✗${NC} kernel module: $module"
        return 1
    fi
}

echo "Checking dependencies for integration tests..."
echo ""

missing=0

echo "Required commands:"
check_command ip "iproute2" || missing=1
check_command wg "wireguard-tools" || missing=1
check_command iperf3 "iperf3" || missing=1
check_command tcpdump "tcpdump" || missing=1
check_command jq "jq" || missing=1
check_command bc "bc" || missing=1
check_command ping "iputils-ping" || missing=1

echo ""
echo "Kernel modules:"
check_kernel_module wireguard || missing=1
check_kernel_module tun || missing=1

echo ""
echo "Build tools:"
check_command cargo "rustc (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)" || missing=1
check_command rustc "rustc" || missing=1

echo ""
if [ $missing -eq 0 ]; then
    echo -e "${GREEN}✓ All dependencies satisfied!${NC}"
    echo ""
    echo "You can now run:"
    echo "  make test-integration    # Full WireGuard integration test"
    echo "  sudo bash tests/quick-test.sh  # Quick smoke test"
    exit 0
else
    echo -e "${RED}✗ Some dependencies are missing${NC}"
    echo ""
    echo "Install missing dependencies:"
    echo ""
    echo "Ubuntu/Debian:"
    echo "  sudo apt-get install -y wireguard-tools iperf3 tcpdump iproute2 iputils-ping jq bc"
    echo ""
    echo "Alpine:"
    echo "  sudo apk add wireguard-tools iperf3 tcpdump iproute2 iputils jq bc"
    echo ""
    echo "Fedora/RHEL:"
    echo "  sudo dnf install wireguard-tools iperf3 tcpdump iproute iputils jq bc"
    echo ""
    echo "Rust (if not installed):"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
