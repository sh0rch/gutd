.PHONY: help build test test-unit test-integration test-wg check-deps clean install

CARGO := cargo
GUTD_BINARY := target/release/gutd

help:
	@echo "Available targets:"
	@echo "  build              - Build gutd in release mode"
	@echo "  test               - Run all tests (unit + integration)"
	@echo "  test-unit          - Run unit tests only"
	@echo "  test-integration   - Run integration tests with WireGuard"
	@echo "  test-wg            - Alias for test-integration"
	@echo "  check-deps         - Check if integration test dependencies are installed"
	@echo "  clean              - Clean build artifacts"
	@echo "  install            - Install gutd to /usr/local/bin"
	@echo ""
	@echo "Integration tests require:"
	@echo "  - wireguard-tools, iperf3, tcpdump, iproute2, jq, bc"
	@echo "  - sudo privileges"
	@echo "Run 'make check-deps' to verify all dependencies"

build:
	$(CARGO) build --release
	@ls -lh $(GUTD_BINARY)

test: test-unit test-integration

test-unit:
	$(CARGO) test --release

check-deps:
	@bash tests/check-deps.sh

test-integration: build check-deps
	@echo "Running WireGuard integration tests (requires sudo)..."
	@if [ ! -f $(GUTD_BINARY) ]; then \
		echo "Error: gutd binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	sudo -E GUTD_BINARY=$(PWD)/$(GUTD_BINARY) bash tests/integration-wg.sh

test-wg: test-integration

clean:
	$(CARGO) clean
	rm -f /tmp/gutd-test-* /tmp/wg-*.conf /tmp/iperf3-*.log

install: build
	sudo install -m 755 $(GUTD_BINARY) /usr/local/bin/gutd
	@echo "gutd installed to /usr/local/bin/gutd"
	@gutd --version
