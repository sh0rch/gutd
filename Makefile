.PHONY: help build test test-unit test-integration test-wg test-ndpi check-deps clean install \
        docker-build docker-build-multiarch docker-push

CARGO := cargo
GUTD_BINARY := target/release/gutd
DOCKER_TAG  ?= gutd:latest

help:
	@echo "Available targets:"
	@echo "  build              - Build gutd in release mode"
	@echo "  test               - Run all tests (unit + integration)"
	@echo "  test-unit          - Run unit tests only"
	@echo "  test-integration   - Run integration tests with WireGuard"
	@echo "  test-wg            - Alias for test-integration"
	@echo "  test-ndpi          - Run nDPI evasion test for all obfuscation modes"
	@echo "  check-deps         - Check if integration test dependencies are installed"
	@echo "  clean              - Clean build artifacts"
	@echo "  install            - Install gutd to /usr/local/bin"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build            - Build x86_64 binary and single-arch runtime image"
	@echo "  docker-build-multiarch  - Build amd64+arm64 runtime image (requires cross)"
	@echo "  docker-push             - Build and push multi-arch image to registry"
	@echo "                           Set DOCKER_TAG=myrepo/gutd:latest (default: gutd:latest)"
	@echo "                           Set PLATFORMS=linux/amd64,linux/arm64,... to override"
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

test-ndpi: build
	@echo "Running nDPI evasion test for all obfuscation modes (requires sudo)..."
	@if [ ! -f $(GUTD_BINARY) ]; then \
		echo "Error: gutd binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	sudo -E GUTD_BINARY=$(PWD)/$(GUTD_BINARY) bash tests/test_ndpi_all_modes.sh

clean:
	$(CARGO) clean
	rm -f /tmp/gutd-test-* /tmp/wg-*.conf /tmp/iperf3-*.log

install: build
	sudo install -m 755 $(GUTD_BINARY) /usr/local/bin/gutd
	@echo "gutd installed to /usr/local/bin/gutd"
	@gutd --version

# ── Docker ────────────────────────────────────────────────────────────────────

# Build the x86_64 binary via the build Dockerfile, then assemble a local
# single-arch runtime image (no cross, no buildx multi-platform needed).
docker-build:
	docker build -t gutd-builder -f docker/Dockerfile.x86_64 .
	$(eval CID := $(shell docker create gutd-builder))
	mkdir -p dist
	docker cp $(CID):/out/gutd dist/gutd-amd64
	docker rm $(CID) >/dev/null
	docker build \
		--build-arg TARGETARCH=amd64 \
		--platform linux/amd64 \
		-t $(DOCKER_TAG) \
		-f docker/Dockerfile.run .
	@echo "Built $(DOCKER_TAG) (linux/amd64)"

# Build amd64 + arm64 (and optionally more via PLATFORMS=...) using cross + buildx.
docker-build-multiarch:
	bash docker/build-multiarch.sh \
		--tag $(DOCKER_TAG) \
		$(if $(PLATFORMS),--platforms $(PLATFORMS),)

# Build and push multi-arch manifest to registry.
docker-push:
	bash docker/build-multiarch.sh \
		--tag $(DOCKER_TAG) \
		$(if $(PLATFORMS),--platforms $(PLATFORMS),) \
		--push
