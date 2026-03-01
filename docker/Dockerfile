# Static musl build for x86_64-unknown-linux-musl
#
# Why cross-compile (host=glibc, target=musl) instead of native Alpine:
#   - libbpf-cargo (build.rs) needs glibc to generate BPF skeletons
#   - Proc-macros compile for HOST (glibc) → works
#   - Final binary links against musl static libs → fully static
#
# For aarch64 / armv7 / mipsel / mips: use `cross` (see Cross.toml)
#
# Build:
#   docker build -t gutd -f docker/Dockerfile .
# Extract:
#   CID=$(docker create gutd) && docker cp "$CID:/out/gutd" gutd && docker rm "$CID"

# ── Stage 1: extract musl libs + headers from Alpine ─────────────
FROM alpine:3.21 AS sysroot

RUN apk add --no-cache \
    elfutils-dev \
    zstd-dev zstd-static \
    zlib-dev zlib-static \
    linux-headers \
    musl-dev && \
    mkdir -p /sysroot/lib /sysroot/include && \
    cp /usr/lib/libelf.a    /sysroot/lib/ && \
    cp /usr/lib/libzstd.a   /sysroot/lib/ 2>/dev/null || true && \
    cp /usr/lib/libz.a      /sysroot/lib/ 2>/dev/null || true && \
    cp /usr/include/libelf.h /usr/include/gelf.h \
    /usr/include/nlist.h  /usr/include/elf.h   /sysroot/include/ && \
    cp /usr/include/zstd.h /sysroot/include/ 2>/dev/null || true && \
    cp -r /usr/include/asm /usr/include/asm-generic \
    /usr/include/linux /sysroot/include/

# ── Stage 2: build toolchain ─────────────────────────────────────
FROM rust:bookworm AS toolchain

RUN export DEBIAN_FRONTEND=noninteractive && \
    export TZ=Etc/UTC && \
    apt-get update && \
    apt-get install -y --no-install-recommends tzdata && \
    apt-get install -y --no-install-recommends \
    clang llvm lld musl-tools pkg-config libelf-dev gettext autopoint flex bison gawk make && \
    (apt-get install -y --no-install-recommends upx || \
    apt-get install -y --no-install-recommends upx-ucl || true) && \
    # clang -target bpf needs /usr/include/asm/
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    rm -rf /var/lib/apt/lists/* && \
    rustup target add x86_64-unknown-linux-musl && \
    rustup component add rustfmt

COPY --from=sysroot /sysroot /sysroot

# x86_64 musl — clang linker + LLVM LTO (clang lld speaks LLVM bitcode natively)
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=--target=x86_64-unknown-linux-musl -C link-arg=-fuse-ld=lld -C link-arg=-Wl,--gc-sections -C link-arg=-Wl,-s -L /sysroot/lib -l static=elf -l static=zstd" \
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CFLAGS_x86_64_unknown_linux_musl="-I/sysroot/include -fno-asynchronous-unwind-tables -Oz"

# ── Stage 3: build ────────────────────────────────────────────────
FROM toolchain AS builder

WORKDIR /build
COPY . .

RUN CARGO_PROFILE_RELEASE_LTO=fat \
    cargo build --release --target x86_64-unknown-linux-musl && \
    mkdir -p /out && \
    cp target/x86_64-unknown-linux-musl/release/gutd /out/gutd && \
    (command -v upx >/dev/null 2>&1 && upx --best --lzma /out/gutd || \
    echo "UPX not found; skipping compression")

# ── Stage 4: minimal runtime ──────────────────────────────────────
FROM scratch

COPY --from=builder /out/gutd /gutd

VOLUME ["/etc/gutd"]
ENTRYPOINT ["/gutd"]
CMD ["--config", "/etc/gutd/gutd.conf"]

LABEL org.opencontainers.image.title="gutd"
LABEL org.opencontainers.image.description="WireGuard traffic obfuscator (TC/XDP eBPF)"
LABEL org.opencontainers.image.source="https://github.com/sh0rch/gutd"
LABEL org.opencontainers.image.licenses="Apache-2.0"
