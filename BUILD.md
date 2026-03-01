# Build Guide

## Standard Build

```bash
cargo build --release
```

Binary: `target/release/gutd`

## Static Build (musl)

A plain `cargo build --target x86_64-unknown-linux-musl` does not work because
`libbpf-sys` (vendored) requires a C toolchain and `libelf` that are not available
through the standard musl-tools package.  The solution is Docker.

`build-musl.sh` builds a toolchain image once (Ubuntu host + musl-cross + Alpine
libelf) and then runs the Cargo build inside a Docker container with the project
source mounted as a volume.  The host `target/` directory is reused, so incremental
builds are fast.

### Usage

```bash
# Build -> target/musl/gutd
./build-musl.sh

# Build + verify static + smoke test inside Alpine
./build-musl.sh verify

# Force toolchain image rebuild
./build-musl.sh --rebuild
```

### Requirements

- Docker (or Podman aliased as docker)
- No other tools needed on the host

### Output

```
target/musl/gutd   # final static binary (x86_64-unknown-linux-musl)
```

The binary is stripped and optionally compressed with UPX if available in the image.

## Development Build

```bash
cargo build          # debug
cargo test           # unit tests
```

## Key Generation

```bash
# Random 256-bit key (64 hex chars)
./target/release/gutd genkey

# Derive key from passphrase (HKDF-SHA256)
./target/release/gutd genkey --passphrase "my secret"
```

## Install

```bash
# Installs binary, writes /etc/gutd.conf, creates systemd/OpenRC service
sudo ./target/release/gutd install

# Remove binary and service (config is preserved)
sudo ./target/release/gutd uninstall
```
