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

## Windows Build (Cross-Compile)

Windows supports **userspace mode only** (no eBPF). Cross-compile from Linux:

```bash
# Install the target (once)
rustup target add x86_64-pc-windows-gnu

# Build without eBPF features
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

Binary: `target/x86_64-pc-windows-gnu/release/gutd.exe`

32-bit build:
```bash
rustup target add i686-pc-windows-gnu
cargo build --release --target i686-pc-windows-gnu --no-default-features
```

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

### Linux

```bash
# Installs binary, writes /etc/gutd.conf, creates systemd/OpenRC service
sudo ./target/release/gutd install

# Remove binary and service (config is preserved)
sudo ./target/release/gutd uninstall
```

### Windows

Run Command Prompt or PowerShell **as Administrator**:

```powershell
# Installs to C:\Program Files\gutd\gutd.exe,
# writes example config to C:\ProgramData\gutd\gutd.conf,
# registers "gutd" Windows Service (manual start, stopped)
gutd.exe install

# Start / stop the service
net start gutd
net stop gutd

# Remove service and binary (config is preserved)
gutd.exe uninstall
```

The Windows service is registered with `start= demand` (manual). Use
`sc config gutd start= auto` to enable automatic startup at boot.
