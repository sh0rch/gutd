# Contributing to gutd

## Getting Started

1. Fork the repository: <https://github.com/sh0rch/gutd>
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes and commit with a clear message
4. Open a pull request against `main`

## Development Requirements

- Rust stable (latest)
- Linux kernel 5.15+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- `clang` 14+ and `llvm-strip` for BPF compilation
- `libbpf` dev headers

Check all build dependencies:

```bash
bash tests/check-deps.sh
```

Build:

```bash
cargo build
```

## Code Style

- Rust: standard `rustfmt` formatting (`cargo fmt`)
- BPF C: follow the style of existing files in `src/tc/bpf/`
- No inline performance claims or benchmark numbers in docs

## Testing

Run the integration test before submitting a PR:

```bash
sudo bash tests/integration-wg.sh
```

The test requires a Linux host with network namespace support and WireGuard loaded.

## Pull Request Guidelines

- One logical change per PR
- Include a brief description of what changes and why
- If changing the wire protocol or BPF datapath, update `COMPLIANCE.md`
- If changing config keys, update `gutd.conf`, `src/installer.rs`, and `README.md`

## Reporting Security Issues

See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your changes will be licensed under the
[Apache-2.0](LICENSE) license.
