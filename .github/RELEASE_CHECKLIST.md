# Release Checklist

## Pre-release

- [ ] All changes merged to `main`
- [ ] `cargo test` passes
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy` clean
- [ ] `cargo build --release --target x86_64-unknown-linux-musl` succeeds
- [ ] Version bumped in `Cargo.toml`

## Integration Test (recommended)

```bash
# Locally (requires root)
sudo bash tests/integration-wg.sh

# Or via GitHub Actions
gh workflow run integration-test.yml
```

## Create Release

```bash
git checkout main && git pull
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
# -> triggers release.yml: test -> build -> verify -> GitHub Release
```

## Verify

```bash
gh release view v1.0.0

wget https://github.com/sh0rch/gutd/releases/download/v1.0.0/gutd
sha256sum -c gutd.sha256
chmod +x gutd && ./gutd --version
file gutd  # should be statically linked
```

## Rollback

```bash
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
gh release delete v1.0.0 --yes
```
