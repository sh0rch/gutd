# CI/CD Workflows Documentation

## Architecture

gutd uses TC eBPF egress + XDP ingress for packet processing.
All data-plane work happens in kernel (no userspace I/O paths).

## Workflows

### 1. ci.yml -- Continuous Integration (automatic)

**Triggers:** Push/PR to `main`, `develop`
**Time:** ~5-7 min

**Jobs:**
- `test`: Unit tests (`cargo test --release`)
- `build`: musl static binary
- `verify`: Config parsing check

---

### 2. tc-check.yml -- TC/XDP Module Verification (automatic)

**Triggers:** Push/PR when `src/tc/**`, `src/config.rs`, `src/tun.rs`, `build.rs` change
**Time:** ~8-12 min

**Jobs:**
- `tc-compilation`: fmt, clippy (strict), build, test, unsafe audit, skeleton verification, Drop check, cargo-audit
- `tc-musl-build`: musl cross-compile, static linking verification

---

### 3. integration-test.yml -- Integration Test (manual)

**Triggers:** Manual dispatch, called by release.yml
**Time:** ~5-8 min

**What it does:**
1. Build gutd (musl)
2. Create two network namespaces with veth transport
3. Start gutd in each namespace (TC egress + XDP ingress)
4. Run: ICMP ping, TCP small, TCP 100KB, iperf3 throughput
5. All tests must pass

**Manual run:**
```bash
gh workflow run integration-test.yml
```

---

### 4. release.yml -- Release Pipeline (tag/manual)

**Triggers:** Push tag `v*.*.*`, manual dispatch
**Time:** ~10-15 min

**Pipeline:**
1. Unit tests
2. Build musl static binary
3. Config parsing verification
4. Create GitHub Release with binary + SHA256

---

### 5. build.yml / unit-tests.yml -- Reusable workflows

Called by other workflows. Not triggered directly.

---

## Workflow Decision Tree

```
Push/PR code
    |
    v
 ci.yml (5-7 min)
    +-- cargo test
    +-- musl build
    \-- config verify
    
TC/XDP code changed?
    |
    v
 tc-check.yml (8-12 min)
    +-- strict clippy
    +-- BPF skeleton verify
    \-- musl cross-compile

Ready for release?
    |
    v
 git tag v1.0.0
    |
    v
 release.yml (10-15 min)
    +-- unit tests
    +-- musl build
    +-- verify
    \-- GitHub Release
```

## Release Process

```bash
# 1. Local checks
cargo test
cargo fmt
cargo clippy

# 2. Tag and push
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# 3. Monitor
gh run watch

# 4. Verify
gh release view v1.0.0
```

## Integration Test (manual before release)

```bash
# Via GitHub Actions
gh workflow run integration-test.yml

# Locally
sudo bash tests/integration-wg.sh
```
