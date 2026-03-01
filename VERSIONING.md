# Dynamic Versioning

gutd uses dynamic versioning based on git tags at build time.

## How it works

The `build.rs` script queries git to determine the version:

1. **On exact tag** (e.g., `v1.0.0`): Shows tag name
   ```bash
   $ gutd --version
   gutd v1.0.0
   ```

2. **Between tags**: Shows `<latest-tag>-<commits>-g<hash>`
   ```bash
   $ gutd --version
   gutd v1.0.0-5-ga53dbc4
   ```

3. **No tags**: Shows short commit hash
   ```bash
   $ gutd --version
   gutd a53dbc4
   ```

4. **Uncommitted changes**: Adds `-dirty` suffix
   ```bash
   $ gutd --version
   gutd v1.0.0-dirty
   ```

5. **No git repo**: Falls back to `Cargo.toml` version
   ```bash
   $ gutd --version
   gutd 1.0.0
   ```

## Version flags

```bash
# Show version
gutd --version
gutd -v

# Show help
gutd --help
gutd -h
```

## CI/CD Integration

The version is automatically embedded at build time:
- GitHub Actions builds include full git describe info
- Release builds use tag version (e.g., `v1.0.0`)
- Development builds show commit hash

## Creating releases

```bash
# Tag a new version
git tag -a v1.0.1 -m "Release v1.0.1"
git push origin v1.0.1

# This triggers release workflow which:
# 1. Builds with version v1.0.1
# 2. Runs tests
# 3. Creates GitHub Release
```
