# CI/CD

## Workflows

| Workflow | Trigger | Time | Purpose |
|----------|---------|------|---------|
| `ci.yml` | Push/PR to main | ~5 min | Unit tests + musl build + config verify |
| `tc-check.yml` | TC/XDP code changes | ~10 min | Strict clippy, BPF skeleton, unsafe audit |
| `integration-test.yml` | Manual / release | ~5 min | Netns tunnel test: ping, TCP, iperf3 |
| `release.yml` | Tag `v*.*.*` | ~12 min | Full pipeline -> GitHub Release |

## Quick Reference

```bash
# Development (automatic on push)
git push                         # -> ci.yml

# Integration test (manual)
gh workflow run integration-test.yml
# or locally:
sudo bash tests/integration-wg.sh

# Release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0            # -> release.yml
```

See [.github/WORKFLOWS.md](.github/WORKFLOWS.md) for details.
