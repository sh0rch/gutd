# Code of Conduct

There are no restrictions on communication style in this project.

The only requirement is that all contributions follow the project's code formatting standards:

## Rust

- **`cargo fmt`** - all Rust code must pass `cargo fmt --check` (default `rustfmt` rules)
- **`cargo clippy`** - no warnings with strict settings:
  - `-D warnings -D clippy::all`
  - Allowed exceptions: `module-name-repetitions`, `missing-errors-doc`, `missing-panics-doc`

## BPF C (`src/tc/bpf/`)

- Linux kernel BPF style: tabs for indentation, K&R braces
- All functions and macros prefixed with `gut_` or `GUT_`
- Verifier-safe bounds checks on every variable-length access

## Shell scripts (`tests/`)

- `set -e` at the top of every script
- Cleanup traps or explicit cleanup sections before exit

## Commits

- Atomic: one logical change per commit
- Build must pass CI (`cargo fmt --check`, `clippy`, `cargo build`, integration test)
