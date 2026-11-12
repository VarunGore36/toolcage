# Contributing to toolcage

Thank you for contributing! toolcage is an early-stage local-first agent sandbox. We welcome bug reports, fixes, and improvements.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/VarunGore36/toolcage.git
cd toolcage

# Build
cargo build --workspace

# Run tests
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings

# Run benchmarks
cargo run --release -p toolcage-cli -- doctor
./scripts/bench.sh
```

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Add or update tests for your change
5. Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
6. Commit with a conventional message (`feat:`, `fix:`, `docs:`, etc.)
7. Push to your fork and open a pull request

## Code Style

- Rust edition 2021
- Run `cargo fmt` before committing
- Run `cargo clippy --workspace --all-targets -- -D warnings` and fix warnings
- Write tests for new functionality
- Document public APIs with `///` doc comments

## Reporting Bugs

Open a GitHub issue with:
- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your toolcage version and host OS/kernel version

## Security Issues

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and `.github/SECURITY.md` before reporting security issues. Do not disclose vulnerabilities in public issues.

## Roadmap

v1 is complete. Post-v1 work includes:
- Persistent budget counters across supervisor restarts (in progress)
- Audit log group commit for higher append throughput
- Merkle tree inclusion proofs for single-event verification
- Cedar policy language support (optional alternative to YAML)
- External security review

## Dependency policy

Dependencies are scanned on **every push/PR**, **nightly**, and **before every release**:

| Tool | Job | What it enforces |
|---|---|---|
| `cargo-audit` | `cargo-audit` / `security-scan` / release `security-gate` | Known **vulnerabilities** (RustSec) fail the build |
| `cargo-deny` | `cargo-deny` / `security-scan` / release `security-gate` | Licenses (permissive-only allow list), duplicate versions (warn), sources (crates.io only) |

Rules:

1. **Vulnerabilities always fail.** Fix with a lock bump (`cargo update <crate>`) or an upstream upgrade. Never ignore on the command line.
2. **Warnings without a fix** (unmaintained/unsound transitives) go in `audit.toml` / `deny.toml` with **a reason and a review date** — those files are the exception list of record, reviewed in every PR that touches them.
3. **New dependencies** must fit the license allow list in `deny.toml` (permissive-only). Adding an allowance requires a rationale comment next to it.
4. **Both workspaces count**: `fuzz/` has its own lockfile and is scanned with the same policy.
5. The nightly `security-scan` workflow re-runs everything against the fresh advisory DB — a clean merge can still be vulnerable by morning; triage the failure the day it appears.
