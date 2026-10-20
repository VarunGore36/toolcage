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
