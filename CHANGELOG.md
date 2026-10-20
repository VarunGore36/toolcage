# Changelog

All notable changes to toolcage will be documented in this file.

## [Unreleased]

### Added
- `backend-fc`: Firecracker microVM Tier 2 driver with REST API boot, vsock exec, snapshot pool, snapshot head-bound checkpoints, warm pool
- `crates/proxy`: real egress proxy dialer with DNS control, metadata/link-local blocking, TLS (native-tls), per-destination byte/request budgets
- `crates/broker`: encrypted-at-rest credential store (XChaCha20-Poly1305), per-credential expiry, master key rotation
- `crates/supervisor`: Tier 0/Tier 1 backend exec routing, fail-closed budget enforcement after proxy call
- `crates/mcp`: stdio JSON-RPC front door with `run_command`, `read_file`, `write_file`, `http_fetch`, learn mode
- `crates/audit`: hash-chain audit writer with verify-on-open, Ed25519 signed checkpoints, head-bound checkpoint verification
- `crates/capability`: attenuable capability tokens with expiry, traversal-normalized paths, revocation graph
- `crates/backend-ns`: real Tier 0 namespace + Landlock + seccomp driver with unprivileged user namespace support
- `crates/guest-agent`: PID 1 guest protocol (Exec/PutFile/Heartbeat) with validation
- `crates/cli`: `run`, `check-net`, `fetch`, `token`, `mcp`, `audit`, `doctor`, `panic` commands
- `scripts/bench.sh`: benchmark harness for policy p99, audit append eps, CLI run baseline
- `docs/REVIEW.md`: Gate 2 review package
- `docs/TEST_RESULTS.md`: test results and benchmarks
- `docs/THREAT_MODEL.md`: threat model with seven invariants

### Changed
- `crates/proxy`: alias resolution now maps guest alias → upstream → operator alias for policy (fixes non-github aliases)
- `crates/supervisor`: budget check moved after proxy call so bytes are charged accurately
- `README.md`: redesigned with hero banner, 60-second demo, four guarantees, tier chart, benchmark table

## [v0.1.0] - Initial Release

- Initial release of toolcage: local-first agent sandbox
- Tier 0: namespaces + Landlock + seccomp + cgroup v2
- Tier 1: gVisor runsc stub driver
- Tier 2: Firecracker REST driver stub
- YAML policy allowlist, metadata forbid, shell string denial
- Hash-chain audit with Ed25519 checkpoints
- Egress proxy (stub), credential broker (in-memory)
- CLI: run, check-net, fetch, token, mcp, audit, doctor, panic
