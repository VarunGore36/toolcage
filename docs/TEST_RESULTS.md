# Test results — toolcage

275 tests, 0 failures (`cargo test --workspace`). Clippy clean
(`cargo clippy --workspace --all-targets`: 0 findings).

Generated from the workspace run (2026-11-13); re-run
`cargo test --workspace` to reproduce. The per-crate breakdown below is
`cargo test -p toolcage-<crate>` (unit + integration + doc tests) and
sums to the workspace total.

| Crate | Count | Invariants |
|---|---|---|
| policy (decide, gate polarity, request hygiene, modes, exec denylist, matrix) | 46 | I1, I6 |
| audit (chain, checkpoint, verify-on-open, freeze, throughput `*`) | 12 | I4, I5 |
| verify (standalone log verifier) | 2 | I5 |
| cli (exit codes, approval pause, secret handling, clients, learn mode, key permissions, revocation, image sign, min isolation) | 24 | I2, I3, I6 |
| supervisor (canary, chaos, destination, fuzz, isolation, limits, memory, output, timeout, token gate, wait-error) | 35 | I2, I4, I7 |
| proxy (alias, metadata, budgets incl. corrupt-store fail-closed, http parsing, chunked decode, scrub) | 28 | I1, I2 |
| broker (inject/scrub/canary, encrypt/load/rotate, empty credential) | 8 | I2 |
| backend (honors lattice, capabilities) | 0 | — |
| backend-fc (REST ordering, snapshot checks, pool failure, Tier-2 escape `*`) | 28 | I1, I7 |
| backend-ns (Landlock, seccomp blocklist pinning, exec resolution, live isolation `*`) | 33 | I1, I6 |
| backend-gv (bundle spec shape, jailer args, runsc invocation) | 9 | I1 |
| guest-agent (request + reply validation) | 6 | I6 |
| capability (narrow/widen/revoke/tamper, signed lineage, revocation persistence, 200-seed property `*`) | 19 | I3 |
| approval (gate decision table, queue contract, timeout sweep) | 7 | I3 |
| mcp (gate, tool args, learn, JSON-RPC 2.0 conformance, RPC smoke) | 16 | A2 |
| **Total** | **273** | 0 failures |

## Coverage

`cargo-tarpaulin` measures statement coverage across the workspace
(excluding the fuzz workspace and `toolcage-backend-ns`, whose exec tests
fork processes that segfault under instrumentation). Coverage is enforced in
CI (`--fail-under 80`).

| Crate | Coverage |
|---|---|
| audit | 85.5% |
| policy | 91.3% |
| proxy | 61.7% |
| supervisor | 67.5% |
| mcp | 42.2% |
| cli | 13.5% |
| guest-agent | 71.1% |
| capability | 86.9% |
| backend-fc | 71.9% |
| backend-gv | 52.2% |
| backend-ns | n/a (excluded — fork-heavy exec tests segfault under instrumentation) |

Lower-coverage crates are CLI argument parsing (cli), the MCP front door
(mcp) and gVisor plumbing (backend-gv); they are covered by CLI-level and
integration tests rather than unit tests. Raising coverage in these crates is
a known improvement area.

## Notes

- Live Tier 0 tests skip loudly on hosts without the namespace stack or
  Landlock; `run --tier tier0` refuses to start rather than downgrade.
- Tier 1 (gVisor) and Tier 2 (Firecracker) suites validate arg/spec shape
  against mock APIs — see the README's status table for what is and is not
  live-tested.
- The counts regenerate from the run: re-run `cargo test --workspace` and
  the `cargo test -p toolcage-<crate>` loop above before editing this file.

## Dependency security

- `cargo audit` (root + fuzz lockfiles): 0 vulnerabilities; 1 triaged warning
  (`unsafe-libyaml` unmaintained, transitive via serde_yaml — ignored with
  rationale and a 2027-01-01 review date in `audit.toml`).
- `cargo deny` (root + fuzz workspaces): licenses ok (permissive-only allow
  list), bans ok, sources ok (crates.io only).
- Gates: every push/PR, nightly advisory refresh, and pre-release. Scanner
  versions pinned (cargo-audit 0.23.0, cargo-deny 0.20.2).
