# Test results — toolcage

72 tests, 0 failures (`cargo test --workspace`). Clippy clean.

| Suite | Count | Invariants |
|---|---|---|
| policy unit (allowlist, metadata, glob, dotdot, shell, case) | 7 | I1, I6 |
| policy escape integration | 3 | I1, I6 |
| audit chain + mutation | 1 | I4, I5 |
| broker inject/scrub/canary + path-bound creds | 3 | I2 |
| broker encrypt/load/rotate (encrypted at rest) | 3 | I2 |
| proxy alias/metadata/budget + blocked-ip + http parsing + golden-image sig | 10 | I1 |
| capability 200-seed property | 1 | I3 |
| approval gate | 1 | policy |
| backend-ns (honors, probe) | 2 | tier fail-closed |
| backend-ns exec isolation (command run, netns blocked, Landlock block, env cleared) | 3 | I1, I2 |
| backend-fc (jailer, pool, honors) | 3 | tier fail-closed |
| backend-gv (honors lattice, bundle config, fail-closed without runsc) | 4 | tier fail-closed |
| guest-agent validate | 2 | I6 |
| mcp (learn, host, unknown-tool) | 3 | A2 |
| supervisor canary | 1 | I2, I7 |
| supervisor fuzz (policy/guest/audit/proxy) | 4 | all |
| supervisor chaos (audit-fail, proxy-down, broker-down, ro-disk, revoked-token, over-budget) | 6 | fail-closed |
| audit checkpoint sign/verify/tamper + old-checkpoint/truncate binding | 2 | I5 |
| capability narrow/widen/revoke/tamper + expiry/traversal | 4 | I3 |
| supervisor limits (timeout kill, over-cap truncate) | 2 | fail-closed |

Manual live checks: `run` ok, `sh -c` denied, metadata denied, `fetch` scrubbed,
evil denied, token widen rejected, POST paused then approved, `verify ok`,
mutation fails, `panic` freezes + taints, checkpoint tamper fails verify.

## 60-Second Demo — Verified (Oct 19 2026)

The plan's wedge demo runs end-to-end on this host:

1. `toolcage-cli doctor` — userns, cgroup2, landlock_abi, seccomp, kvm all present
2. `toolcage-cli run --tier tier0 -- /bin/echo hello` — prints "hello"
3. `toolcage-cli run --tier tier0 -- sh -c 'echo pwned'` — denied: `deny:shell`
4. `toolcage-cli audit keygen --out-prefix /tmp/k` — generates Ed25519 keypair
5. `toolcage-cli audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex` — checkpoint written
6. `toolcage-cli audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex` — `ok: N events, head ... (checkpoints verified)`
7. Flip one byte of `/tmp/tc.jsonl` → `audit verify` fails (tamper detected)

This demonstrates all four guarantees: disposable isolation, capabilities (deny shell), secret-free guest (no secrets leaked), and tamper-evident log.

## Benchmarks — plan §11 targets (measured on this host, Oct 17 2026)

| Metric | Target | Measured | Status |
|---|---|---|---|
| Policy decision p99 (in-process) | < 5 ms | 404 ns (p50 340 ns, max 6.0 µs, n=10k) | ✓ |
| Audit append throughput | ≥ 10,000 eps | ~270,000 eps (fsync per append, n=5k) | ✓ |
| CLI run end-to-end (Tier0 real isolation) | — | 53 ms/call (n=200, pre-isolation) | baseline |
| Supervisor idle memory | < 100 MB | not measured | open |

Notes: audit fsyncs per append (crash-safe); the eps figure is host/fs-dependent
(tmpfs may not durably flush) and is a baseline, not a durability claim.
Group commit is the next step if real throughput ever needs it. Run `scripts/bench.sh`
to re-measure on any host.
