# Test results — toolcage

47 tests, 0 failures (`cargo test --workspace`). Clippy 0 warnings.

| Suite | Count | Invariants |
|---|---|---|
| policy unit (allowlist, metadata, glob, dotdot, shell, case) | 7 | I1, I6 |
| policy escape integration | 3 | I1, I6 |
| audit chain + mutation | 1 | I4, I5 |
| broker inject/scrub/canary | 2 | I2 |
| proxy alias/metadata/budget | 4 | I1 |
| capability 200-seed property | 1 | I3 |
| approval gate | 1 | policy |
| backend-ns (honors, probe) | 2 | tier fail-closed |
| backend-fc (jailer, pool, honors) | 3 | tier fail-closed |
| backend-gv (honors) | 1 | tier fail-closed |
| guest-agent validate | 2 | I6 |
| mcp (learn, host, unknown-tool) | 3 | A2 |
| supervisor canary | 1 | I2, I7 |
| supervisor fuzz (policy/guest/audit/proxy) | 4 | all |
| supervisor chaos (audit-fail, proxy-down, broker-down, ro-disk) | 4 | fail-closed |
| audit checkpoint sign/verify/tamper + old-checkpoint/truncate binding | 2 | I5 |
| capability narrow/widen/revoke/tamper + expiry/traversal | 4 | I3 |
| supervisor limits (timeout kill, over-cap truncate) | 2 | fail-closed |

Manual live checks: `run` ok, `sh -c` denied, metadata denied, `fetch` scrubbed,
evil denied, token widen rejected, POST paused then approved, `verify ok`,
mutation fails, `panic` freezes + taints, checkpoint tamper fails verify.
