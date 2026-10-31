# Test results — toolcage

196 tests, 0 failures (`cargo test --workspace`). Clippy clean
(`cargo clippy --workspace --all-targets`: 0 findings).

Generated from the workspace run; re-run `cargo test --workspace` to
reproduce. The breakdown is by test target (integration targets marked `*`).

| Suite | Count | Invariants |
|---|---|---|
| policy unit (decide, request hygiene, modes, exec gate) | 7 | I1, I6 |
| policy escape `*` (shell/interpreter, traversal, request-line, allowlist, mount modes, absent method) | 15 | I1, I6 |
| policy timing `*` (decision p99) | 1 | perf |
| audit unit (chain, checkpoint, verify) | 6 | I4, I5 |
| audit throughput `*` | 1 | perf |
| broker unit (inject/scrub/canary, encrypt/load/rotate, hex, empty credential) | 8 | I2 |
| capability unit (narrow/widen/revoke/tamper, MAC shape, root prefix, rev_id) | 11 | I3 |
| capability property `*` (200-seed chains, revocation subtree, keyed tokens) | 3 | I3 |
| approval unit (gate matching, unknown dodges, queue) | 2 | policy |
| proxy unit (alias, metadata, budgets, http parsing, chunked decode) | 19 | I1 |
| guest-agent unit (request + reply validation) | 6 | I6 |
| mcp unit (gate, tool args, learn, JSON-RPC 2.0 conformance, RPC smoke) | 15 | A2 |
| supervisor unit (hashing, budget helpers) | 1 | — |
| supervisor canary `*` | 3 | I2, I7 |
| supervisor chaos `*` (audit-fail, proxy-down, broker-down, ro-disk, revoked-token, over-budget, panic freeze) | 8 | fail-closed |
| supervisor destination `*` | 2 | I1 |
| supervisor fuzz `*` (policy/guest/audit/proxy) | 4 | all |
| supervisor isolation `*` (fail-closed, tier2 no host spawn, escape hatch) | 4 | I1 |
| supervisor limits `*` (timeout kill, over-cap truncate) | 2 | fail-closed |
| supervisor output `*` (no SIGPIPE on over-cap) | 1 | fail-closed |
| supervisor timeout `*` (process-group kill) | 1 | fail-closed |
| supervisor wait-error `*` (group killed on wait failure) | 1 | fail-closed |
| supervisor token gate `*` (dual auth, attenuation, revocation) | 5 | I3 |
| backend-ns unit (probe, pidns, exec isolation, seccomp, Landlock ABI, environ scrub, waitpid EINTR) | 22 | I1, I2 |
| backend-gv unit (OCI bundle, read_capped, honors lattice, fail-closed) | 9 | tier fail-closed |
| backend-fc unit (config, jailer, pool, snapshot, guest reply, frame, escape suite) | 27 | I1, I6 |
| cli unit (budget naming) | 1 | — |
| cli exit_code `*` | 2 | fail-closed |
| cli key_permissions `*` (0600/0644 exact, umask-independent) | 3 | I2 |
| cli learn_mode `*` (proposals, never auto-applied) | 2 | policy |
| cli min_isolation `*` | 2 | tier fail-closed |
| cli secret_arg `*` (secret never on argv) | 2 | I2 |

Live tier tests **skip loudly** where the host lacks the prerequisites
(userns/mount/net/ipc/pid/uts, Landlock, `runsc`, firecracker + `/dev/kvm`);
probes test the real syscalls, not sysctls.

Manual live checks: `run` ok, `sh -c` denied, metadata denied, `fetch`
scrubbed, evil denied, token widen rejected, POST paused then approved,
`verify ok`, mutation fails, `panic` freezes + taints, checkpoint tamper
fails verify.

Not covered here (see `docs/REVIEW.md`): independent security review —
this is the gate before any public security claim.
