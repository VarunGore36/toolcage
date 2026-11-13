# toolcage Security Review — Gate 2 Prep

This document is the review package for Gate 2 (independent review before any public security claim), per the [Agent Sandbox Analysis and Build Plan](../Agent%20Sandbox%20Analysis%20and%20Build%20Plan.md) §15/M6.

## What to review

| Item | Location |
|------|----------|
| Threat model | `docs/THREAT_MODEL.md` |
| Test results | `docs/TEST_RESULTS.md` |
| Design/build plan | `Agent Sandbox Analysis and Build Plan.md` |
| Code | `crates/` (Rust workspace) |
| Demo | 60-second commands below |

## Threat model

Five adversaries (A1–A5) and seven attack paths are modeled in `docs/THREAT_MODEL.md`. Each attack path maps to a primary control:

| Attack path | Primary control |
|-------------|-----------------|
| Sandbox escape | Tiered isolation (T0 ns+Landlock+seccomp, T1 gVisor, T2 Firecracker) |
| Network exfiltration | Single egress proxy, guest never dials |
| Exfil via allowed tool | Per-destination method/path/byte budgets + approvals |
| Credential theft | Broker-only secrets, encrypted at rest, never in guest |
| Persistence | Ephemeral sessions, golden-image-only snapshots |
| Lateral movement | No guest-reachable control socket |
| Log tampering | Hash chain + signed checkpoints, verify fails on mutation |

## Seven security invariants (all tested)

| ID | Invariant | Test suite |
|----|-----------|------------|
| I1 | No guest process reaches any network except through the egress proxy | Escape suite (raw sockets, DNS, ICMP, IPv6, tunnels), proxy alias/metadata/budget tests |
| I2 | No credential value ever appears in guest memory, files, environment, or arguments | Credential canaries, broker encrypt/load/rotate |
| I3 | A token can only be narrowed, never widened, when delegated | Capability property tests (200 seeds), narrow/widen/revoke/tamper, **approval `needs_approval` fail-closed on unknown/empty method/host preventing gate-dodging — decision-table matrices pin the full contract (UNKNOWN fires, KNOWN-WRONG passes, wildcard lists, `.any()` across rules) in both the policy and approval crates, end-to-end through the YAML loader; a gate pause exits 3 (`fetch` and `mcp call`) and `Queue::sweep_expired` enforces timeout = deny** |
| I4 | Every decision and side effect is recorded before the action completes | Supervisor write-ahead intent logging, chaos tests |
| I5 | Any edit/deletion/reordering of the audit log is detected by `audit verify` | Audit mutation tests, checkpoint truncation test |
| I6 | The guest cannot loosen its own policy or reach the policy engine | `sh -c` denial, path traversal tests, fs mount checks |
| I7 | After teardown, no session state is reachable by another session | Cross-session canary tests |

## Verification

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test --workspace       # all green (count + breakdown: docs/TEST_RESULTS.md)
cargo clippy --workspace --all-targets  # clean
```

### 60-second demo

```bash
# 1. Host capability check
./target/release/toolcage-cli doctor

# 2. Run under policy + audit
./target/release/toolcage-cli run \
  --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --tier tier0 -- /bin/echo hello

# 3. Evil twin — denied + audited
./target/release/toolcage-cli run \
  --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --tier tier0 -- sh -c 'echo pwned'
# denied: deny:shell

# 4. Tamper-evident log
./target/release/toolcage-cli audit keygen --out-prefix /tmp/k
./target/release/toolcage-cli audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
./target/release/toolcage-cli audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex
# ok: N events, head ... (checkpoints verified)

# 5. Flip one byte — verify fails
# (flip any byte in /tmp/tc.jsonl, then:)
./target/release/toolcage-cli audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex
# error
```

## Security claims and evidence

| Claim | Evidence |
|-------|----------|
| No secret appears in guest | I2 — canary secrets planted and scanned; broker holds secrets host-side, injects via proxy only |
| No guest network except via proxy | I1 — escape suite tests raw sockets, DNS, ICMP, IPv6, tunnels all denied |
| Tokens cannot widen on delegate | I3 — 200-seed property test, narrow/widen/revoke/tamper unit tests |
| Every action logged before it runs | I4 — write-ahead intent logging, chaos tests kill supervisor mid-action |
| Log tampering detected | I5 — audit mutation tests flip/delete/reorder bytes; verify fails |
| Shell strings blocked | I6 — `sh -c`/`bash -c` denied at policy and guest-agent level; the argv-shape bypasses are closed and pinned by the exec-denylist suite: `env -S`/`--split-string` reassembly, shell startup files (`--rcfile=`/`--init-file=`), the awk family, python `-m`, and perl/ruby `-x` all deny with `deny:shell`; the end-to-end matrix runs through the real YAML loader and the cross-product matrix covers wrapper x interpreter x flag-spelling forms |
| Cross-session isolation | I7 — canary tests write marked data, confirm later sessions can't read it |

## Historical review artifacts

- [`docs/VULNERABILITY_REPORT.md`](VULNERABILITY_REPORT.md) — the Nov 10 audit of the
  pre-fix tree (v0.1.0). Superseded: every finding is fixed on `main` (see the
  CHANGELOG and the closed review issues #69–#77 for per-finding dispositions).

## Dependency security tooling

`cargo-audit` (RustSec vulnerabilities) and `cargo-deny` (permissive-only
licenses, crates.io-only sources) run on every push/PR, nightly against the
fresh advisory DB, and before every release — over **both** workspaces
(root + fuzz). Exception lists: `audit.toml`, `deny.toml` (reason + review
date per entry). Policy: CONTRIBUTING.md "Dependency policy".

## Known limitations (honest)

- **Seccomp-BPF fallback mitigations**: On kernels where `PR_SET_SECCOMP` / `SYS_seccomp` returns `EINVAL`, Tier 0 runs namespaces + Landlock + `no_new_privs` and seccomp acts as defense-in-depth:
  | Blocked syscall family | Reachable on `EINVAL` host? | Active kernel mitigation without seccomp |
  | --- | --- | --- |
  | `socket`, `socketpair` | Syscall reachable; routing denied | `CLONE_NEWNET` creates an isolated network namespace with no interfaces or routes (`ENETUNREACH`). |
  | `mount`, `umount2`, `pivot_root`, `fsopen`, `move_mount`, `open_tree`, `fsmount`, `fspick`, `chroot` | Confined to unprivileged userns | `CLONE_NEWUSER` + `MS_PRIVATE\|MS_REC` prevent propagation to host; Landlock VFS rules enforce `/workspace` (rw) and `/usr,/bin,/lib,/lib64` (ro+x). |
  | `ptrace`, `process_vm_readv`, `process_vm_writev` | Confined to child PID ns | `CLONE_NEWPID` isolates PID 1; host processes are unaddressable. |
  | `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Syscall reachable; VFS gated | Operations inherit the task's Landlock ruleset and unprivileged userns credentials. |
  | `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `iopl`, `ioperm` | Denied (`EPERM`) | Require `CAP_SYS_ADMIN` / `CAP_SYS_MODULE` / `CAP_SYS_RAWIO` / `CAP_SYS_BOOT` in `init_user_ns`. |
- **Audit group commit**: `Writer::append_batch` batches multiple events into a single write + `fdatasync` (`sync_data`), meeting the >=10,000 eps target while preserving I4 write-ahead ordering.
- **Tier 1 (gVisor) & Tier 2 (Firecracker) CI jobs**: Dedicated CI jobs install `runsc` and `firecracker`/`jailer` to exercise driver probes and execution paths alongside mock-backed unit suites.
- **Supervisor idle memory**: Measured in `crates/supervisor/tests/memory.rs` and `scripts/bench.sh` at ~3.1–3.5 MB RSS (< 100 MB target).
- **Persistent capability revocation graph & hierarchical `rev_id`s**: `RevocationList::save` and `load` persist `parent_of` links alongside revoked IDs (with backward compatibility for bare-array files) and enforce `/` hierarchical prefix revocation.
- **Persistent budget counters** now implemented — per-destination byte/request budgets survive restart via fsync'd JSON.
- No GPU workloads, no multi-tenant hosting, no Windows/macOS guests (all out of scope for v1).

## How to contact / scope of review

Review the threat model, the seven invariants and their tests, the egress proxy design (single chokepoint), the capability attenuation logic, and the audit chain verification. Any finding that invalidates a security invariant blocks public claim until addressed.

## Reviewer checklist

- [ ] Threat model covers realistic adversaries (prompt injection, malicious tools, credential theft, log tampering)
- [ ] Seven invariants are testable and each has test coverage
- [ ] Egress proxy is the single network chokepoint; guest cannot dial directly
- [ ] Credentials never appear in guest (env, args, files, memory)
- [ ] Tokens cannot widen on delegation (subset checks on all axes)
- [ ] Audit intent is written before action; corrupt logs are not extended
- [ ] Checkpoint signatures bind `(seq, head, time)` and old checkpoints + truncated tails fail
- [ ] Fail-closed: audit write failure denies action; proxy down closes network
- [ ] No silent tier downgrade — `min_isolation` is enforced fail-closed
