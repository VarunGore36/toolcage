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
| I3 | A token can only be narrowed, never widened, when delegated | Capability property tests (200 seeds), narrow/widen/revoke/tamper |
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
cargo test --workspace       # 194 tests, 0 failures (see docs/TEST_RESULTS.md)
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
| Shell strings blocked | I6 — `sh -c`/`bash -c` denied at policy and guest-agent level |
| Cross-session isolation | I7 — canary tests write marked data, confirm later sessions can't read it |

## Known limitations (honest)

- **Seccomp-BPF unavailable** on this host's kernel build (returns EINVAL). Namespaces + Landlock still enforce the Tier0 boundary; seccomp is defense-in-depth.
- **Audit fsyncs per append** — crash-safe but ~hundreds/s throughput target not yet met with group commit (~270k eps measured is host/fs-dependent).
- **Supervisor idle memory** not yet measured (< 100 MB target).
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
