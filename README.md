<div align="center">

![toolcage banner](assets/banner.svg)

**A local-first security runtime for AI agents.** It puts policy enforcement, host-held credentials, controlled egress, isolation, and tamper-evident audit records between an agent and the systems it can affect.

[![CI](https://github.com/VarunGore36/toolcage/actions/workflows/ci.yml/badge.svg)](https://github.com/VarunGore36/toolcage/actions/workflows/ci.yml)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha%20%C2%B7%20not%20independently%20reviewed-orange.svg)](docs/REVIEW.md)
[![Tests](https://img.shields.io/badge/tests-275%20%C2%B7%200%20failures-brightgreen.svg)](docs/TEST_RESULTS.md)
![Rust](https://img.shields.io/badge/built%20with-Rust-black.svg)

[Quickstart](#quickstart) · [Why toolcage](#why-toolcage) · [Architecture](#architecture) · [Isolation tiers](#isolation-tiers) · [Security invariants](#the-seven-invariants) · [Policy](#policy) · [CLI reference](#cli-reference) · [MCP front door](#mcp-front-door) · [Tests](#tests) · [Status & limits](#status-and-known-limits)

</div>

---

![Terminal demo](assets/demo.svg)

## Why toolcage

A sandbox that only stops escapes misses what actually goes wrong with agents. Agents read untrusted content, call third-party tools, and install packages. toolcage is the **control plane** for those actions: it makes each action explicitly allowed, bounded, attributable, and fail-closed when its requirements cannot be enforced.

The failure modes toolcage addresses:

| Risk | What toolcage does about it |
|---|---|
| 🔑 Prompt injection says "send me the key" | The guest **never holds the key**. A host-side broker injects it into requests to allowed destinations only, and strips it from responses. |
| 📦 Poisoned MCP server or dependency | Runs as a contained guest process under the same policy and audit trail as everything else. |
| 🧾 Agent exfiltrates through an allowed tool (`git push`) | Per-destination method, path, and byte budgets, plus human approval gates. |
| 🎟️ Over-broad delegation | Capability tokens can only be **narrowed** when delegated, never widened. |
| 🔏 "What happened, and can I trust the record?" | Every decision is hash-chained and checkpoint-signed. `audit verify` fails on any edit, deletion, or reordering. |

> **Boundary on the last claim:** Signed checkpoints authenticate the log only through the newest retained checkpoint. See [Audit log](#audit-log) for how to protect the unchecked tail.

---

## Quickstart

**Requirements:** Linux and a stable Rust toolchain. Tier 0 uses user namespaces, cgroup v2, Landlock, and seccomp; Tier 1 needs gVisor (`runsc`); Tier 2 needs Firecracker and `/dev/kvm`. Start with `doctor`: toolcage denies a request when its requested isolation cannot be provided.

```bash
cargo build --release

# The Cargo package produces this release binary.
tc() { ./target/release/toolcage-cli "$@"; }

# 1. Probe the host (prints userns, cgroup2, landlock_abi, seccomp, kvm)
tc doctor

# 2. Run under policy + audit (argv arrays only, no shell)
tc run --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
       --tier tier0 -- /bin/echo hello

# 3. The evil twin: denied, and the denial is logged
tc run --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
       --tier tier0 -- sh -c 'echo pwned'
# denied: ["deny:shell"]
#   deny:shell:
#     shell strings and interpreter inline code (`sh -c`, `python -c`) are
#     blocked by policy: the guest may only run binaries as plain argv arrays.
#     If you trust this binary, allowlist it in the policy: ...

# 4. Sign the log, verify it
tc audit keygen     --out-prefix /tmp/k
tc audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
tc audit verify     --log /tmp/tc.jsonl --pubkey  /tmp/k.pub.hex
# ok: N events, head ... (checkpoints verified)

# 5. Flip one byte of /tmp/tc.jsonl and verify again: it fails.
```

Or watch the whole story in one command:

```bash
tc demo   # allowed run → denied shell (with explanation) → signed log → tamper → verify fails
```

Secrets through the proxy:

```bash
tc fetch --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --host github.internal --method GET --path /repos/acme/app/issues/1 \
  --cred github_token --secret-value s3cr3t
# body: upstream api.github.com/... ok auth=[REDACTED]
```

> `--secret-value` on the command line is a demo convenience. It ends up in shell history and the process list. For real credentials, use `--secret-file`, which is read host-side and never placed on argv.

The demo flow was last verified end to end on 2026-10-19 ([`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)).

---

## Architecture

![How a tool call is handled](assets/how-it-works.svg)

Every tool call crosses one small trusted core, the **supervisor**. It decides, records, isolates, proxies, and proves. Everything else (model output, guest processes, tool and MCP output, file and web content) is untrusted.

| | Moving part | Job |
|---|---|---|
| 📜 | **policy engine** | One YAML file per tool. Anything not allowed is denied. |
| 🔐 | **credential broker** | Secrets live host-side; injected only toward the destinations they are bound to. |
| 🌐 | **egress proxy** | The single network chokepoint — the guest never dials. |
| 🧾 | **audit writer** | Write-ahead intent, hash chain, signed checkpoints. |
| 🧰 | **supervisor** | The thin trusted core that ties the four above to the sandbox. |

> **Trusted, and kept small.** Those five are the entire trusted computing base — the guest never holds a key, a policy, or a pen to the log.

### Decision order for every request

![Decision flow animation](assets/decision-flow-anim.svg)

```mermaid
flowchart TD
    A[Request arrives] --> B[Canonicalize at enforcement point]
    B --> C{Operator<br/>forbid?}
    C -- yes --> D[DENY]
    C -- no --> E{Capability token<br/>allows?}
    E -- no --> D
    E -- yes --> F{Approval<br/>gate?}
    F -- required --> G[Pause for operator<br/>timeout = deny]
    F -- not required --> H[Write INTENT to audit log]
    G -- approved --> H
    G -- denied --> D
    H -- write fails --> D
    H -- write ok --> I[Execute action]
    I --> J[Write OUTCOME to audit log]
```

```
canonicalize at the enforcement point
  → operator forbid wins
  → capability token checks
  → approval gate (timeout = deny)
  → write intent to the log     ← if this fails, the action is denied
  → act
  → write outcome
```

### Secrets never cross the boundary

![Credential flow](assets/secrets.svg)

---

## Isolation tiers

![Isolation tiers](assets/tiers.svg)

A tool declares `min_isolation`. If the host can't provide it, the call is **denied and audited**. It is never run at a weaker tier. Tier 0 shares the host kernel; use Tier 1 or 2 for hostile code.

```mermaid
flowchart LR
    subgraph T0[Tier 0 - Namespaces + Landlock]
        T0K[Shared host kernel]
        T0B[backend-ns]
        T0F[Fast, ~50ms start]
    end
    subgraph T1[Tier 1 - gVisor]
        T1K[Intercepted syscalls]
        T1B[backend-gv]
        T1F[~300ms start]
    end
    subgraph T2[Tier 2 - Firecracker]
        T2K[Separate guest kernel]
        T2B[backend-fc]
        T2F[Warm pool, <20ms claim]
    end

    Tool[Tool declares min_isolation] -->|tier0| T0
    Tool -->|tier1| T1
    Tool -->|tier2| T2

    T0 -.->|fail closed| Deny[Denied + audited]
    T1 -.->|fail closed| Deny
    T2 -.->|fail closed| Deny

    style T0 fill:#161b22,stroke:#3fb950,stroke-width:2px
    style T1 fill:#161b22,stroke:#58a6ff,stroke-width:2px
    style T2 fill:#161b22,stroke:#bc8cff,stroke-width:2px
```

There is no unsandboxed fallback: without a wired isolation backend the call is **denied** (`isolation:unavailable`), never direct-spawned on the host. The only unconfined mode is the explicit `--unsafe-no-isolation` (tier0 only, refused for tier1/2), and those runs are audited as `isolation:unisolated`.

| Tier | Mechanism | Boundary | Use for | Cost and limits |
|---|---|---|---|---|
| **0** | User, mount, PID, net, IPC namespaces + Landlock + seccomp-bpf + cgroup v2 | Shared host kernel | Formatters, linters, read-only git, hosts without KVM | A kernel bug is an escape. Landlock network rules are port-based. |
| **1** | gVisor (`runsc`) | User-space kernel in front of host kernel | Untrusted code where KVM is unavailable | Syscall overhead, compatibility gaps, changing install format. |
| **2** | Firecracker microVM with jailer | Separate guest kernel via KVM | Untrusted code, package installs, anything with network access | Needs `/dev/kvm`, kernel and rootfs image management, snapshot hazards. |

---

## The seven invariants

These are the security claims toolcage makes. Each one is tied to a test suite, so a regression is a failing test and not a vibe.

```mermaid
graph TB
    subgraph Invariants[Seven Testable Invariants]
        I1[🌐 I1: No guest network<br/>except via egress proxy]
        I2[🔑 I2: No credential value<br/>in guest mem/files/env/args]
        I3[🎟️ I3: Token only narrows<br/>on delegation, never widens]
        I4[🧾 I4: Every decision recorded<br/>before action runs]
        I5[🔏 I5: Log tampering detected<br/>by audit verify]
        I6[🛡️ I6: Guest cannot loosen<br/>policy or reach engine]
        I7[🧹 I7: No cross-session<br/>state after teardown]
    end

    subgraph Tests[Test Suites]
        T1[Escape suite: raw sockets,<br/>DNS, ICMP, IPv6, tunnels]
        T2[Canary secrets planted<br/>and scanned]
        T3[200-seed property tests<br/>narrow/widen/revoke/tamper]
        T4[Write-ahead intent logging<br/>chaos tests kill supervisor]
        T5[Mutation tests flip/delete/<br/>reorder/truncate log]
        T6[sh -c denial, path traversal,<br/>exec PATH pinned]
        T7[Cross-session canary tests]
    end

    I1 -.-> T1
    I2 -.-> T2
    I3 -.-> T3
    I4 -.-> T4
    I5 -.-> T5
    I6 -.-> T6
    I7 -.-> T7

    style Invariants fill:#161b22,stroke:#3fb950,stroke-width:2px
    style Tests fill:#161b22,stroke:#58a6ff,stroke-width:2px
```

| | Invariant | Enforced and tested by |
|---|---|---|
| 🌐 **I1** | No guest process reaches any network except through the egress proxy | Escape suite: raw sockets, DNS, ICMP, IPv6, tunnels; proxy alias, metadata, and budget tests |
| 🔑 **I2** | No credential value appears in guest memory, files, environment, or arguments | Planted canary secrets scanned for; broker encryption and rotation tests |
| 🎟️ **I3** | A token can only be narrowed on delegation, never widened — and can't be minted without the host key | 200-seed multi-hop property test; narrow / widen / revoke / tamper / forgery tests; approval `needs_approval` fail-closed on unknown/empty method/host |
| 🧾 **I4** | Every decision is recorded before the action runs | Supervisor write-ahead intent logging; chaos tests that kill the supervisor mid-action |
| 🔏 **I5** | Any edit, deletion, or reordering of the audit log **below the newest retained checkpoint** is detected by `audit verify` | Mutation tests; checkpoint truncation and old-checkpoint tests |
| 🛡️ **I6** | The guest cannot loosen its own policy or reach the policy engine | `sh -c` denial, path traversal tests, fs mount checks |
| 🧹 **I7** | After teardown, no session state is reachable by another session | Cross-session canary tests |

---

## Policy

One YAML file per tool. Anything not allowed is denied.

```yaml
tool: dependency-updater
min_isolation: firecracker
fs:
  mounts:
    - path: /workspace
      mode: rw
      source: session-copy
net:
  mode: allowlist
  hosts:
    - host: registry.npmjs.org
      methods: [GET]
    - alias: github
      methods: [GET, POST]
      paths: ["/repos/acme/app/**"]
credentials:
  - name: github_token
    use_with: github
exec:
  # Optional: explicit allowlist of binaries that may run (argv[0] basenames,
  # version-tolerant). When set, ONLY these run — this is the fix for the
  # shell/interpreter denylist being inherently incomplete. Omit for the v0
  # denylist-only behaviour.
  allowlist: [dependency-updater, git]
approval:
  require_for:
    - http.request: { methods: [POST], hosts: [github] }
```

### Key policy rules

- **`sh -c` and `bash -c` are denied.** Commands are argv arrays.
- **The inline-code denylist, and where it ends.** Shells anywhere in argv are denied an inline command string, a script file, or a startup file (`--rcfile=`/`--init-file=`); interpreters (python/perl/ruby/node/lua/php) are denied every inline-code spelling (`-c`, `-e`, `-E`, `-p`, `--eval`, `-r`, `-R`, bundled clusters), the program-extraction flag `-x`, and python's `-m` (the cwd lands on `sys.path[0]`); the awk family is denied outright (its program text *is* code, and `system()` gives it the shell); `env -S`/`--split-string` are denied (a whole command line reassembled at exec time). Residuals the denylist cannot see: GNU `sed`'s `e` command, interpreters run with a script file (`python3 script.py` — allowed by design), and tools that exec on their own (`find -exec`, `xargs`, git hooks). If a policy needs any of those binaries, spell out `exec.allowlist` and review what each is permitted to reach.
- **`exec.allowlist`** (optional) names the binaries that may run — anything else is denied, closing the wrapper/rename/flag-spelling holes a denylist leaves. The denylist still applies on top: an allowlisted interpreter cannot take inline code (`-c`, `-e`, `-p`, `-r`, …) or a shell script file.
- **Bare binary names resolve only from the sandbox's fixed PATH** (`/usr/bin:/bin`), never from the workspace: the guest chdirs into its workspace before exec, and a bare name the PATH search misses is a hard error — not a silent fallback that would run a guest-written file under an allowlisted name. Non-absolute PATH entries are ignored, candidates must be executable, and Tier 1 resolves bare names the same way.
- **Hosts and methods match case-insensitively.** Mount paths are canonicalized (`/workspace/a/../b` becomes `/workspace/b`) and `..` escapes are denied.
- **Cloud metadata endpoints** (`169.254.169.254`, `metadata*`, `instance-data`) are never reachable.
- **Credentials are bound to destinations with `use_with`.** They are not attached to requests for any other host.
- **Approval gates pause the call** (exit code 3 on the CLI — `fetch` and `mcp call` alike; a policy denial is exit 2). A timeout is a denial. Gate polarity: an **unknown** method or host (omitted/empty) *fires* the gate — an unattributable request could be the gated one, so a human decides; only a known-and-non-matching value (GET against a POST gate) passes.

### Capability tokens

```bash
tc token keygen    --out-prefix /tmp/k                          # host secret
tc token mint      --rev root-1  --out root.tok  --key-hex /tmp/k.key.hex
tc token attenuate --parent root.tok --rev child-1 --out child.tok \
                    --hosts github --key-hex /tmp/k.key.hex      # narrow only
tc token revoke    --rev root-1 --out revoked.json              # revocation list for --revocation-file
```

```mermaid
sequenceDiagram
    participant User
    participant Toolcage as toolcage
    participant Token as Capability Token

    User->>Toolcage: token keygen --out-prefix /tmp/k
    Toolcage->>User: HMAC-SHA256 host key

    User->>Toolcage: token mint --rev root-1 --key-hex /tmp/k.key.hex
    Toolcage->>User: root token (rev_id: root-1)

    User->>Toolcage: token attenuate --parent root.tok --rev child-1 --hosts github
    Toolcage->>User: child token (rev_id: child-1, ancestors: [root-1])

    Note over Token: HMAC binds rev_id + parent + ancestors + rights
    Note over Token: A holder cannot strip, hide, or pad an ancestor
    Note over Token: Revoking root-1 kills child-1 and entire subtree
```

Tokens carry scoped, expiring authority and are revocable. Tags are **HMAC-SHA256 keyed with the host secret**, so a guest that reads a token can neither mint a sibling nor widen anything: forged and hand-edited tokens fail verification and are denied. Expiry is enforced, paths are traversal-normalized, and an empty rights list grants nothing on that axis. `fetch` requires a policy allow **and** a token that verifies against `--key-hex` — without a key, a presented token is denied, never waved through.

Revocation covers the **whole subtree**: revoking a `rev_id` kills every token delegated from it, including ones that were never tracked explicitly, while revoking a child never affects its parent. This holds because every token carries its **signed lineage** (root first, immediate parent last) inside the HMAC — a holder cannot strip, hide, or pad an ancestor to survive its revocation — and the walk terminates even on hostile link shapes. The same `--revocation` flag is honored by `mcp serve`, `mcp call`, and `fetch`.

---

## Secrets

![Credential flow](assets/secrets.svg)

![Credential flow animation](assets/credential-flow-anim.svg)

- The guest holds `secret:name` placeholders. Literal values in `env_refs` are rejected.
- The broker store is **encrypted at rest** and supports rotation; its `Debug` output is redacted. Saves and rotations are atomic (0600 temp file, fsync, rename) and never world-readable, even transiently.
- The proxy resolves DNS, enforces `host + method + path`, and attaches the credential upstream.
- Responses are scrubbed. If an API echoes the token, it's removed before the guest sees it.
- Package installs use two-phase sessions: setup talks only to a pinned mirror, then the run phase gets a narrowed or closed network.
- Per-destination byte and request budgets are persisted (fsync'd) and survive restarts.

---

## Audit log

![Audit hash chain](assets/audit.svg)

![Audit chain growth animation](assets/audit-chain-anim.svg)

```mermaid
graph LR
    A[Event N] -->|H(prev, canonical)| B[Event N+1]
    B -->|H(prev, canonical)| C[Event N+2]
    C -->|...| D[Event N+k]

    D -.->|Every N events or T seconds| E[Checkpoint]
    E -.->|Ed25519 sign (seq, head, time)| F[Signed checkpoint]

    style A fill:#161b22,stroke:#bc8cff,stroke-width:2px
    style B fill:#161b22,stroke:#bc8cff,stroke-width:2px
    style C fill:#161b22,stroke:#bc8cff,stroke-width:2px
    style D fill:#161b22,stroke:#bc8cff,stroke-width:2px
    style E fill:#1c2230,stroke:#d29922,stroke-width:2px
    style F fill:#1c2230,stroke:#d29922,stroke-width:2px
```

`audit verify` checks chain continuity, monotonic sequence with no gaps, a re-hash of every event, and checkpoint signatures against a pinned public key. Old checkpoints and truncated tails fail. The writer re-verifies the chain on open, so a corrupt log is never extended.

### Scope of detection

The chain hash is unkeyed (SHA-256 over public fields), so anyone can recompute a self-consistent chain; what makes it tamper-*evident* is the signed checkpoints pinning `(seq, head)` to a prefix. Concretely: tampering **below the newest retained checkpoint** is detected, but edits, deletions, or reordering of the **tail after that checkpoint** are not — unless a newer checkpoint is anchored externally (a second machine, a transparency log). Delete the newer `<log>.checkpoint.*` files, rewrite the tail, and `audit verify` passes. Store checkpoints somewhere the log writer can't reach if you need tail integrity.

```bash
# Freeze a log after suspected compromise
tc panic --audit /path/to/log.jsonl
# Appends terminal deny-all event, creates .tainted marker
# Writer refuses the log from then on (write-ahead gate)
```

`audit events` lists log events newest-first, with optional `--session`, `--action`, `--decision`, and `--limit` filters — useful for reviewing what the agent actually did.

---

## CLI reference

| Command | Purpose |
|---|---|
| `tc doctor` | Probe the namespace stack (userns/mount/net/ipc/pid/uts), cgroup v2, Landlock ABI, seccomp, `/dev/kvm` |
| `tc run --tier T -- <argv>` | Policy check, audit intent, exec with cleared env (1 MiB streaming output cap, 30 s kill), audit outcome. `--unsafe-no-isolation` opts out of the cage (tier0 only, audited) |
| `tc check-net --host H --method M --path P` | Proxy decision and upstream resolution, no network touched |
| `tc fetch [--token T] [--revocation R] [--revocation-file F] [--approve]` | Proxy + broker fetch with dual auth and approval pause (revocation checked against the token, its signed ancestry, and a persisted revocation file); scrubbed body; both steps audited |
| `tc token keygen / mint / attenuate / revoke` | Host MAC key; create root tokens; delegate narrower ones; write a revocation list (JSON) for `--revocation-file` |
| `tc image sign --dir D --key-hex K` | Ed25519-sign a golden image manifest (`signature.bin`) — what `GoldenImage::load` verifies before trusting the image |
| `tc image verify --dir D --pubkey P` | Verify a signed image manifest against a pinned Ed25519 public key |
| `tc mcp serve / call [--revocation-file F] [--approve]` | Stdio JSON-RPC front door; `--revocation-file` merges a persisted revocation list with `--revocation` ids; `--approve` answers a gated call out of band (else the call pauses, exit 3) |
| `tc audit keygen / checkpoint / verify / events` | Keys, signed checkpoints, pinned-key verification; list audit log events (newest first) with optional filters |
| `tc panic --audit LOG` | Freeze a log after a suspected compromise |

**Dependency security:** Every push/PR, the nightly advisory refresh, and every release run `cargo-audit` (RustSec vulnerabilities fail the build) and `cargo-deny` (permissive-only licenses, crates.io-only sources). The exception lists — `audit.toml` / `deny.toml` — carry a reason and a review date for every ignore.

**Guest-agent protocol** (`Exec` / `PutFile` / `Heartbeat`): bounded argv, no NUL bytes, `env_refs` must be `secret:name`, writes confined to `/workspace`.

**Clients:** [`clients/python/toolcage.py`](clients/python/toolcage.py), [`clients/ts/toolcage.ts`](clients/ts/toolcage.ts).

---

## MCP front door

`mcp serve` exposes four tools over stdio JSON-RPC. The wire protocol is **JSON-RPC 2.0** (version-checked requests, standard error codes, responses carry exactly one of `result`/`error`, notifications get no reply, bounded frames and ids). Each tool is a policy-checked action:

| Tool | Action | Notes |
|---|---|---|
| `run_command` | `proc.exec` | argv array; `sh -c` denied; runs inside the `--tier` cage (default tier0), denied without one |
| `read_file` | `fs.read` | mount-checked |
| `write_file` | `fs.write` | mount-checked |
| `http_fetch` | `http.request` | proxy + broker, dual auth |

```mermaid
sequenceDiagram
    participant Agent
    participant MCP as mcp serve
    participant Supervisor
    participant Proxy
    participant Broker

    Agent->>MCP: tools/call run_command {argv: ["/bin/ls"]}
    MCP->>Supervisor: exec request + token
    Supervisor->>Supervisor: policy check + token verify
    Supervisor->>Supervisor: write INTENT to audit
    Supervisor->>Supervisor: spawn guest at tier
    Supervisor->>Proxy: network requests via vsock
    Proxy->>Broker: inject credential if bound
    Broker-->>Proxy: scrubbed response
    Proxy-->>Supervisor: response
    Supervisor->>Supervisor: write OUTCOME to audit
    Supervisor-->>MCP: stdout/stderr/exit
    MCP-->>Agent: JSON-RPC response
```

Third-party MCP servers run as **guest processes** under the same policy and audit trail, so a poisoned tool becomes a contained process. **Learn mode** (`--learn` on `mcp call`/`mcp serve`) records denials and prints a proposed allowlist addition at exit so you don't write policy by hand — proposals are for operator review and are never applied automatically.

---

## Tests

`cargo test --workspace` runs the full suite green with clippy clean — the current count and per-suite breakdown live in [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) (regenerated from the run; counts here went stale every commit when duplicated).

### Coverage

`cargo-tarpaulin` measures statement coverage across the workspace (excluding the fuzz workspace and `toolcage-backend-ns`, whose exec tests fork processes that segfault under instrumentation). Coverage is enforced in CI (`--fail-under 80`).

| Crate | Coverage |
|---|---|
| policy | 91.3% |
| audit | 85.5% |
| capability | 86.9% |
| backend-fc | 71.9% |
| guest-agent | 71.1% |
| supervisor | 67.5% |
| proxy | 61.7% |
| backend-gv | 52.2% |
| mcp | 42.2% |
| cli | 13.5% |
| backend-ns | n/a (excluded — fork-heavy exec tests segfault under instrumentation) |

Lower-coverage crates are CLI argument parsing (cli), the MCP front door (mcp) and gVisor plumbing (backend-gv); they are covered by CLI-level and integration tests rather than unit tests. Raising coverage in these crates is a known improvement area.

### Beyond unit tests the suite includes:

- 🎯 **Escape suite** against the policy and proxy (I1, I6), and a Tier 2 escape suite asserting the design closes each exit — vsock-only with no network device ever configured, jailer confinement of the VMM process, and a control-channel escape matrix
- 🐞 **Fuzzing** of the policy, guest-agent, audit, proxy, and MCP JSON-RPC parsers (nightly campaigns + commit-time smoke twins)
- 💥 **Chaos tests** that fail the audit disk, proxy, and broker, revoke tokens mid-run, and exceed budgets, asserting every case fails closed
- 📐 **Property tests** over capability chains (200 seeds): a delegation never widens, and revoking an ancestor kills the whole subtree
- 🧬 **Mutation tests** on the audit log (flip, delete, reorder, truncate)
- 🏕️ **Tier 0 live isolation tests**: command executes, network namespace blocks egress, Landlock blocks file access, environment is cleared

Live Tier 0 tests **skip loudly** on hosts that can't provide the namespace stack or Landlock (GitHub's hosted runners allow user namespaces but block mount/net/ipc/pid/uts — probes test the real thing, not sysctls), and `run --tier tier0` refuses to start with a clear error instead of downgrading.

Full breakdown: [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md).

### Benchmarks

Measured on the development host, October 2026. Re-run `scripts/bench.sh` on yours.

| Metric | Target | Result |
|---|---|---|
| Policy decision p99, in-process | < 5 ms | **404 ns** (p50 340 ns, max 6.0 µs, n = 10k) |
| Audit append, fsync per event | ≥ 10,000 eps | **~270,000 eps** (n = 5k) |
| `run` end-to-end, Tier 0 | n/a | 53 ms/call (n = 200, measured before isolation was enabled) |
| Tier 2 warm-claim start latency | track p50/p99 by tier | p50 19.9 ms, p99 20.2 ms (n = 20; includes the mock API's ~10 ms accept poll — real firecracker is sub-ms, so read it as the orchestration ceiling and its trend) |
| Supervisor idle memory | < 100 MB | **3.82 MB** (RSS of a constructed supervisor after one policy decision; `cargo test -p toolcage-supervisor --test memory -- --nocapture`) |

The audit figure is filesystem-dependent (tmpfs may not flush durably) and is a baseline, not a durability claim. The 53 ms figure predates real isolation and will be higher now.

---

## Status and known limits

**toolcage is alpha and has not had independent security review.** The project's own review package ([`docs/REVIEW.md`](docs/REVIEW.md)) treats that review as a gate before any public security claim. Until it happens, treat the invariants above as *tested design goals*, not audited guarantees.

| Area | State |
|---|---|
| Tier 0 (namespaces, Landlock, seccomp) | Implemented, with live isolation tests. Landlock is **mandatory** (fail-closed): if the kernel can't provide it, session creation is denied and the child refuses to run — no silent fallback to namespaces-only. The handled rights follow the running kernel's ABI: on Landlock ABI 1 (Linux 5.13–6.1), `refer` (ABI 2+) and `truncate` (ABI 5+) are **unrestricted** there — the kernel cannot bound a right it does not know. `doctor` reports the detected ABI. |
| Tier 1 (gVisor) | Functional as wired: `runsc create --bundle` with the upstream argument shape, a complete OCI spec (`process.args`, `cwd`, `/proc`, devices), SIGKILL + polled `delete` cleanup, and id/path validation. CI installs `runsc` on the runner and runs the driver suite against it on every merge (the `tier1-gvisor` job); arg-shape and spec-shape tests cover the rest. |
| Tier 2 (Firecracker) | Functional as wired: the jailer actually launches the VM (nothing launched one before), `/boot-source` is configured before `InstanceStart` (Firecracker rejects a start without it), then machine-config → drives → vsock → start over the API; snapshot-restored VMs resume with `PATCH /vm {"state":"Resumed"}` (the `InstanceStart` action is for fresh boots only); warm-pool failures surface as errors (only an empty pool falls back to a fresh boot) and a failed pool VM is torn down, not leaked; and `destroy()` kills the firecracker process. REST ordering, the resume verb, pool failure handling, and the Tier 2 escape suite (vsock-only with no network device ever configured, jailer confinement of the VMM process, and a control-channel escape matrix) are tested against a mock API socket; the create-time socket check refuses symlinks and stale plants; warm-claim start latency is benchmarked in `scripts/bench.sh`. The `tier2-firecracker` CI job exercises the driver suite on every merge; a full microVM boot needs `/dev/kvm` on the runner, which hosted runners don't guarantee. |
| seccomp-BPF | Defense in depth alongside namespaces + Landlock. The filter itself is valid — an invalid BPF addressing mode used to make `PR_SET_SECCOMP` fail with `EINVAL` on *every* kernel (the old note here blamed "some kernels"); that is fixed, and the workload runs under the filter **where the kernel accepts seccomp**. `doctor` probes yours: some kernel builds (including this dev host's) return EINVAL and Tier 0 continues with namespaces + Landlock, loudly. The blocklist is written with named `libc::SYS_*` constants and pinned to the kernel's numbers by a test: an earlier bare-number table blocked the wrong syscalls (wait4 and prctl under "chroot"/"nis+" labels — both fixed, the workload can wait for children and name threads again) while `chroot` (161) and the new mount API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) claimed coverage but were never listed — all of those are genuinely denied now. |
| Audit throughput | fsync per append (crash-safe). Group commit is the next step if throughput is ever needed. |
| Secret handling | `fetch --secret-value` takes the credential as a CLI flag, so it is visible to other local users via `ps`/`/proc/*/cmdline` and usually lands in shell history — despite "stays host-side". **Use `--secret-file` instead**: it is read host-side and never appears on argv. Keys written by `token keygen` / `audit keygen` are `0600`; the `--secret-value` path is not. |
| Scope | Linux only. No GPU workloads, no multi-tenant hosting, no Windows or macOS guests. |

### Things the design does **not** do, by construction:

- It doesn't decide whether an *allowed* action is wise. An agent permitted to `POST` to a repo can do damage inside that scope. Use approvals and budgets on high-impact destinations.
- It doesn't protect a compromised host. The supervisor, broker, and log live on the host and are trusted.
- Tier 0 is not a defense against kernel exploits.

---

## Repository layout

```text
crates/
  supervisor/    exec (env_clear, argv hash, output cap, timeout kill), fetch_via_proxy, panic_freeze
  policy/        YAML v0 loader, allowlist + forbid evaluator, approval gates, escape tests
  proxy/         alias resolution, method/path enforcement, budgets, blocked-IP checks
  broker/        encrypted host-only secret store, inject-if-bound, echo scrubbing, canaries
  capability/    attenuate-only tokens, expiry, revocation, property tests
  approval/      require_for gates, out-of-band queue (timeout = deny)
  backend/       Tier trait + fail-closed honors()
  backend-ns/    Tier 0 driver + host probe
  backend-gv/    Tier 1 (gVisor runsc) driver
  backend-fc/    Tier 2 (Firecracker) driver, warm pool
  guest-agent/   PID 1 protocol with input validation
  mcp/           stdio MCP server, sandboxed host check, learn mode
  audit/         hash-chain writer, Ed25519 checkpoints, verifier library
  verify/        standalone log verifier
  cli/           the command-line binary
clients/         Python and TypeScript clients
docs/            THREAT_MODEL.md, TEST_RESULTS.md, REVIEW.md
fuzz/            fuzz targets
images/          guest image build (manifest + sha256, per-host-class goldens)
schemas/         audit-event-v0.json, policy-v0.yaml
scripts/         doctor.sh, bench.sh
assets/          banner, architecture, tiers, secrets, audit and demo SVGs
```

---

## Security

Found a vulnerability or a broken invariant? Please report it privately through **Security → Report a vulnerability** on this repository instead of opening a public issue. Any finding that invalidates an invariant blocks public security claims until it is fixed.

---

## License

Apache-2.0 OR MIT. See [LICENSE](LICENSE) and [LICENSE-MIT](LICENSE-MIT).

---

<div align="center">

<sub>

[Threat model](docs/THREAT_MODEL.md) · [Test results](docs/TEST_RESULTS.md) · [Review package](docs/REVIEW.md)

**Designed to be verified, not trusted.** The project's security properties are backed by an explicit test suite and a documented threat model.

</sub>

</div>