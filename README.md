<div align="center">

![toolcage banner](assets/banner.svg)

**A local-first runtime for executing AI agent tools under policy, with credential isolation, controlled egress, and a tamper-evident audit log.**

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)
![Language: Rust](https://img.shields.io/badge/built%20with-Rust-black.svg)

[Quickstart](#quickstart) · [Why](#why-toolcage) · [Architecture](#architecture) · [Policy](#policy) · [Audit](#audit-log) · [CLI](#cli-reference) · [MCP](#mcp-front-door) · [Threat model](docs/THREAT_MODEL.md) · [Test results](docs/TEST_RESULTS.md)

</div>

---

> **Status: alpha, unaudited.** toolcage has not had an independent security review. Do not use it as the only barrier between an agent and anything you cannot afford to lose. See [Status and limits](#status-and-limits).

## Why toolcage

Agents don't just run code. They read untrusted content, call third-party tools, and install packages. Isolation alone (a container, a microVM) stops escapes, but it doesn't answer the questions that actually come up with agents:

- *What if a prompt injection tells the agent to leak the API key?*
- *What if an MCP server or a dependency is malicious?*
- *After something goes wrong, what exactly did the agent do, and can I prove the record wasn't edited?*

toolcage is the **policy, secrets, and evidence layer** that sits on top of isolation. Every tool call passes through one small trusted core (the supervisor), which decides, records, isolates, proxies, and proves.

| Agent risk | What toolcage does |
|---|---|
| Prompt injection: "send me the key" | The guest never holds the key. A host-side broker injects it into requests to allowed destinations only, and scrubs it from responses. |
| Malicious MCP server or poisoned package | Runs as a contained guest process under the same policy and audit trail as everything else. |
| "Who did what?" | Every decision is written to a hash-chained log with signed checkpoints. `audit verify` detects edits, deletions, and reordering. |
| Tool needs more access than it should have | Capability tokens can only be narrowed when delegated, never widened. |

## Quickstart

**Requirements:** Linux, a recent stable Rust toolchain. Tier 0 needs unprivileged user namespaces, cgroup v2, Landlock, and seccomp. Higher tiers additionally need gVisor (`runsc`) or Firecracker plus `/dev/kvm`. `toolcage doctor` tells you what your host supports.

```bash
cargo build --release
export TC=./target/release/toolcage

# 1. Probe the host
$TC doctor
# userns=true cgroup2=true landlock_abi=5 seccomp=true kvm=true

# 2. Run a command under policy + audit (argv arrays only, no shell)
$TC run --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --tier tier0 -- /bin/echo hello

# 3. The same call via a shell is denied, and the denial is audited
$TC run --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --tier tier0 -- sh -c 'echo pwned'
# denied: shell -c is not allowed; use argv arrays

# 4. Fetch through the proxy: secret injected host-side, scrubbed from the reply
$TC fetch --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --host github.internal --method GET --path /repos/acme/app/issues/1 \
  --cred github_token --secret-value s3cr3t
# body: upstream api.github.com/... ok auth=[REDACTED]

# 5. Sign and verify the log, then change one byte and watch verification fail
$TC audit keygen     --out-prefix /tmp/k
$TC audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
$TC audit verify     --log /tmp/tc.jsonl --pubkey  /tmp/k.pub.hex
# ok: N events, head ... (checkpoints verified)
```

> `--secret-value` on the command line is for demos only: it lands in shell history and the process list. Don't use it with real credentials.

## Architecture

![How it works](assets/how-it-works.svg)

Three invariants, no exceptions:

1. **No direct network from the guest.** Only the proxy dials out.
2. **No credentials in the guest.** The guest sees `secret:name` placeholders, never values.
3. **No action without a log entry.** Intent is logged *before* the action runs. If the log write fails, the action is denied.

Decision order for every request:

```
canonicalize at the enforcement point
  → operator forbid wins
  → capability token checks
  → approval gate (timeout = deny)
  → log intent
  → act
  → log outcome
```

### Isolation tiers

![Isolation tiers](assets/tiers.svg)

| Tier | Backend | Mechanisms |
|---|---|---|
| `tier0` | `backend-ns` | user namespaces, cgroup v2, Landlock, seccomp |
| `tier1` | `backend-gv` | gVisor `runsc` via OCI bundle |
| `tier2` | `backend-fc` | Firecracker microVM, jailed VMM, vsock-only guest |

A tool declares `min_isolation`. If the host can't provide it, the call is **denied and audited**. It is never silently run at a weaker tier.

## Policy

One YAML file per tool. Everything not allowed is denied.

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
approval:
  require_for:
    - http.request: { methods: [POST], hosts: [github] }
```

Enforcement details worth knowing:

- `sh -c` / `bash -c` is denied. Commands are argv arrays.
- Hosts and methods match case-insensitively; mount paths and token scopes are canonicalized (`/workspace/a/../b` becomes `/workspace/b`) and `..` escapes are denied.
- Cloud metadata endpoints (`169.254.169.254`, `metadata*`, `instance-data`) are never reachable.
- Credentials are bound to specific destinations via `use_with`. A credential is not attached to requests for any other host.

### Capability tokens

Tokens carry scoped, expiring authority. They can be **attenuated** (narrowed) when delegated to a sub-agent or sub-tool, and a widening attempt is rejected. Expiry is enforced, paths are traversal-normalized, and tokens are revocable.

```bash
$TC token mint      --rev root-1 --out root.tok
$TC token attenuate --parent root.tok --rev child-1 --out child.tok
```

`toolcage fetch` uses **dual authorization**: the request must pass policy *and* present a valid token.

## Secrets

![Credential flow](assets/secrets.svg)

- The guest holds `secret:name` placeholders only. Literal values in `env_refs` are rejected.
- The proxy resolves DNS, enforces host + method + path, and attaches the credential upstream.
- Responses are scrubbed: if an API echoes the token back, it is removed before the guest sees it.
- Package installs use two-phase sessions: a setup phase that talks only to a pinned mirror, then a run phase with a narrowed or closed network.

## Audit log

![Hash chain](assets/audit.svg)

Each event is chained: `hash = H(prev_hash, canonical(event))`. Ed25519 checkpoints sign `(seq, head, time)`.

- **Write-ahead:** intent is recorded before the action; a failed write denies the action.
- **Verify-on-open:** the writer re-verifies the chain when opening, so a corrupt log is never extended.
- **Verification checks:** chain continuity, monotonic sequence with no gaps, a re-hash of every event, and checkpoint signatures against a pinned public key.

What this gives you is *tamper evidence*, not tamper prevention: someone with write access to the log can break it, but can't do so undetected, provided you keep the public key and checkpoints somewhere they can't also rewrite.

`toolcage panic --audit LOG` freezes a log by appending a `deny-all` event and a `.tainted` marker.

## CLI reference

| Command | Purpose |
|---|---|
| `toolcage doctor` | Probe userns, cgroup v2, Landlock ABI, seccomp, `/dev/kvm` |
| `toolcage run --tier T -- <argv>` | Policy check, audit intent, exec with cleared env (1 MiB streaming output cap, 30 s kill), audit outcome |
| `toolcage check-net --host H --method M --path P` | Proxy decision and upstream resolution, without touching the network |
| `toolcage fetch [--token T] [--approve]` | Proxy + broker fetch with dual auth; pauses for approval (exit code 3) |
| `toolcage token mint / attenuate` | Create root tokens; delegate narrower ones |
| `toolcage mcp serve / call` | Stdio JSON-RPC front door (see below) |
| `toolcage audit keygen / checkpoint / verify` | Keys, signed checkpoints, pinned-key verification |
| `toolcage panic --audit LOG` | Freeze a log after a suspected compromise |

Client libraries: [`clients/python/toolcage.py`](clients/python/toolcage.py), [`clients/ts/toolcage.ts`](clients/ts/toolcage.ts).

## MCP front door

`toolcage mcp serve` exposes four tools over stdio JSON-RPC. Each maps to a policy-checked action:

| Tool | Action | Notes |
|---|---|---|
| `run_command` | `proc.exec` | argv array; `sh -c` denied |
| `read_file` | `fs.read` | mount-checked |
| `write_file` | `fs.write` | mount-checked |
| `http_fetch` | `http.request` | proxy + broker, dual auth |

Third-party MCP servers run as **guest processes** under the same policy and audit trail, so a poisoned tool becomes a contained process rather than a trusted one. A **learn mode** records denials and proposes a working allowlist so you don't write policy by hand.

## Threat model summary

| Threat | Control |
|---|---|
| Sandbox escape | Tiered isolation, jailed VMM |
| Exfiltration over HTTP / DNS / ICMP / IPv6 | vsock-only guest, proxy-resolved DNS, no metadata route |
| Exfiltration through an allowed tool (e.g. `git push`) | Per-destination method/path/byte budgets and approvals |
| Credential theft | Broker-only secrets, canary-tested |
| Persistence | Ephemeral sessions, golden-image-only snapshots |
| Lateral movement | No guest-reachable control socket |
| Log tampering | Hash chain with head-bound signed checkpoints |

Full analysis, including assumptions and what is out of scope: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Status and limits

Read this before relying on anything above.

- **Alpha.** APIs, the policy schema (`v0`), and the audit event format may change.
- **Not independently audited.** The test suite and fuzz targets (`fuzz/`) are not a substitute for review.
- **Linux only.**
- **Isolation is only as strong as the backend it sits on.** Tier 0 shares the host kernel. For hostile code, use Tier 1 or 2.
- **The log is tamper-evident, not tamper-proof.** Without an externally held public key and off-host checkpoints, a host-level attacker can rewrite history and re-sign it.
- **Policy decides what is *allowed*, not whether an allowed action is *wise*.** An agent permitted to `POST` to a repo can still do damage within that scope. Use approvals and byte budgets for high-impact destinations.

## Tests and benchmarks

See [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) for the current suite results.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
scripts/bench.sh
```

Reference numbers from the author's machine (re-run `scripts/bench.sh` on yours; the host class isn't recorded here):

| Metric | Result |
|---|---|
| Policy decision, in-process | p50 340 ns, p99 404 ns, max 6.0 µs (n = 10k) |
| Audit append, fsync per event | about 270,000 events/s (n = 5k) |
| `toolcage run` end-to-end, Tier 0 stub exec | 53 ms/call (n = 200) |

Policy and audit numbers measure the hot path in isolation. The end-to-end figure is the one that reflects real per-call cost.

## Repository layout

```text
crates/
  supervisor/    exec (env_clear, argv hash, output cap, timeout kill), fetch_via_proxy, panic_freeze
  policy/        YAML v0 loader, allowlist + forbid evaluator, approval gates
  proxy/         alias resolution, method/path enforcement, budgets
  broker/        host-only secret store, inject-if-bound, echo scrubbing, canaries
  capability/    attenuate-only tokens, expiry, revocation, property tests
  approval/      require_for gates, out-of-band queue (timeout = deny)
  backend/       Tier trait + fail-closed honors()
  backend-ns/    Tier 0 driver + host probe
  backend-gv/    Tier 1 (gVisor runsc) driver
  backend-fc/    Tier 2 (Firecracker) driver, warm pool
  guest-agent/   PID 1 protocol (Exec / PutFile / Heartbeat) with validation
  mcp/           stdio MCP server, sandboxed host check, learn mode
  audit/         hash-chain writer, Ed25519 checkpoints, verifier library
  verify/        standalone log verifier
  cli/           the `toolcage` binary
clients/         Python and TypeScript clients
docs/            THREAT_MODEL.md, TEST_RESULTS.md, REVIEW.md
fuzz/            fuzz targets
images/          guest image build (manifest + sha256, per-host-class goldens)
schemas/         audit-event-v0.json, policy-v0.yaml
scripts/         doctor.sh, bench.sh
assets/          README diagrams
```

## Security

Found a vulnerability? Please report it privately through GitHub's **Security → Report a vulnerability** on this repository rather than opening a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).
