<div align="center">

# toolcage

**Every agent tool call runs inside a disposable cage — least-privilege capabilities, zero visible secrets, and a verifiable receipt.**

[Quickstart](#-quickstart-60-seconds) • [How it works](#-how-it-works) • [Guarantees](#-the-four-guarantees) • [Policy](#-policy-in-one-file) • [CLI](#-cli-reference) • [MCP](#-mcp-front-door) • [Threat model](docs/THREAT_MODEL.md) • [Test results](docs/TEST_RESULTS.md)

</div>

---

## ✨ Why toolcage?

Agents don't just run code — they read untrusted content, call third-party tools, and install packages. A sandbox that only blocks escapes misses the real risks.

| Agent risk | toolcage answer |
|------------|-----------------|
| Prompt injection says "exfiltrate the key" | Guest never holds the key — broker injects it host-side, for allowed destinations only |
| Malicious MCP server / poisoned package | Runs as a contained guest process under the same policy + audit trail |
| "It worked on my machine" / "who did what?" | Every decision is hash-chained and checkpoint-signed — `audit verify` proves it |

**Design center:** not another code-interpreter box. toolcage is the **policy + secrets + evidence layer** on top of isolation.

---

## 🚀 Quickstart — 60 seconds

```bash
cargo build --release

# 1. Check your host (userns, cgroup v2, Landlock ABI, seccomp, /dev/kvm)
./target/release/toolcage doctor
# userns=true cgroup2=true landlock_abi=5 seccomp=true kvm=true

# 2. Run something under policy + audit (no shell, argv arrays only)
./target/release/toolcage run \
  --policy schemas/policy-v0.yaml \
  --audit /tmp/tc.jsonl \
  --tier tier0 -- /bin/echo hello

# 3. Try the evil twin (denied + audited)
./target/release/toolcage run \
  --policy schemas/policy-v0.yaml \
  --audit /tmp/tc.jsonl \
  --tier tier0 -- sh -c 'echo pwned'
# denied: shell -c is not allowed; use argv arrays

# 4. Fetch through the proxy — secret injected host-side, scrubbed guest-side
./target/release/toolcage fetch \
  --policy schemas/policy-v0.yaml --audit /tmp/tc.jsonl \
  --host github.internal --method GET --path /repos/acme/app/issues/1 \
  --cred github_token --secret-value s3cr3t
# body: upstream api.github.com/... ok auth=[REDACTED]

# 5. Prove the log — then tamper with one byte and watch it fail
./target/release/toolcage audit keygen --out-prefix /tmp/k
./target/release/toolcage audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
./target/release/toolcage audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex
# ok: N events, head ... (checkpoints verified)
```

---

## 🧭 How It Works

Every agent tool call crosses one small trusted core — the supervisor — which decides, records, isolates, proxies, and proves.

```
┌─────────┐    exec + token    ┌─────────────┐
│ Agent   │ ──────────────────►│ Front Door  │
└─────────┘                    └──────┬──────┘
                                      │
                                      ▼
                               ┌─────────┴─────────┐
                               │   Policy Engine   │◄─────────┐
                               └─────────┬─────────┘          │
                                         │                   │
                                         ▼                   │
                               ┌─────────┴─────────┐         │
                               │   Audit Log       │◄────────┘
                               │   (intent)        │
                               └─────────┬─────────┘
                                         │
                                         ▼
                               ┌─────────┴─────────┐
                               │   Cage (T0/T1/T2) │
                               │   namespaces      │
                               │   Landlock        │
                               │   seccomp         │
                               └─────────┬─────────┘
                                         │
                                         ▼
                               ┌─────────┴─────────┐
                               │   Egress Proxy    │
                               │   DNS + method +  │
                               │   path check      │
                               └─────────┬─────────┘
                                         │
                                         ▼
                               ┌─────────┴─────────┐
                               │ Credential Broker │
                               │   inject at proxy │
                               └─────────┬─────────┘
                                         │
                                         ▼
                               ┌─────────┴─────────┐
                               │   Internet        │
                               └───────────────────┘
```

Three rules with no exceptions:

1. **No direct network from the guest.** Only the proxy dials.
2. **No credentials in the guest.** Only `secret:name` placeholders.
3. **No action without a log entry.** Intent is written *before* the action runs — if the write fails, the action is denied.

---

## 🛡️ The Four Guarantees

| Guarantee | How |
|-----------|-----|
| **1. Disposable isolation** | One API, three backends — picked per-tool by risk. Fail-closed — never silently downgraded. |
| **2. Capabilities, not ACLs** | Tokens narrow on delegate. Never widen. Expiry enforced, traversal-normalized, revocable. |
| **3. Secret-free guest** | Broker holds secrets, injects at proxy for allowed dests only. Echoes scrubbed. |
| **4. Tamper-evident log** | `hash = H(prev_hash, canonical(event))` + Ed25519 checkpoints bound to `(seq, head)`. |

---

## 🧊 Isolation Tiers

| Tier | Mechanism | Best for | Cost |
|------|-----------|----------|------|
| **T0** | namespaces + Landlock + seccomp | formatters, linters, read-only git | ~50 ms |
| **T1** | gVisor runsc | untrusted code where KVM unavailable | ~300 ms |
| **T2** | Firecracker µVM | untrusted code, package installs, network | snapshot pool |

> A tool declares `min_isolation`. If the host can't provide it, the call is **denied and audited**. Never silently downgraded.

---

## 🔐 Secrets Never Cross the Boundary

The guest holds `secret:name` placeholders — never values in env, args, files, or memory. The proxy resolves DNS, enforces `host + method + path`, attaches the credential upstream, and scrubs echoes.

Two-phase sessions: setup talks only to a pinned package mirror, run phase uses a narrowed or closed network.

---

## 🧾 Every Action Leaves a Receipt

Intent is logged *before* the action runs. If the write fails, the action is denied. The writer re-verifies the chain on open, so a corrupt log is never extended. Checkpoints bind `(seq, head, time)` with Ed25519 — flip one byte, delete, or reorder, verification fails.

```bash
toolcage audit keygen --out-prefix /tmp/k
toolcage audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
toolcage audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex
# ok: N events, head ... (checkpoints verified)
```

---

## 📜 Policy in One File

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

Decision order: `canonicalize at enforcement point → operator forbid wins → token checks → approval gate (timeout = deny) → log before act`.

`sh -c` / `bash -c` is denied — use argv arrays. Hosts and methods match case-insensitively. Mounts are canonicalized (`/workspace/a/../b` → `/workspace/b`), and `..` escapes outside mounts are denied. Tokens are traversal-normalized and expiry-enforced too. Metadata (`169.254.169.254`, `metadata*`, `instance-data`) is never reachable.

---

## 🖥️ CLI Reference

| Command | What it does |
|---------|-------------|
| `toolcage doctor` | Probe userns, cgroup v2, Landlock ABI, seccomp, `/dev/kvm` |
| `toolcage run --tier tier0 -- <argv>` | Policy check → audit intent → `env_clear` exec (streaming 1 MiB cap, 30 s kill) → audit outcome |
| `toolcage check-net --host H --method M --path P` | Proxy decision + upstream resolution, no network touched |
| `toolcage fetch [--token T] [--approve]` | Proxy + broker fetch with dual-auth (policy AND token) and approval pause (exit 3); scrubbed body, both steps audited |
| `toolcage token mint --rev ID --out F` | Mint a root capability token |
| `toolcage token attenuate --parent P --rev ID --out F` | Narrow-only delegation — widen rejected |
| `toolcage mcp serve / call` | Stdio JSON-RPC: `run_command`, `read_file`, `write_file`, `http_fetch` |
| `toolcage audit keygen / checkpoint / verify` | Ed25519 keygen, signed checkpoints, pinned-pubkey verify |
| `toolcage panic --audit LOG` | Freeze log with `deny-all` event + `.tainted` marker |

Guest-agent protocol (`Exec` / `PutFile` / `Heartbeat`): argv bounded, no NUL bytes, `env_refs` must be `secret:name` (literal values rejected), writes confined to `/workspace`.

---

## 🔌 MCP Front Door

| Tool | Maps to |
|------|---------|
| `run_command` | `proc.exec` (argv array, `sh -c` denied) |
| `read_file` | `fs.read` (mount-checked) |
| `write_file` | `fs.write` (mount-checked) |
| `http_fetch` | `http.request` (proxy + broker, dual-auth) |

Third-party MCP servers run as **guest processes** under the same policy and audit trail — tool-poisoning becomes a contained process. Includes a learn mode that records denials and proposes a working allowlist.

---

## 🎯 Threats Handled

| Path | Control |
|------|---------|
| Sandbox escape | Tiered isolation + jailed VMM |
| Exfil via HTTP/DNS/ICMP/IPv6 | vsock-only guest, proxy-resolved DNS, no metadata route |
| Exfil via allowed tool (`git push`) | Per-dest method/path/byte budgets + approvals |
| Credential theft | Broker-only secrets, canary-tested |
| Persistence | Ephemeral sessions, golden-image-only snapshots |
| Lateral movement | No guest-reachable control socket |
| Log tampering | Hash chain + head-bound signed checkpoints |

Full model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) · Results: [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)

---

## 📊 Benchmarks

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| Policy decision p99 (in-process) | < 5 ms | 404 ns (p50 340 ns, max 6.0 µs, n=10k) | ✅ |
| Audit append throughput | ≥ 10,000 eps | ~270,000 eps (fsync per append, n=5k) | ✅ |
| CLI run end-to-end (Tier0 stub exec) | — | 53 ms/call (n=200) | baseline |

Run `scripts/bench.sh` to re-measure on any host.

---

## 📂 Repository Layout

```text
crates/
  supervisor/    exec (env_clear, argv-hash, streaming cap, timeout kill), fetch_via_proxy (token+approval), panic_freeze
  policy/        YAML v0 loader, allowlist + forbid evaluator, approval gates, tests/escape.rs
  proxy/         alias resolve, method/path enforcement, budgets
  broker/        host-only store (redacted Debug), inject-if-bound, scrub echo, canaries
  capability/    attenuate-only tokens (expiry + traversal-safe), tag integrity, revocation, 200-seed property test
  approval/      require_for gates, out-of-band queue (timeout = deny)
  backend/       Tier trait + honors() fail-closed
  backend-ns/    Tier0 driver + probe (userns/cgroup2/Landlock/seccomp)
  backend-gv/    Tier1 runsc driver (OCI bundle, honors tier0/1)
  backend-fc/    Tier2 driver (jailer argv, vsock-only, WarmPool + uniqueness steps)
  guest-agent/   PID1 protocol (Exec/PutFile/Heartbeat) + validate()
  mcp/           stdio tools/call x4, sandboxed host check, learn mode
  audit/         hash-chain writer (verify-on-open, fsync), head-bound Ed25519 checkpoints, verify_with_pubkey
  verify/        standalone verifier
  cli/           run, check-net, fetch --token/--approve, token, mcp, audit keygen/checkpoint/verify, doctor, panic
schemas/         audit-event-v0.json, policy-v0.yaml
scripts/         doctor.sh, bench.sh
docs/            THREAT_MODEL.md, TEST_RESULTS.md, REVIEW.md
images/          build.sh (manifest + sha256, per-host-class goldens)
clients/         python/toolcage.py, ts/toolcage.ts
```

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE).

</div>