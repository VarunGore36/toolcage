<div align="center">

<svg width="860" height="200" viewBox="0 0 860 200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="toolcage banner">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0f172a"/>
      <stop offset="55%" stop-color="#1e1b4b"/>
      <stop offset="100%" stop-color="#0e7490"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#22d3ee"/>
      <stop offset="100%" stop-color="#a78bfa"/>
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="860" height="200" rx="24" fill="url(#bg)"/>
  <g opacity="0.25" stroke="#22d3ee" stroke-width="1">
    <path d="M0 150 L860 130"/>
    <path d="M0 165 L860 145"/>
    <path d="M0 180 L860 160"/>
    <circle cx="720" cy="45" r="60" fill="none"/>
    <circle cx="720" cy="45" r="35" fill="none"/>
  </g>
  <g transform="translate(60,52)">
    <rect x="0" y="0" width="96" height="96" rx="20" fill="none" stroke="url(#accent)" stroke-width="4"/>
    <line x1="0" y1="24" x2="96" y2="24" stroke="url(#accent)" stroke-width="3"/>
    <line x1="0" y1="48" x2="96" y2="48" stroke="url(#accent)" stroke-width="3"/>
    <line x1="0" y1="72" x2="96" y2="72" stroke="url(#accent)" stroke-width="3"/>
    <line x1="24" y1="0" x2="24" y2="96" stroke="url(#accent)" stroke-width="3"/>
    <line x1="48" y1="0" x2="48" y2="96" stroke="url(#accent)" stroke-width="3"/>
    <line x1="72" y1="0" x2="72" y2="96" stroke="url(#accent)" stroke-width="3"/>
    <circle cx="48" cy="48" r="14" fill="#22d3ee"/>
    <circle cx="48" cy="48" r="6" fill="#0f172a"/>
  </g>
  <text x="180" y="95" font-family="monospace" font-size="56" font-weight="bold" fill="white" letter-spacing="2">toolcage</text>
  <text x="182" y="125" font-family="monospace" font-size="16" fill="#a5f3fc">isolate • attenuate • broker • prove</text>
  <rect x="180" y="140" width="220" height="26" rx="13" fill="none" stroke="#22d3ee" stroke-width="1.5"/>
  <text x="192" y="158" font-family="monospace" font-size="13" fill="#e0f2fe">local-first agent sandbox</text>
</svg>

<p>
  <a href="https://github.com/VarunGore36/toolcage"><img src="https://img.shields.io/badge/repo-toolcage-0e7490?style=flat-square&logo=github" alt="repo"/></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="license"/>
  <img src="https://img.shields.io/badge/rust-1.98+-orange?style=flat-square&logo=rust" alt="rust"/>
  <img src="https://img.shields.io/badge/linux-cgroupv2_landlock_kvm-lightgrey?style=flat-square&logo=linux" alt="linux"/>
  <img src="https://img.shields.io/badge/tests-69_passing-brightgreen?style=flat-square" alt="tests"/>
</p>

**Every agent tool call runs inside a disposable cage — least-privilege capabilities, zero visible secrets, and a verifiable receipt.**

[Quickstart](#-quickstart-60-seconds) • [How it works](#-how-it-works) • [Guarantees](#-the-four-guarantees) • [Policy](#-policy-in-one-file) • [CLI](#-cli-reference) • [MCP](#-mcp-front-door) • [Threat model](docs/THREAT_MODEL.md) • [Test results](docs/TEST_RESULTS.md)

</div>

---

## ✨ Why toolcage?

Agents don't just run code — they read untrusted content, call third-party tools, and install packages. A sandbox that only blocks escapes misses the real risks:

| Agent risk | toolcage answer |
|---|---|
| Prompt-injected instruction says "exfiltrate the key" | Guest never holds the key — broker injects it host-side, for allowed destinations only |
| Malicious MCP server / poisoned package | Runs as a contained guest process under the same policy + audit trail |
| "It worked on my machine" / "who did what?" | Every decision is hash-chained and checkpoint-signed — `audit verify` proves it |

> **Design center:** not another code-interpreter box. toolcage is the **policy + secrets + evidence layer** on top of isolation.

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
# ok: N events, head abc123... (checkpoints verified)
```

---

## 🧭 How it works

```mermaid
flowchart LR
    Agent([Agent / MCP Client]) -->|exec + token| Front[Front Door<br/>Unix socket + MCP]
    Front --> Policy{Policy +<br/>Capability?}
    Policy -- deny --> AuditD[(Audit Log<br/>denied)]
    Policy -- allow --> AuditA[(Audit Log<br/>intent)]
    AuditA --> Cage[[Cage<br/>T0 / T1 / T2]]
    Cage -->|vsock / veth| Proxy(Egress Proxy)
    Proxy --> Broker[(Credential Broker)]
    Broker -->|inject for allowed dest| Net[(Internet)]
    Cage -->|stdout/stderr| Agent
    Proxy -->|allow/deny + bytes| AuditO[(Audit Log<br/>outcome)]
```

Three rules with no exceptions:

1. **No direct network from the guest.** Only the proxy dials.
2. **No credentials in the guest.** Only `secret:name` placeholders.
3. **No action without a log entry.** Intent is written *before* the action runs — if the write fails, the action is denied.

---

## 🛡️ The four guarantees

<div align="center">

| | Guarantee | How |
|---|---|---|
| <b>1</b> | **Disposable isolation** | One API, three backends. Picked per-tool by risk. Fail-closed — never silently downgraded. |
| <b>2</b> | **Capabilities, not ACLs** | Tokens narrow on delegate. Never widen. Expiry enforced, traversal-normalized, revocable. |
| <b>3</b> | **Secret-free guest** | Broker holds secrets, injects at proxy for allowed dests only. Echoes scrubbed. |
| <b>4</b> | **Tamper-evident log** | `hash = H(prev_hash, canonical(event))` + Ed25519 checkpoints bound to `(seq, head)`. |

</div>

---

## 🧊 Isolation tiers

<div align="center">
<svg width="760" height="210" viewBox="0 0 760 210" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="tier chart">
  <rect x="0" y="0" width="760" height="210" rx="16" fill="#0f172a"/>
  <text x="24" y="28" font-family="monospace" font-size="13" fill="#94a3b8">ISOLATION STRENGTH → STARTUP COST</text>
  <g font-family="monospace" font-size="12">
    <text x="24" y="65" fill="#e2e8f0">T0  ns+Landlock+seccomp</text>
    <rect x="250" y="48" width="120" height="18" rx="9" fill="#22d3ee"/>
    <text x="380" y="62" fill="#64748b">shared kernel · ~50ms</text>
    <text x="24" y="105" fill="#e2e8f0">T1  gVisor runsc</text>
    <rect x="250" y="88" width="260" height="18" rx="9" fill="#a78bfa"/>
    <text x="520" y="102" fill="#64748b">user-space kernel · ~300ms</text>
    <text x="24" y="145" fill="#e2e8f0">T2  Firecracker µVM</text>
    <rect x="250" y="128" width="420" height="18" rx="9" fill="#f472b6"/>
    <text x="24" y="182" fill="#64748b">separate guest kernel via KVM · snapshot pool · vsock-only net</text>
  </g>
</svg>
</div>

```text
Tier 0  namespaces (user/mount/pid/net/ipc) + Landlock + seccomp-bpf + cgroup v2
        → formatters, linters, read-only git

Tier 1  gVisor runsc (OCI runtime)
        → untrusted code where KVM is unavailable

Tier 2  Firecracker + jailer (unprivileged, own netns, tight seccomp)
        → untrusted code, package installs, anything with network
```

> A tool declares `min_isolation`. If the host can't provide it, the call is **denied and audited**. Never silently downgraded.

---

## 🔐 Secrets never cross the boundary

<div align="center">
<svg width="760" height="120" viewBox="0 0 760 120" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="credential flow">
  <rect x="0" y="0" width="760" height="120" rx="16" fill="#0f172a"/>
  <g font-family="monospace" font-size="12" text-anchor="middle">
    <rect x="20" y="30" width="160" height="60" rx="12" fill="none" stroke="#f87171" stroke-width="2"/>
    <text x="100" y="55" fill="#fecaca">GUEST</text>
    <text x="100" y="73" fill="#64748b">secret:github_token</text>
    <rect x="300" y="30" width="160" height="60" rx="12" fill="none" stroke="#22d3ee" stroke-width="2"/>
    <text x="380" y="55" fill="#a5f3fc">PROXY</text>
    <text x="380" y="73" fill="#64748b">check + inject</text>
    <rect x="580" y="30" width="160" height="60" rx="12" fill="none" stroke="#4ade80" stroke-width="2"/>
    <text x="660" y="55" fill="#bbf7d0">GITHUB</text>
    <text x="660" y="73" fill="#64748b">real token</text>
    <line x1="180" y1="60" x2="300" y2="60" stroke="#475569" stroke-width="2" stroke-dasharray="6 4"/>
    <polygon points="300,54 312,60 300,66" fill="#475569"/>
    <line x1="460" y1="60" x2="580" y2="60" stroke="#4ade80" stroke-width="2"/>
    <polygon points="580,54 592,60 580,66" fill="#4ade80"/>
  </g>
</svg>
</div>

- Guest holds `secret:name` placeholders. Never values in env, args, files, or memory.
- Proxy resolves DNS, enforces `host + method + path`, attaches the credential upstream.
- Responses are scrubbed — if an API echoes the token, it's stripped before the guest sees it.
- Two-phase sessions: setup talks only to a pinned package mirror, run phase uses a narrowed or closed network.

---

## 🧾 Every action leaves a receipt

<div align="center">
<svg width="760" height="110" viewBox="0 0 760 110" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="hash chain">
  <rect x="0" y="0" width="760" height="110" rx="16" fill="#0f172a"/>
  <g font-family="monospace" font-size="11" text-anchor="middle">
    <rect x="20" y="25" width="140" height="60" rx="10" fill="#1e293b" stroke="#22d3ee"/>
    <text x="90" y="48" fill="#e2e8f0">evt #41</text>
    <text x="90" y="66" fill="#64748b">H(genesis…)</text>
    <rect x="200" y="25" width="140" height="60" rx="10" fill="#1e293b" stroke="#22d3ee"/>
    <text x="270" y="48" fill="#e2e8f0">evt #42</text>
    <text x="270" y="66" fill="#64748b">H(#41…)</text>
    <rect x="380" y="25" width="140" height="60" rx="10" fill="#1e293b" stroke="#22d3ee"/>
    <text x="450" y="48" fill="#e2e8f0">evt #43</text>
    <text x="450" y="66" fill="#64748b">H(#42…)</text>
    <rect x="560" y="25" width="180" height="60" rx="10" fill="none" stroke="#a78bfa" stroke-dasharray="6 4"/>
    <text x="650" y="48" fill="#ddd6fe">checkpoint</text>
    <text x="650" y="66" fill="#64748b">Ed25519(seq,head)</text>
    <line x1="160" y1="55" x2="200" y2="55" stroke="#22d3ee" stroke-width="2"/>
    <line x1="340" y1="55" x2="380" y2="55" stroke="#22d3ee" stroke-width="2"/>
    <line x1="520" y1="55" x2="560" y2="55" stroke="#a78bfa" stroke-width="2"/>
  </g>
</svg>
</div>

```bash
toolcage audit keygen --out-prefix /tmp/k        # k.secret.hex (host-only) + k.pub.hex
toolcage audit checkpoint --log /tmp/tc.jsonl --key-hex /tmp/k.secret.hex
toolcage audit verify --log /tmp/tc.jsonl --pubkey /tmp/k.pub.hex
# chain continuity ✓  seq monotonic ✓  no gaps ✓  re-hash every event ✓  checkpoint sigs ✓
```

Write-ahead: intent is logged *before* the action runs. If the write fails, the action is denied. The writer re-verifies the chain on open, so a corrupt log is never extended. Checkpoints bind `(seq, head, time)` with Ed25519 and each checkpoint's head is checked against the chain prefix at that seq — an old checkpoint plus a truncated tail fails. Flip one byte, delete, or reorder — verification fails.

---

## 📜 Policy in one file

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

## 🖥️ CLI reference

| Command | What it does |
|---|---|
| `toolcage doctor` | Probe userns, cgroup v2, Landlock ABI, seccomp, `/dev/kvm` |
| `toolcage run --tier tier0 -- <argv>` | Policy check → audit intent → `env_clear` exec (streaming 1 MiB cap, 30 s kill) → audit outcome. Fail-closed vs `min_isolation`; `sh -c` denied |
| `toolcage check-net --host H --method M --path P` | Proxy decision + upstream resolution, no network touched |
| `toolcage fetch [--token T] [--approve]` | Proxy + broker fetch with dual-auth (policy AND token) and approval pause (exit 3); scrubbed body, both steps audited |
| `toolcage token mint --rev ID --out F` | Mint a root capability token |
| `toolcage token attenuate --parent P --rev ID --out F` | Narrow-only delegation — widen rejected |
| `toolcage mcp serve / call` | Stdio JSON-RPC: `run_command`, `read_file`, `write_file`, `http_fetch` |
| `toolcage audit keygen / checkpoint / verify` | Ed25519 keygen, signed checkpoints, pinned-pubkey verify |
| `toolcage panic --audit LOG` | Freeze log with `deny-all` event + `.tainted` marker |

Guest-agent protocol (`Exec` / `PutFile` / `Heartbeat`): argv bounded, no NUL bytes, `env_refs` must be `secret:name` (literal values rejected), writes confined to `/workspace`.

---

## 🔌 MCP front door

Four tools, each mapping 1:1 onto a policy action:

| Tool | Maps to |
|---|---|
| `run_command` | `proc.exec` (argv array, `sh -c` denied) |
| `read_file` / `write_file` | `fs.read` / `fs.write` (mount-checked) |
| `http_fetch` | `http.request` (proxy + broker, dual-auth) |

Third-party MCP servers run as **guest processes** under the same policy and audit trail — tool-poisoning (A2) becomes a contained process. Includes a learn mode that records denials and proposes a working allowlist.

Python + TypeScript clients live in `clients/` (`toolcage.py`, `toolcage.ts`).

---

## 🎯 Threats handled

| Path | Control |
|---|---|
| Sandbox escape | Tiered isolation + jailed VMM |
| Exfil via HTTP/DNS/ICMP/IPv6 | vsock-only guest, proxy-resolved DNS, no metadata route |
| Exfil via allowed tool (`git push`) | Per-dest method/path/byte budgets + approvals |
| Credential theft | Broker-only secrets, canary-tested |
| Persistence | Ephemeral sessions, golden-image-only snapshots |
| Lateral movement | No guest-reachable control socket |
| Log tampering | Hash chain + head-bound signed checkpoints |

Full model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) · Results: [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) (49 tests, 0 failures, clippy clean).

---

## 🗺️ Status & roadmap

**Enforced today:** YAML policy allowlist + metadata forbid, Tier0 real kernel isolation (namespaces + Landlock), Tier1 real gVisor isolation (runsc exec) and Tier2 Firecracker REST driver (microVM boot + vsock exec, signed golden-image snapshots + warm pool) + `env_clear`/streaming cap/timeout kill, real egress proxy (DNS control, metadata blocking, TLS, per-dest byte/request budgets) + broker inject/scrub, attenuate-only tokens with expiry + revocation graph, approval pause, hash-chain audit with verify-on-open and head-bound checkpoints, `doctor`/`panic`.

**In progress:** shared/persistent budget counters, encrypted credential store, seccomp-BPF (unavailable on this host's kernel build — best-effort, namespaces+Landlock still enforce).

---

## 📂 Layout

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
docs/            THREAT_MODEL.md, TEST_RESULTS.md
images/          build.sh (manifest + sha256, per-host-class goldens)
clients/         python/toolcage.py, ts/toolcage.ts
```

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE).
