# toolcage

Local-first sandbox runtime for untrusted agent tools and third-party MCP servers.

Each tool call runs in disposable isolation (Tier 0 namespaces+Landlock+seccomp / Tier 1 gVisor / Tier 2 Firecracker), is allowed only if operator policy + attenuable capability token agree, never sees real credentials (broker injects at egress proxy), and leaves a hash-chained signed audit record.

Status: M0 foundations / M1 Tier-0 slice in progress. See `../Agent Sandbox Analysis and Build Plan.md` and `docs/THREAT_MODEL.md`.

## Layout

```text
crates/policy/      YAML v0 parser + evaluator stub
crates/audit/       hash-chain writer (H(prev_hash, canonical(event)))
crates/verify/      standalone `audit verify` binary
crates/cli/         `toolcage` CLI (run, audit, doctor, panic)
crates/supervisor/  session lifecycle stub
schemas/            audit-event-v0.json, policy-v0.yaml
scripts/doctor.sh   prerequisite checks
```

## 60-sec demo target (Gate 1)

1. Agent reads doc with injected instruction to exfil secret.
2. Proxy denies destination; secret was never in guest.
3. Audit shows denied attempt + rule id.
4. `audit verify` passes; 1-byte edit fails.
