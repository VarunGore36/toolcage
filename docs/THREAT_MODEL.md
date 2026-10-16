# Threat model — toolcage v1

Source: `Agent Sandbox Analysis and Build Plan.md` §2.

Untrusted: model output, guest processes, tool/MCP output, file/web content.
Trusted (keep small): supervisor, policy engine, credential broker, egress proxy, audit writer.
Host kernel trusted with reservations — Tier 2 uses separate guest kernel.

## Adversaries

- A1 remote content owner (prompt injection via CSV/web/email/tool output)
- A2 malicious/compromised tool, MCP server, package
- A3 model itself, steered/jailbroken (treat as A1)
- A4 neighboring session
- A5 operator by mistake (over-broad policy, leaked token)

## Invariants (testable)

- I1 no guest net except via egress proxy — escape suite: raw/DNS/ICMP/IPv6/tunnels
- I2 no credential value in guest mem/files/env/args — canary scan
- I3 token only narrows on delegate — property tests
- I4 decision recorded before action — kill supervisor mid-action
- I5 any log edit/delete/reorder detected by `audit verify` — mutation tests
- I6 guest cannot loosen policy — adversarial guest
- I7 no cross-session state after teardown — canary tests
