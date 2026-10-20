# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.0   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

toolcage is an early-stage research sandbox (v0.1, pre-1.0). It has **not** undergone independent security review. Do not use it as the only boundary between an agent and anything you cannot afford to lose.

If you find a security issue, please report it privately:

- Open a GitHub issue marked as a security concern, or
- Email the maintainer directly (see GitHub profile)

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce
- The affected component (supervisor, proxy, broker, audit, backend-ns, backend-fc, backend-gv, guest-agent, mcp, cli)
- Suggested fix (if you have one)

We will acknowledge your report within 7 days and provide an estimated fix timeline.

## Security Model

toolcage runs untrusted agent code in isolation tiers (namespaces+Landlock+seccomp, gVisor, or Firecracker microVM). All agent network traffic is mediated by a host-side egress proxy; secrets never enter the guest. All decisions are recorded in a tamper-evident hash chain.

Known limitations (see `docs/TEST_RESULTS.md` and `docs/REVIEW.md`):

- Seccomp-BPF is unavailable on some kernel builds; namespaces + Landlock still enforce the Tier 0 boundary.
- Audit append uses fsync per entry (~hundreds/s); group commit is not yet implemented.
- Budget counters are persisted to disk but restart with stored values.
- No multi-tenant hosting, no Windows/macOS guests, no GPU workloads (out of scope for v1).

## Disclosure Policy

We follow a 90-day disclosure timeline from the date of a confirmed report. Public disclosure will occur after a fix is released or 90 days elapse, whichever comes first. Credit will be given to the reporter unless they request anonymity.