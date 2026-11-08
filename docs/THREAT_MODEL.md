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

- I1 no guest net except via egress proxy — escape suite: raw/DNS/ICMP/IPv6/tunnels; **seccomp-BPF blocklist** (named `libc::SYS_*` constants, pinned to the kernel header by test) denies `socket`/`socketpair`/`clone*`/`ptrace`/the mount family — `mount`, `umount2`, `pivot_root`, `chroot`, and the full new mount API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) — plus `io_uring`, `bpf`, `userfaultfd`, `perf_event_open`, `process_vm_writev`, `open_by_handle_at`, module loading, `kexec`, `swapon`/`swapoff`/`reboot`, `setns`, and the x32 ABI / foreign-arch escapes
- I2 no credential value in guest mem/files/env/args — canary scan
- I3 token only narrows on delegate — property tests (200-seed chains); **approval `needs_approval` now fails closed on unknown/empty method/host, preventing gate-dodging by omission**
- I4 decision recorded before action — kill supervisor mid-action
- I5 any log edit/delete/reorder detected by `audit verify` — mutation tests
- I6 guest cannot loosen policy — adversarial guest
- I7 no cross-session state after teardown — canary tests
