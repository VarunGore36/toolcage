# Changelog

All notable changes to toolcage will be documented in this file.

## [Unreleased]

### Added
- `backend-fc`: Firecracker microVM Tier 2 driver with REST API boot, vsock exec, snapshot pool, snapshot head-bound checkpoints, warm pool
- `crates/proxy`: real egress proxy dialer with DNS control, metadata/link-local blocking, TLS (native-tls), per-destination byte/request budgets
- `crates/broker`: encrypted-at-rest credential store (XChaCha20-Poly1305), per-credential expiry, master key rotation
- `crates/supervisor`: Tier 0/Tier 1 backend exec routing, fail-closed budget enforcement after proxy call
- `crates/mcp`: stdio JSON-RPC front door with `run_command`, `read_file`, `write_file`, `http_fetch`, learn mode
- `crates/audit`: hash-chain audit writer with verify-on-open, Ed25519 signed checkpoints, head-bound checkpoint verification
- `crates/capability`: attenuable capability tokens with expiry, traversal-normalized paths, revocation graph
- `crates/backend-ns`: real Tier 0 namespace + Landlock + seccomp driver with unprivileged user namespace support
- `crates/guest-agent`: PID 1 guest protocol (Exec/PutFile/Heartbeat) with validation
- `crates/cli`: `run`, `check-net`, `fetch`, `token`, `mcp`, `audit`, `doctor`, `panic` commands
- `scripts/bench.sh`: benchmark harness for policy p99, audit append eps, CLI run baseline
- `docs/REVIEW.md`: Gate 2 review package
- `docs/TEST_RESULTS.md`: test results and benchmarks
- `docs/THREAT_MODEL.md`: threat model with seven invariants

### Changed
- `crates/proxy`: alias resolution now maps guest alias → upstream → operator alias for policy (fixes non-github aliases)
- `crates/supervisor`: budget check moved after proxy call so bytes are charged accurately
- `README.md`: redesigned with hero banner, 60-second demo, four guarantees, tier chart, benchmark table

### Fixed
- `crates/cli`: the egress **budget store is a damage bound** — a store that exists but cannot be parsed now fails closed (all three call sites: `fetch`, `mcp serve`, `mcp call`) instead of silently resetting accumulated damage to an unbounded ceiling.
- `crates/cli`: `mcp serve` bounds frame reads **during** buffering (capped `fill_buf` chunks) — the old `lines()` accumulated an unbounded line before the 64 KiB check ran, a memory amp on a guest-controlled stream.
- `crates/capability`, `crates/broker`: a pre-epoch clock (broken VM RTC) now fails safe — token expiry reads as passed and credential injection is denied, instead of tokens living forever and the broker panicking mid-request.
- `crates/broker`: the credential store is created `0600` **before** any bytes are written (no world-readable window), `rotate()` propagates chmod failures and fsyncs the replacement before rename (no permanently-0644 store, no empty store after a crash).
- `crates/guest-agent`: the dangerous-env reject list covers interpreter hijacks — `BASH_ENV`, `ENV`, `SHELLOPTS`, `GLIBC_TUNABLES`, `NODE_OPTIONS`, `PYTHONSTARTUP`/`PYTHONPATH`/`PYTHONHOME`, `PERL5OPT`/`PERL5LIB`, `RUBYOPT`/`RUBYLIB`, `ZDOTDIR`, `GEM_HOME`.
- `crates/audit`: `verify` no longer panics on degenerate log paths (`/`, `.`); the writer detects **same-length tail rewrites** between appends (a mtime check rides along; a changed file is re-verified under the lock before extending the chain).
- `crates/cli`, `crates/mcp`: learn mode records only **policy** denials — token rejections, missing arguments, approval pauses, and infrastructure failures no longer pollute the allowlist proposals operators review.
- `crates/cli`: `mcp serve` answers requests with an explicit `id: null` (per JSON-RPC 2.0 it is a request, not a notification) and echoes **null** — not the illegal value — in responses to invalid requests; frame reads are bounded during buffering.
- `crates/cli`: `demo` refuses to wipe `/`, system prefixes, `$HOME`, or non-scratch directories; `doctor` anchors `doctor.sh` execution to the build tree, never the cwd.
- `crates/supervisor`: backend errors append their audit outcome (`backend-error: …`) instead of leaving a permanently open write-ahead intent (I4 pairing).
- `clients/python`: tool-name validation no longer uses `assert` (survives `python -O`).

### Fixed
- `crates/policy`, `crates/approval`: approval gates fail **closed** on unknown method/host. Both `needs_approval` functions treated an absent/empty method or host as "matches nothing", letting any request dodge a method- or host-constrained gate by omission — while the code comments, the tests' own messages, and THREAT_MODEL I3 all claimed the opposite (commit 5135ab7 inverted the predicate on a branch named fix/approval-fail-closed; this restores 4cf7729's fail-closed semantics and re-aligns the assertions with their messages). Unknown now fires the gate; only known-and-non-matching values pass.
- `crates/cli`, `crates/mcp`: `mcp call` reports an approval pause as **exit 3** with a `paused:` message (matching `fetch` and the documented contract) instead of collapsing it into exit 2 with a `denied:` prefix — operator scripts can now distinguish "needs a human" from "refused".
- `crates/approval`: the documented "Timeout = deny" contract is now enforceable — `Pending` records `created_at`, and `Queue::sweep_expired(now, timeout)` moves timed-out requests to decided-Deny and returns their ids for per-timeout audit events.

### Fixed
- `crates/policy`: the exec inline-code denylist is closed on the argv-shape bypasses. `env -S`/`--split-string` (a whole command line reassembled at exec time, invisible to the shell/interpreter gates), shell startup files via the `=` form (`bash --rcfile=/workspace/evil.sh -i`), the awk family (program text is code by construction; `system()` gives it the shell), python `-m` (the cwd lands on `sys.path[0]`, so `python3 -m evil` runs `/workspace/evil.py`), and perl/ruby `-x` program extraction are all denied. Residual denylist blind spots (GNU sed `e`, interpreter script files, self-executing tools) are documented and belong behind `exec.allowlist`.
- `crates/backend-ns`: exec no longer falls back to a bare `argv[0]` when the PATH search fails. The old fallback let `execve` resolve a bare name against the child's cwd — the guest-writable workspace — after the chdir, so a guest-written file could run under an allowlisted NAME (the policy decision and audit argv hash were computed for a trusted binary). Not-found is now a pre-fork error naming the command and the sandbox PATH.
- `crates/backend-ns`: the program-path search consults the sandbox's fixed `PATH` (`GUEST_PATH`, shared constant in `crates/backend`) instead of the supervisor's environment, skips non-absolute PATH entries (check-vs-use with the child's chdir), and requires the executable bit. An empty `argv[0]` is rejected with a nameable error.
- `crates/backend-gv`: the Tier 1 OCI spec now carries `PATH=<GUEST_PATH>`; without it `runsc exec` had no PATH to search and bare-name argv failed ENOENT.
- `crates/backend-ns`: seccomp blocklist rewritten with named `libc::SYS_*` constants, pinned to the kernel's `asm/unistd_64.h` numbers by a test. The old bare-number table denied the wrong syscalls — `wait4` and `prctl` were blocked under "chroot"/"nis+" labels (workloads could not wait for children or name threads) — while `chroot` (161) and the entire new mount API (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) claimed coverage but were never listed. `chroot` and the mount API are now genuinely denied; `wait4`/`prctl` are unblocked.
- `crates/proxy`: fetch fails closed on a response head with no parseable status line; header parsing no longer hides the first header of a status-less response (a hostile upstream could hide `Content-Encoding`/`Transfer-Encoding` from the scrub gate); chunked decoding uses strict HEXDIG sizes and overflow-proof bounds.

## [v0.1.0] - Initial Release

- Initial release of toolcage: local-first agent sandbox
- Tier 0: namespaces + Landlock + seccomp + cgroup v2
- Tier 1: gVisor runsc stub driver
- Tier 2: Firecracker REST driver stub
- YAML policy allowlist, metadata forbid, shell string denial
- Hash-chain audit with Ed25519 checkpoints
- Egress proxy (stub), credential broker (in-memory)
- CLI: run, check-net, fetch, token, mcp, audit, doctor, panic
