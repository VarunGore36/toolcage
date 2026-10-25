//! Tier 0 driver v1: real kernel isolation.
//!
//! `exec(id, argv)` clones a child which is *born inside* the namespace stack
//! — user (root only inside it), mount, PID, network, IPC, UTS — and which,
//! *before* exec'ing the workload, applies a private mount tree, bind-mounted
//! read-only system dirs, a writable `/workspace`, a Landlock ruleset
//! restricting file access, and a seccomp-BPF filter blocking sockets,
//! namespace manipulation, mounts, ptrace and module/kexec ops. Only then is
//! argv exec'd. The child is PID 1 of the new PID namespace, so the workload
//! and everything it spawns are contained there (and never in the host's).
//! The parent waits (bounded by the supervisor's timeout), reads capped
//! output and reports the exit code.
//!
//! This is a genuine kernel boundary for Tier0. It needs the full namespace
//! stack (user, mount, net, ipc, pid, uts) and Landlock; where the host can't
//! provide them, session creation fails closed with an error and the live
//! tests skip — never a silent fallback to a direct spawn.
//!
//! REVIEW: Landlock syscall numbers (444/445/446) and the ruleset struct
//! layout below match the kernel headers installed on this host
//! (verified: `landlock_create_ruleset` returns a fd). Landlock is part of the
//! advertised Tier0 cage and is FAIL-CLOSED: if its syscalls are unavailable
//! or the ruleset cannot be installed, session creation and the exec'd child
//! refuse to proceed — a run never degrades silently to namespaces-only.
//! seccomp stays defense-in-depth (warn and continue where the kernel refuses
//! it) and the seccomp numbers here match x86_64. seccomp for non-x86_64
//! allows everything, and Landlock is not ported there — so Tier0 refuses to
//! run on those archs at all (documented; no Tier0 claim without porting).
//!
//! Seccomp blocked (x86_64): socket/accept4/socketpair, clone*/fork/vfork,
//! unshare/setns, mount/umount2/pivot_root, ptrace, process_vm_writev,
//! swapon/swapoff/reboot/kexec*/init_module/finit_module, perf_event_open,
//! open_by_handle_at, iopl/ioperm, bpf, userfaultfd, epoll_create1.
//!
//! Landlock: /workspace gets full file rights; /usr /bin /lib /lib64 get
//! read+execute only; everything else is inaccessible.

use libc::{
    c_char, c_int, c_long, c_uint, c_ulong, c_void, getgid, getuid, prctl, sock_filter, sock_fprog,
    syscall, BPF_ABS, BPF_A, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, EPERM,
    SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SIGKILL, STDERR_FILENO, STDOUT_FILENO,
    WEXITSTATUS, WIFEXITED, WNOHANG,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, fork, pipe2, ForkResult};
use toolcage_backend::{Backend, CommandResult, SessionSpec, Tier};

const OUTPUT_CAP: usize = 1024 * 1024;
/// How long an output reader waits past the kill deadline for the last bytes.
/// Bounds the case where a grandchild inherits the pipe write end and keeps it
/// open after the workload exits: the drain gives up instead of hanging.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

// x86_64 syscall numbers for the seccomp filter, taken from this host's
// installed headers (glibc agrees: socket=41, mount=165, unshare=272,
// clone3=435, ptrace=101 all verified to match the running kernel).
#[cfg(target_arch = "x86_64")]
const BLOCKED_SYSCALLS: &[c_int] = &[
    41,  // socket
    53,  // socketpair
    56,  // clone
    57,  // fork
    58,  // vfork
    101, // ptrace
    155, // pivot_root
    165, // mount
    166, // umount2
    167, // swapon
    168, // swapoff
    169, // reboot
    172, // iopl
    173, // ioperm
    175, // init_module
    246, // kexec_load
    272, // unshare
    288, // accept4
    291, // epoll_create1
    298, // perf_event_open
    304, // open_by_handle_at
    311, // process_vm_writev
    313, // finit_module
    320, // kexec_file_load
    321, // bpf
    323, // userfaultfd
    435, // clone3
];

// Landlock syscalls on this host's kernel (444/445/446; verified live:
// create_ruleset returned fd 3). Not wrapped by libc.
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_ADD_RULE: c_long = 445;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: c_long = 446;

const LANDLOCK_RULE_PATH_BENEATH: c_uint = 1;
const LANDLOCK_CREATE_RULESET_VERSION: c_ulong = 1;

// Landlock access rights (linux/landlock.h).
const LANDLOCK_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_FS_REMOVE_FILE: u64 = 1 << 5;
#[allow(dead_code)]
const LANDLOCK_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_FS_MAKE_REG: u64 = 1 << 8;
#[allow(dead_code)]
const LANDLOCK_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_FS_MAKE_FIFO: u64 = 1 << 10;
#[allow(dead_code)]
const LANDLOCK_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_FS_REFER: u64 = 1 << 13;
const LANDLOCK_FS_TRUNCATE: u64 = 1 << 14;

// Mirrors struct landlock_ruleset_attr on this host's headers (ABI-6+
// layout: handled_access_fs, handled_access_net, scoped; no handled_abi).
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

// Mirrors struct landlock_path_beneath_attr (packed per the kernel header).
#[repr(C, packed)]
struct LandlockPathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Doctor probe: what the host can provide for Tier0.
#[derive(Debug, Default)]
pub struct Probe {
    /// Tier0 namespace stack (userns + mount/net/ipc/pid/uts) probed live.
    pub namespaces: bool,
    pub cgroup2: bool,
    /// Landlock ABI detected live via `landlock_create_ruleset`; -1 = unavailable.
    pub landlock_abi: i32,
    pub seccomp: bool,
}

/// Create a child inside the full Tier 0 namespace stack — user + mount +
/// net + ipc + pid + uts — in ONE clone3() call. Returns 0 in the child and
/// the child's pid in the parent (fork-like: stack is NULL, so the child
/// resumes on a copy of our stack and both continue from the call site).
///
/// Why clone3() and not fork()+unshare(): `unshare(CLONE_NEWPID)` only moves
/// *future children* into the new PID namespace — the calling process stays
/// in the old one. That shape therefore exec'd the workload in the HOST PID
/// namespace, where kill(2) is permitted against any process sharing its uid:
/// other sessions' processes and the supervisor itself. Creating the child
/// with CLONE_NEWPID makes it PID 1 of the new namespace — the workload runs
/// inside it, and when it dies the kernel tears down everything it spawned.
///
/// clone3 needs Linux 5.3+ (Tier 0 already requires Landlock, i.e. 5.13+, so
/// this is never the limiting factor). Where it is unavailable the PID
/// namespace boundary cannot be established: fail closed, never run without
/// it — the same stance Landlock takes below.
fn clone_all_namespaces() -> anyhow::Result<i32> {
    /// struct clone_args (Linux 5.5+). Kernels that know fewer trailing
    /// fields accept the larger size as long as they are zero, which they are.
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    // NB: clone3 takes the exit signal ONLY in exit_signal — unlike the legacy
    // clone(2) syscall, whose flags carry it in the low byte. CSIGNAL bits in
    // flags make the kernel reject the call with EINVAL.
    let flags = (libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUTS) as u64;
    let args = CloneArgs {
        flags,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    // stack: 0 -> fork(2) semantics for the child's stack and return value.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        anyhow::bail!("clone3(userns+mount/net/ipc/pid/uts) failed: {e}");
    }
    Ok(rc as i32)
}

/// Real isolation-namespace probe: run the exact namespace stack Tier0 uses
/// (userns + mount/net/ipc/pid/uts) in a throwaway child and report the
/// outcome. Probing `CLONE_NEWUSER` alone is not enough: some hosts (GitHub's
/// Ubuntu runners) allow user namespaces but block the remaining ones, in
/// which case every exec dies during setup (exit 126). Reading
/// /proc/sys/kernel/unprivileged_userns_clone is not enough either — that
/// sysctl is Debian-specific and absent elsewhere. The child does only
/// async-signal-safe work (_exit), so this is safe from a multithreaded
/// caller. Probes the same clone_all_namespaces() the exec path uses, so the
/// report matches what a run would actually hit.
fn ns_stack_works() -> bool {
    let Ok(pid) = clone_all_namespaces() else {
        return false;
    };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut status: c_int = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
        }
        return false;
    }
}

/// Probe whether seccomp-BPF can actually be installed on this host.
/// Runs in a forked child so installing (even a permissive) filter cannot
/// affect the caller: seccomp is sticky per-thread, and the child exits
/// immediately after. Returns true if PR_SET_SECCOMP accepts a filter.
#[cfg(target_arch = "x86_64")]
fn seccomp_works() -> bool {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let mut status: c_int = 0;
            loop {
                match unsafe { libc::waitpid(child.as_raw(), &mut status, 0) } {
                    r if r == child.as_raw() => {
                        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
                    }
                    r if r < 0 => {
                        let e = std::io::Error::last_os_error();
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        return false;
                    }
                    _ => return false,
                }
            }
        }
        Ok(ForkResult::Child) => {
            // Trivial allow-all filter: load seccomp_data.nr, return ALLOW.
            let filter = [sock_filter {
                code: (BPF_RET | BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            }];
            let prog = sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut sock_filter,
            };
            let rc = unsafe {
                prctl(
                    22, // PR_SET_SECCOMP
                    SECCOMP_MODE_FILTER as c_ulong,
                    &prog as *const sock_fprog as c_ulong,
                    0,
                    0,
                )
            };
            unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
        }
        Err(_) => false,
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn seccomp_works() -> bool {
    false
}

fn landlock_abi() -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        let size = std::mem::size_of::<LandlockRulesetAttr>() as c_long;
        // 1) version probe
        let mut attr = LandlockRulesetAttr {
            handled_access_fs: 0,
            handled_access_net: 0,
            scoped: 0,
        };
        let r = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr,
                size,
                LANDLOCK_CREATE_RULESET_VERSION as c_ulong,
            )
        };
        if r >= 0 {
            return r as i32;
        }
        // 2) fall back: a real ruleset proves the syscall exists on this host
        attr.handled_access_fs = LANDLOCK_FS_READ_FILE;
        let fd = unsafe { syscall(SYS_LANDLOCK_CREATE_RULESET, &attr, size, 0) };
        if fd >= 0 {
            let _ = unsafe { libc::close(fd as c_int) };
            return 1;
        }
        -1
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        -1
    }
}

pub struct NsBackend {
    pub sessions: HashMap<String, SessionSpec>,
}

impl Default for NsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NsBackend {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Prerequisite probe for `doctor` (no root needed for the report).
    pub fn probe() -> Probe {
        Probe {
            namespaces: ns_stack_works(),
            cgroup2: std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            landlock_abi: landlock_abi(),
            seccomp: seccomp_works(),
        }
    }
}

impl Backend for NsBackend {
    fn tier(&self) -> Tier {
        Tier::Tier0
    }
    fn capabilities(&self) -> toolcage_backend::TierCaps {
        toolcage_backend::TierCaps {
            separate_kernel: false, // shared host kernel — documented limit
            syscall_filter: true,
            fs_mount_enforced: true,
            net_vsock_only: false, // veth+firewall-style, not vsock
            snapshot_pool: false,
        }
    }
    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(
            spec.tier == Tier::Tier0,
            "tier0 backend cannot honor {:?}",
            spec.tier
        );
        // Fail closed at session creation: Tier0 needs unprivileged user
        // namespaces and Landlock, and the exec'd child refuses to run without
        // them — reject up front with a clear error instead of surfacing a
        // child death code later.
        anyhow::ensure!(
            ns_stack_works(),
            "tier0 namespace stack unavailable on this host (needs userns+mount/net/ipc/pid/uts); tier0 cannot isolate"
        );
        anyhow::ensure!(
            landlock_abi() >= 0,
            "landlock unavailable on this host; tier0 refuses to run without the fs boundary"
        );
        self.sessions.insert(spec.id.clone(), spec.clone());
        Ok(())
    }
    fn destroy(&mut self, id: &str) -> anyhow::Result<()> {
        self.sessions.remove(id);
        Ok(())
    }
    fn exec(
        &mut self,
        id: &str,
        argv: &[String],
        timeout_secs: u64,
        cap: usize,
    ) -> anyhow::Result<CommandResult> {
        let spec = self
            .sessions
            .get(id)
            .cloned()
            .with_context(|| format!("session {id} not created"))?;
        isolated_exec(&spec, argv, timeout_secs, cap)
    }
}

fn isolated_exec(
    spec: &SessionSpec,
    argv: &[String],
    timeout_secs: u64,
    cap: usize,
) -> anyhow::Result<CommandResult> {
    if argv.is_empty() {
        anyhow::bail!("empty argv");
    }

    // ------------------------------------------------------------------
    // Everything below allocates — do it BEFORE fork so the child path
    // between fork() and execve() performs zero allocation (fork() in a
    // multi-threaded process is unsafe if the child calls malloc while
    // another thread in the parent held malloc's lock).
    // ------------------------------------------------------------------

    // Build CStrings for argv (child inherits them after fork via COW).
    let c_args: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut c_args_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    c_args_ptrs.push(std::ptr::null()); // execve expects NULL-terminated argv

    // Minimal environment: only PATH, no secrets (I2).
    let c_env: Vec<CString> = vec![CString::new("PATH=/usr/bin:/bin")?];
    let mut c_env_ptrs: Vec<*const c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
    c_env_ptrs.push(std::ptr::null()); // execve expects NULL-terminated envp

    // Resolve program path: if argv[0] has no slash, search PATH before fork.
    let prog_path = if c_args[0].as_bytes().contains(&b'/') {
        c_args[0].clone()
    } else {
        let path_var = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
        let mut found = None;
        for dir in path_var.split(':') {
            let candidate = format!("{dir}/{}", c_args[0].to_string_lossy());
            if std::path::Path::new(&candidate).is_file() {
                found = Some(CString::new(candidate)?);
                break;
            }
        }
        found.unwrap_or_else(|| c_args[0].clone())
    };

    let workspace_cstr = CString::new(spec.workspace.as_str())?;

    // Pre-build the seccomp-BPF instructions (allocates a Vec — pre-fork on
    // purpose, see the zero-allocation rule above). The Vec must outlive
    // apply_seccomp: the sock_fprog handed to prctl points into it. v0 bug:
    // the builder returned a sock_fprog whose Vec was already dropped — a
    // use-after-free fed to PR_SET_SECCOMP.
    let seccomp_insns = build_seccomp_insns();

    // Pipes for output and handshake.
    let (out_r, out_w) = pipe2(OFlag::O_CLOEXEC)?;
    let (err_r, err_w) = pipe2(OFlag::O_CLOEXEC)?;
    let (ready_r, ready_w) = pipe2(OFlag::O_CLOEXEC)?;
    let (go_r, go_w) = pipe2(OFlag::O_CLOEXEC)?;

    // ONE clone3() call creates the child in the whole Tier 0 namespace stack
    // (user + mount + net + ipc + pid + uts) — see clone_all_namespaces() for
    // why this has to be a clone() and not fork()+unshare(). CLONE_NEWPID
    // makes the child PID 1 of the new PID namespace, so the workload really
    // runs inside it; the previous shape ran it in the host PID namespace.
    let child_raw = clone_all_namespaces()?;
    match child_raw {
        // --- PARENT: nonzero = the child's pid ---
        pid if pid != 0 => {
            // Parent: original process, allocation is fine here.

            // FAIL-CLOSED post-fork contract. The child has already unshared
            // and is blocked on the go signal: if anything below fails before
            // that signal is sent, returning the error as-is would drop go_w,
            // the child would see EOF and run the workload with no supervisor,
            // no timeout, no output capture and no outcome event (a
            // permanently open intent in the audit log). Every failure here
            // therefore SIGKILLs and reaps the child first.
            let setup = (|| -> anyhow::Result<()> {
                close(out_w)?;
                close(err_w)?;
                close(ready_w)?;
                close(go_r)?;

                // Wait until the child has created its user namespace.
                let mut b = [0u8; 1];
                let n =
                    unsafe { libc::read(ready_r.as_raw_fd(), b.as_mut_ptr() as *mut c_void, 1) };
                anyhow::ensure!(n == 1, "child did not signal readiness");

                // Rootless uid/gid map: the parent writes the child's maps.
                // Order matters: setgroups=deny must be written BEFORE gid_map,
                // otherwise gid_map is rejected with EPERM.
                let uid = unsafe { getuid() };
                let gid = unsafe { getgid() };
                let pid_raw = child_raw;
                std::fs::write(format!("/proc/{pid_raw}/setgroups"), "deny")
                    .context("write child setgroups")?;
                std::fs::write(format!("/proc/{pid_raw}/uid_map"), format!("0 {uid} 1\n"))
                    .context("write child uid_map (needs unprivileged userns)")?;
                // gid_map is best-effort: some kernels require CAP_SETGID for the
                // parent to write it. If it fails, the child still runs.
                let _ = std::fs::write(format!("/proc/{pid_raw}/gid_map"), format!("0 {gid} 1\n"));

                // Test-only fault injection point (compiled out of release
                // builds). The post-fork error paths are otherwise unreachable
                // from a test: none of the setup above is driven by user input.
                // Scoped to a reserved session id so it cannot fire for the
                // tests running concurrently in this binary.
                #[cfg(test)]
                {
                    if spec.id == "t-inject-parent-fail" {
                        anyhow::bail!("injected parent setup failure");
                    }
                }
                Ok(())
            })();
            if let Err(e) = setup {
                kill_and_reap(child_raw);
                return Err(e);
            }

            // Child may now become root (inside its own user namespace only).
            let n = unsafe {
                libc::write(go_w.as_raw_fd(), &[1u8] as *const u8 as *const c_void, 1)
            };
            if n != 1 {
                // Without the go signal the workload must not start at all.
                kill_and_reap(child_raw);
                anyhow::bail!("failed to release child (go signal)");
            }

            let deadline = Instant::now() + Duration::from_secs(timeout_secs);
            let mut timed_out = false;

            // Drain BOTH output pipes on their own threads while waiting for
            // the child. The pipes hold ~64 KiB: a workload writing more than
            // that blocks in write(2) forever while the parent waits for it to
            // exit — a deadlock that only ended at `deadline`, where the child
            // was SIGKILLed and the run recorded as a timeout (with
            // truncated=false, the output having fit under OUTPUT_CAP). The
            // drain stops at EOF or `drain_until`, so a grandchild holding the
            // write end open cannot hang the parent either.
            let drain_until = deadline + DRAIN_GRACE;
            let out_thread = std::thread::spawn(move || read_capped_until(out_r, drain_until, cap));
            let err_thread = std::thread::spawn(move || read_capped_until(err_r, drain_until, cap));

            let mut status: c_int = 0;
            let exit_code = loop {
                match unsafe { libc::waitpid(child_raw, &mut status, WNOHANG) } {
                    0 => {
                        if Instant::now() > deadline {
                            timed_out = true;
                            let _ = unsafe { libc::kill(child_raw, SIGKILL) };
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    n if n > 0 => {
                        break if WIFEXITED(status) {
                            Some(WEXITSTATUS(status) as i32)
                        } else {
                            None
                        };
                    }
                    _ => break None,
                }
            };

            let _ = close(ready_r);
            let _ = close(go_w);

            // Readers are gone by now: EOF once the child is reaped (its write
            // ends are closed), or at `drain_until` at the latest. A failed
            // join is a panicked reader thread — report empty output rather
            // than hanging or unwinding here.
            let (stdout, out_trunc) = out_thread.join().unwrap_or_default();
            let (stderr, err_trunc) = err_thread.join().unwrap_or_default();

            Ok(CommandResult {
                exit_code: if timed_out { None } else { exit_code },
                stdout,
                stderr,
                truncated: out_trunc || err_trunc,
            })
        }
        // --- CHILD: 0 = us, and we are PID 1 of the new PID namespace ---
        _ => {
            // Zero allocation between clone and execve: the address space is
            // a COW copy of the parent's (exactly like fork()), so another
            // thread may have held the allocator lock when we were copied.
            close(out_r).ok();
            close(err_r).ok();
            close(ready_r).ok();
            close(go_w).ok();

            // 1. The namespace stack is already in place: clone_all_namespaces()
            // created us inside user + mount + net + ipc + pid + uts in a
            // single call. CLONE_NEWPID is what makes this process init of the
            // new PID namespace — everything the workload spawns stays in it,
            // and killing us (timeout) takes the whole namespace down with it.
            let _ = unsafe {
                libc::write(ready_w.as_raw_fd(), &[1u8] as *const u8 as *const c_void, 1)
            };
            let mut b = [0u8; 1];
            let n = unsafe { libc::read(go_r.as_raw_fd(), b.as_mut_ptr() as *mut c_void, 1) };
            if n != 1 {
                // The parent never released us (setup failed or the parent
                // died). Refuse to run the workload unsupervised — no
                // supervisor, no timeout, no output capture would apply.
                child_die(126, b"toolcage: go signal missing; refusing to run");
            }
            // Root inside this namespace only (uid/gid maps written by the
            // parent during the handshake above).
            //
            // Raw syscalls, NOT glibc's setresgid/setresuid: those run the
            // setxid broadcast in a multithreaded program (a libc lock plus a
            // futex wait). clone() — unlike fork() — runs no pthread_atfork
            // handler, so a lock like that still held by another thread of the
            // parent at clone time is never released in *this* process: the
            // child parks in futex_wait forever and the exec is eventually
            // killed as a timeout. Everything between clone and execve must be
            // a raw syscall for the same reason.
            let _ = unsafe { libc::syscall(libc::SYS_setresgid, 0, 0, 0) };
            let _ = unsafe { libc::syscall(libc::SYS_setresuid, 0, 0, 0) };
            // no_new_privs BEFORE the sandbox layers: landlock restrict_self
            // and seccomp both require it (or CAP_SYS_ADMIN in the userns), and
            // some hosts deny the capability path (restrict_self failed EPERM
            // on GitHub's runners while the capability-free NNP path works).
            // Fail closed: without it nothing below can be enforced.
            if unsafe { prctl(38, 1, 0, 0, 0) } != 0 {
                // PR_SET_NO_NEW_PRIVS = 38
                child_die(123, b"toolcage: no_new_privs failed; refusing to run");
            }
            // 3. Private mount tree: nothing propagates to the host.
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr() as *const libc::c_char,
                    std::ptr::null(),
                    libc::MS_PRIVATE | libc::MS_REC,
                    std::ptr::null(),
                );
            }

            // Read-only system dirs (guest may read/execute, never write).
            // CStr literals on purpose: these pointers go to mount(2) as C
            // strings, and a `&str` would rely on rustc's unspecified trailing
            // NUL in rodata.
            for sysdir in [c"/usr", c"/bin", c"/lib", c"/lib64"] {
                if unsafe { libc::access(sysdir.as_ptr(), libc::F_OK) } == 0 {
                    let _ = unsafe {
                        libc::mount(
                            sysdir.as_ptr() as *const libc::c_char,
                            sysdir.as_ptr() as *const libc::c_char,
                            c"".as_ptr() as *const libc::c_char,
                            libc::MS_BIND | libc::MS_REC,
                            std::ptr::null(),
                        )
                    };
                    let _ = unsafe {
                        libc::mount(
                            std::ptr::null(),
                            sysdir.as_ptr() as *const libc::c_char,
                            c"".as_ptr() as *const libc::c_char,
                            libc::MS_RDONLY | libc::MS_BIND | libc::MS_REMOUNT,
                            std::ptr::null(),
                        )
                    };
                }
            }
            // chdir into the workspace.
            if unsafe { libc::chdir(workspace_cstr.as_ptr()) } != 0 {
                child_die(125, b"toolcage: chdir workspace failed");
            }
            // 4. Landlock filesystem rules (best-effort).
            apply_landlock(&spec.workspace);
            // 5. seccomp-BPF: block sockets, namespace/mount/ptrace/module ops.
            apply_seccomp(&seccomp_insns);
            // env_clear: replace environ with minimal PATH (no secrets leak).
            // Raw pointer manipulation — no allocation.
            unsafe {
                extern "C" {
                    static mut environ: *mut *mut c_char;
                }
                if !environ.is_null() {
                    let mut i = 0usize;
                    while !(*environ.add(i)).is_null() {
                        let entry = *environ.add(i);
                        let mut eq = 0usize;
                        while entry.add(eq).read() != b'=' as c_char && entry.add(eq).read() != 0 {
                            eq += 1;
                        }
                        let is_path = eq == 4
                            && entry.add(0).read() == b'P' as c_char
                            && entry.add(1).read() == b'A' as c_char
                            && entry.add(2).read() == b'T' as c_char
                            && entry.add(3).read() == b'H' as c_char;
                        if is_path {
                            let new_val = b"PATH=/usr/bin:/bin\0";
                            for (j, &byte) in new_val.iter().enumerate() {
                                entry.add(j).write(byte as c_char);
                            }
                            entry.add(new_val.len()).write(0);
                        } else {
                            entry.write(0);
                        }
                        i += 1;
                    }
                }
            }
            // Duplicate output pipes onto stdout/stderr, close the rest.
            let _ = unsafe { libc::dup2(out_w.as_raw_fd(), STDOUT_FILENO) };
            let _ = unsafe { libc::dup2(err_w.as_raw_fd(), STDERR_FILENO) };
            close(out_w).ok();
            close(err_w).ok();
            close(ready_w).ok();
            close(go_r).ok();

            // execve with resolved path and minimal environment.
            // Never returns on success; returns -1 on error.
            let rc = unsafe {
                libc::execve(
                    prog_path.as_ptr(),
                    c_args_ptrs.as_ptr(),
                    c_env_ptrs.as_ptr(),
                )
            };
            if rc == -1 {
                child_die(127, b"toolcage: exec failed");
            }
            // execve returns only on failure; the _exit is belt and braces so
            // this arm stays diverging.
            unsafe { libc::_exit(127) };
        }
    }
}

// ---------------------------------------------------------------------------
// Forked-child failure handling (between fork() and execve()): NEVER allocate
// — the child of a multithreaded parent can deadlock in malloc (another thread
// may have held the allocator lock at fork). And NEVER `?`/return: a child that
// returns resumes the CALLER's control flow as a duplicate process. Static
// byte messages + _exit only.
// ---------------------------------------------------------------------------

/// Report a fatal child-side failure, then terminate THIS process. Appends
/// " errno=N" (best-effort context, zero-alloc itoa) so a CI log or operator
/// can tell EPERM from EINVAL/ENOSPC without reproducing locally.
/// Exit codes: 123 no_new_privs, 124 Landlock boundary, 125 chdir,
/// 126 namespace setup, 127 exec.
fn child_die(code: i32, msg: &[u8]) -> ! {
    let e = unsafe { *libc::__errno_location() };
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        let mut buf = [0u8; 24];
        let mut n = 0usize;
        for &c in b" errno=" {
            buf[n] = c;
            n += 1;
        }
        // Zero-alloc itoa (this runs between fork and execve).
        let mut digits = [0u8; 10];
        let mut d = 0usize;
        let mut v: u32 = if e < 0 { (-e) as u32 } else { e as u32 };
        if v == 0 {
            digits[d] = b'0';
            d += 1;
        }
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        while d > 0 {
            d -= 1;
            buf[n] = digits[d];
            n += 1;
        }
        buf[n] = b'\n';
        n += 1;
        libc::write(2, buf.as_ptr() as *const c_void, n);
        libc::_exit(code as c_int);
    }
}

/// Non-fatal child-side warning for best-effort layers (Landlock, seccomp).
fn child_warn(msg: &[u8]) {
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
    }
}

/// Kill and reap a forked child that must not be allowed to run. Parent-side
/// only (allocation is fine here): used on every post-fork error path before
/// the go signal is sent, so a failed setup never leaves a live or zombie
/// workload behind. Both syscalls are best-effort — the point is that we do
/// not return while the child is still running or unreaped.
fn kill_and_reap(pid: i32) {
    unsafe {
        libc::kill(pid, SIGKILL);
        let mut status: c_int = 0;
        let _ = libc::waitpid(pid, &mut status, 0);
    }
}

/// Read one output pipe to EOF, capped at OUTPUT_CAP. Runs on its own thread
/// in the parent so a chatty workload cannot fill the pipe and deadlock
/// against the waitpid loop. Past the cap the excess is discarded but draining
/// continues, so a large-output workload still reaches its real exit code and
/// the truncation flag stays honest. Reads are poll-based and never block past
/// `stop_at`, so a grandchild holding the write end open cannot hang us.
fn read_capped_until(fd: OwnedFd, stop_at: Instant, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut truncated = false;
    loop {
        if Instant::now() >= stop_at {
            // Draining gave up: whatever is still unread is lost.
            truncated = true;
            break;
        }
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            continue; // poll timeout: re-check stop_at
        }
        // Readable, hung up or errored — one read() resolves all three
        // (0 means EOF).
        let n = unsafe {
            libc::read(fd.as_raw_fd(), tmp.as_mut_ptr() as *mut c_void, tmp.len())
        };
        match n {
            0 => break,
            n if n > 0 => {
                let n = n as usize;
                if truncated {
                    continue; // over cap: discard, keep draining to EOF
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > cap {
                    buf.truncate(cap);
                    truncated = true;
                }
            }
            _ => break,
        }
    }
    (buf, truncated)
}

/// Build the seccomp-BPF filter instructions (allocates — call before fork).
/// Returns the Vec so the caller owns and keeps it alive: `apply_seccomp`'s
/// sock_fprog points into this buffer. v0 bug: this returned a bare sock_fprog
/// whose backing Vec was dropped here — a use-after-free.
fn build_seccomp_insns() -> Vec<sock_filter> {
    let mut insns: Vec<sock_filter> = Vec::new();
    // Load seccomp_data.nr into the accumulator. NOTE the addressing mode:
    // this is BPF_ABS (load from an offset in the seccomp_data struct), NOT
    // BPF_A (0x10, the MISC-A field — identical to BPF_B). BPF_LD|BPF_W|BPF_A
    // assembles to opcode 0x10, i.e. BPF_LD|BPF_B|BPF_IMM ("load byte
    // immediate"), which the kernel's classic-BPF validator rejects with
    // EINVAL — so PR_SET_SECCOMP failed and apply_seccomp warned "seccomp
    // unavailable, continuing without it" on every host. The syscall filter
    // was never installed.
    insns.push(sock_filter {
        code: (BPF_LD | BPF_W | BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: 0, // A = seccomp_data.nr (offset 0)
    });
    for &nr in BLOCKED_SYSCALLS {
        // Match the syscall number in A. Jump offsets are counted from the
        // instruction AFTER this one: `jt` is taken when A == nr, `jf` when
        // A != nr. Denylist semantics: equal -> fall through into the next
        // instruction (RET ERRNO), not-equal -> skip it and keep comparing.
        // The inverse encoding (jt=1, jf=0) allowed exactly the blocked
        // syscalls and denied everything else, `execve` included.
        insns.push(sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        insns.push(sock_filter {
            code: (BPF_RET | BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | ((EPERM as u32) & SECCOMP_RET_DATA),
        });
    }
    insns.push(sock_filter {
        code: (BPF_RET | BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    insns
}

/// Install the seccomp-BPF program. No allocation (runs in the forked child):
/// the sock_fprog lives on this stack and points into `insns`, which the
/// caller keeps alive across the call.
///
/// Tier 0 treats seccomp as defense-in-depth (README "Status and known
/// limits"): where the kernel refuses the filter (EINVAL on some kernels) or
/// no_new_privs is unavailable, we warn zero-alloc and continue — namespaces +
/// Landlock still enforce the boundary.
fn apply_seccomp(insns: &[sock_filter]) {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = insns;
        // Not ported: seccomp allows everything on this arch (documented
        // weakening; no Tier0 claim on those archs without porting).
        child_warn(b"toolcage: seccomp skipped (non-x86_64)\n");
    }
    #[cfg(target_arch = "x86_64")]
    {
        let prog = sock_fprog {
            len: insns.len() as u16,
            filter: insns.as_ptr() as *mut sock_filter,
        };
        // no_new_privs is already set (see isolated_exec) — it is what makes
        // unprivileged seccomp installation work.
        let rc = unsafe {
            prctl(
                22, // PR_SET_SECCOMP
                SECCOMP_MODE_FILTER as c_ulong,
                &prog as *const sock_fprog as c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            // Seccomp unavailable on this host (EINVAL on some kernels).
            // Namespaces + Landlock still enforce the boundary.
            child_warn(b"toolcage: seccomp unavailable, continuing without it\n");
        }
    }
}

/// Establish the Landlock filesystem boundary. FAIL-CLOSED (operator
/// decision): Landlock is part of the advertised Tier 0 cage, so any failure
/// terminates the forked child (child_die, exit 124) instead of letting the
/// workload run namespaces-only. No allocation — runs between fork and execve.
fn apply_landlock(workspace: &str) {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = workspace;
        // Not ported here, so the fs boundary cannot be established — refuse
        // to run rather than silently weaken Tier0 (see module header).
        child_die(
            124,
            b"toolcage: landlock not ported on this arch; refusing to run without the fs boundary",
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Ruleset must declare every right any of its rules will use.
        let ws_rights = LANDLOCK_FS_READ_FILE
            | LANDLOCK_FS_WRITE_FILE
            | LANDLOCK_FS_READ_DIR
            | LANDLOCK_FS_MAKE_DIR
            | LANDLOCK_FS_MAKE_REG
            | LANDLOCK_FS_MAKE_FIFO
            | LANDLOCK_FS_MAKE_SYM
            | LANDLOCK_FS_REMOVE_DIR
            | LANDLOCK_FS_REMOVE_FILE
            | LANDLOCK_FS_TRUNCATE
            | LANDLOCK_FS_EXECUTE
            | LANDLOCK_FS_REFER;
        let sys_rights = LANDLOCK_FS_READ_FILE | LANDLOCK_FS_READ_DIR | LANDLOCK_FS_EXECUTE;
        let all_rights = ws_rights | sys_rights;

        // Probe/create ruleset with the ABI this host's headers use.
        let attr = LandlockRulesetAttr {
            handled_access_fs: all_rights,
            handled_access_net: 0,
            scoped: 0,
        };
        let ruleset = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>() as c_long,
                0,
            )
        };
        if ruleset < 0 {
            child_die(
                124,
                b"toolcage: landlock create_ruleset unavailable; refusing to run without the fs boundary",
            );
        }
        let add_rule = |fd: c_long, path: &str, rights: u64| -> bool {
            let dir = match open(
                Path::new(path),
                OFlag::O_PATH | OFlag::O_DIRECTORY,
                Mode::empty(),
            ) {
                Ok(d) => d,
                Err(_) => return false,
            };
            let rule = LandlockPathBeneath {
                allowed_access: rights,
                parent_fd: dir.as_raw_fd(),
            };
            let ok = unsafe {
                syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    fd,
                    LANDLOCK_RULE_PATH_BENEATH as c_long,
                    &rule as *const LandlockPathBeneath as *const _,
                    0,
                )
            };
            let _ = close(dir);
            ok >= 0
        };
        let ok = add_rule(ruleset, workspace, ws_rights)
            && ["/usr", "/bin", "/lib", "/lib64"]
                .iter()
                .all(|p| add_rule(ruleset, p, sys_rights));
        if ok {
            let rc = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0) };
            if rc < 0 {
                child_die(
                    124,
                    b"toolcage: landlock restrict_self failed; refusing to run",
                );
            }
        } else {
            child_die(124, b"toolcage: landlock add_rule failed; refusing to run");
        }
        let _ = unsafe { libc::close(ruleset as c_int) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tier0_refuses_tier2_need() {
        let b = NsBackend::new();
        assert!(b.honors("tier0"));
        assert!(!b.honors("firecracker"));
    }

    fn isolated() -> bool {
        // Tier0 refuses to run without Landlock (fail-closed, enforced in
        // create()), so live tests need both userns and Landlock.
        let p = NsBackend::probe();
        p.namespaces && p.landlock_abi >= 0
    }

    #[test]
    fn tier0_exec_runs_command() {
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t1".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = b.exec("t1", &["/bin/true".into()], 30, OUTPUT_CAP).unwrap();
        assert_eq!(r.exit_code, Some(0));
        let r = b
            .exec("t1", &["/bin/echo".into(), "hello-cage".into()], 30, OUTPUT_CAP)
            .unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&r.stdout), "hello-cage\n");
        b.destroy("t1").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier0_network_isolated() {
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        // Helper: try connect() to an external IP. Inside the new network
        // namespace there is no route anywhere, so connect must fail (I1).
        let src = r#"
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <unistd.h>
        int main(void) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) return 0; // socket itself failed -> isolated
            struct sockaddr_in a = { .sin_family = AF_INET,
                                     .sin_port = __builtin_bswap16(53),
                                     .sin_addr = { .s_addr = __builtin_bswap32(0x08080808) } }; // 8.8.8.8
            int r = connect(s, (struct sockaddr*)&a, sizeof(a));
            close(s);
            return r < 0 ? 0 : 1; // 0 = connect failed (good), 1 = leak (bad)
        }
        "#;
        let mut child = match std::process::Command::new("gcc")
            .arg("-x")
            .arg("c")
            .arg("-")
            .arg("-o")
            .arg("/tmp/opencode/tc-net-helper")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("skip: gcc unavailable");
                return;
            }
        };
        let _ = child.stdin.take().unwrap().write_all(src.as_bytes());
        if !child.wait().map(|s| s.success()).unwrap_or(false) {
            eprintln!("skip: gcc compile failed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-net-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::copy("/tmp/opencode/tc-net-helper", dir.join("net-helper"));
        let spec = SessionSpec {
            id: "t2".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        // cwd is the workspace, so relative path works.
        let r = b.exec("t2", &["./net-helper".into()], 30, OUTPUT_CAP).unwrap();
        assert_eq!(
            r.exit_code,
            Some(0),
            "external connect must be blocked inside Tier0"
        );
        b.destroy("t2").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier0_environment_cleared() {
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t3".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        // Direct exec of `env`, no shell: the seccomp filter blocks fork/clone,
        // so a shell script cannot spawn `env` on hosts where seccomp actually
        // installs (this host returns EINVAL for seccomp; runners do not).
        // `env` prints exactly the scrubbed environment.
        let r = b.exec("t3", &["/usr/bin/env".into()], 30, OUTPUT_CAP).unwrap();
        assert_eq!(r.exit_code, Some(0));
        let out = String::from_utf8_lossy(&r.stdout);
        // env is cleared before exec (only PATH); nothing else may leak.
        assert!(
            out.lines().any(|l| l.starts_with("PATH=")),
            "PATH must be present:\n{out}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("HOME=")),
            "HOME must not leak:\n{out}"
        );
        assert!(
            !out.lines().any(|l| l.starts_with("USER=")),
            "USER must not leak:\n{out}"
        );
        assert!(
            !out.lines().any(|l| l.contains("SECRET")),
            "secrets must not leak:\n{out}"
        );
        b.destroy("t3").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier0_landlock_blocks_outside_workspace() {
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-landlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t4".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();

        // Write inside workspace (cwd) should succeed.
        let r = b
            .exec(
                "t4",
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo ok > tc-write-test".into(),
                ],
                30,
                OUTPUT_CAP,
            )
            .unwrap();
        assert_eq!(
            r.exit_code,
            Some(0),
            "write inside workspace should succeed"
        );
        assert!(
            dir.join("tc-write-test").exists(),
            "file should appear on host"
        );

        // Write outside workspace should be blocked by Landlock.
        let r = b
            .exec(
                "t4",
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo nope > /etc/tc-test-blocked".into(),
                ],
                30,
                OUTPUT_CAP,
            )
            .unwrap();
        assert_ne!(
            r.exit_code,
            Some(0),
            "write outside workspace must be blocked by Landlock"
        );
        assert!(
            !std::path::Path::new("/etc/tc-test-blocked").exists(),
            "nothing should leak to host /etc"
        );

        b.destroy("t4").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn seccomp_insns_are_owned_by_caller() {
        // Locks the UAF fix's shape: the builder returns the instruction Vec
        // (caller keeps it alive while the sock_fprog points into it). v0
        // returned a sock_fprog whose Vec was already dropped.
        let insns = build_seccomp_insns();
        assert_eq!(insns.len(), 2 * BLOCKED_SYSCALLS.len() + 2);
        // First insn loads seccomp_data.nr into the accumulator. Must be
        // BPF_ABS (the seccomp_data offset addressing mode) — BPF_A is a
        // different constant (0x10 == BPF_B) that assembles to an invalid
        // opcode the kernel rejects with EINVAL.
        assert_eq!(insns[0].code, (BPF_LD | BPF_W | BPF_ABS) as u16);
        assert_eq!(insns[0].k, 0, "loads seccomp_data.nr at offset 0");
        // Last insn is the fall-through allow; every blocked syscall is
        // matched in between and returns EPERM.
        assert_eq!(insns[insns.len() - 1].code, (BPF_RET | BPF_K) as u16);
        assert_eq!(insns[insns.len() - 1].k, SECCOMP_RET_ALLOW);
    }

    /// Interpret the generated filter over `seccomp_data.nr == nr` and return
    /// the verdict. Each instruction is matched on its FULL opcode, not just
    /// the class nibble: masking with 0x07 would accept any LD-class code,
    /// including the invalid BPF_LD|BPF_W|BPF_A (0x10) the kernel rejects.
    /// This exists because checking instruction *shape* cannot catch a swapped
    /// jt/jf pair or a mistyped addressing mode — the v0 filter was
    /// structurally perfect and semantically inverted.
    #[cfg(target_arch = "x86_64")]
    fn run_filter(insns: &[sock_filter], nr: i32) -> u32 {
        // Exact opcodes as emitted by build_seccomp_insns.
        const OP_LD_W_ABS: u16 = (BPF_LD | BPF_W | BPF_ABS) as u16;
        const OP_JMP_JEQ_K: u16 = (BPF_JMP | BPF_JEQ | BPF_K) as u16;
        const OP_RET_K: u16 = (BPF_RET | BPF_K) as u16;
        let mut a: u32 = 0;
        let mut pc = 0usize;
        loop {
            let ins = &insns[pc];
            match ins.code {
                OP_LD_W_ABS => {
                    // LD_W_ABS k=0 -> seccomp_data.nr
                    assert_eq!(ins.k, 0, "only seccomp_data.nr is loaded");
                    a = nr as u32;
                    pc += 1;
                }
                OP_JMP_JEQ_K => {
                    pc += 1 + if a == ins.k { ins.jt } else { ins.jf } as usize;
                }
                OP_RET_K => return ins.k,
                c => panic!("unexpected opcode {c:#x} at pc {pc}"),
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn seccomp_filter_denies_blocklist_and_allows_the_rest() {
        // Denylist semantics, executed: every blocked syscall must return
        // SECCOMP_RET_ERRNO|EPERM, and ordinary syscalls must be ALLOWED.
        // Guards the jt/jf orientation in build_seccomp_insns.
        let insns = build_seccomp_insns();
        let deny_verdict = SECCOMP_RET_ERRNO | ((EPERM as u32) & SECCOMP_RET_DATA);

        for &nr in BLOCKED_SYSCALLS {
            assert_eq!(
                run_filter(&insns, nr),
                deny_verdict,
                "blocked syscall {nr} must be denied with EPERM"
            );
        }

        // A representative slice of the syscalls a workload actually needs.
        for nr in [
            0,  // read
            1,  // write
            2,  // open
            3,  // close
            9,  // mmap
            12, // brk
            21, // access
            39, // getpid
            59, // execve   <-- v0 returned EPERM here: nothing could run
            60, // exit
            231, // exit_group
            257, // openat
            262, // newfstatat
            318, // getrandom
        ] {
            assert_eq!(
                run_filter(&insns, nr),
                SECCOMP_RET_ALLOW,
                "ordinary syscall {nr} must be allowed"
            );
        }

        // And the whole rest of the space (aside from the blocklist) is open.
        let blocked: Vec<u32> = BLOCKED_SYSCALLS.iter().map(|&n| n as u32).collect();
        for nr in -2i32..512 {
            if blocked.contains(&(nr as u32)) {
                continue;
            }
            assert_eq!(
                run_filter(&insns, nr),
                SECCOMP_RET_ALLOW,
                "syscall {nr} is not on the denylist and must be allowed"
            );
        }
    }

    /// Opcodes the kernel's classic-BPF validator + seccomp_check_filter accept
    /// for a seccomp filter (everything `build_seccomp_insns` emits). Anything
    /// else is rejected with EINVAL and the filter is never installed — the
    /// bug this test guards: `BPF_LD|BPF_W|BPF_A` (0x10, the MISC-A field)
    /// assembled to BPF_LD|BPF_B|BPF_IMM, which is not in this set.
    #[cfg(target_arch = "x86_64")]
    fn kernel_seccomp_opcode_ok(code: u16) -> bool {
        matches!(
            code,
            c if c == (BPF_LD | BPF_W | BPF_ABS) as u16
                || c == (BPF_JMP | BPF_JEQ | BPF_K) as u16
                || c == (BPF_RET | BPF_K) as u16
        )
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn seccomp_filter_opcodes_are_kernel_valid() {
        // Regression for the invalid BPF addressing mode: the load must use
        // BPF_ABS (seccomp_data offset), not BPF_A. The two constants are easy
        // to confuse — BPF_A (0x10) == BPF_B (0x10) — and the old code emitted
        // an opcode the kernel rejected, so seccomp silently never installed
        // (every run logged "seccomp unavailable, continuing without it").
        let insns = build_seccomp_insns();

        // The load: exact opcode, offset 0, and explicitly not the BPF_A form.
        assert_eq!(
            insns[0].code,
            (BPF_LD | BPF_W | BPF_ABS) as u16,
            "first insn must load seccomp_data.nr via BPF_ABS"
        );
        assert_ne!(
            insns[0].code,
            (BPF_LD | BPF_W | BPF_A) as u16,
            "BPF_A (== BPF_B) is not a load addressing mode; the kernel rejects it"
        );
        assert_eq!(insns[0].k, 0, "loads seccomp_data.nr at offset 0");

        // Every instruction must be one the kernel will accept for seccomp.
        for (pc, ins) in insns.iter().enumerate() {
            assert!(
                kernel_seccomp_opcode_ok(ins.code),
                "instruction {pc} has opcode {:#x}, which the kernel's seccomp \
                 validator rejects (EINVAL) — the filter would never install",
                ins.code
            );
        }

        // And the structural shape: pairs of (JEQ, RET ERRNO) plus the two
        // ends. Verified as exact opcodes, so a mistyped addressing mode or
        // class cannot slip through.
        assert_eq!(insns[insns.len() - 1].code, (BPF_RET | BPF_K) as u16);
        assert_eq!(insns[insns.len() - 1].k, SECCOMP_RET_ALLOW);
        for chunk in insns[1..insns.len() - 1].chunks(2) {
            assert_eq!(chunk[0].code, (BPF_JMP | BPF_JEQ | BPF_K) as u16);
            assert_eq!(chunk[1].code, (BPF_RET | BPF_K) as u16);
            assert_eq!(chunk[1].k, SECCOMP_RET_ERRNO | ((EPERM as u32) & SECCOMP_RET_DATA));
        }
    }

    #[test]
    fn child_setup_failure_exits_never_resumes_caller() {
        // Contract for every failure site between fork() and execve(): the
        // child terminates itself (child_die), it must never `?`-return into
        // the caller's control flow — that leaves a duplicate of the caller
        // running, which here would append to the marker file twice.
        //
        // Forced at the chdir site with a workspace that is a regular file.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-childexit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        let wsfile = dir.join("not-a-dir");
        std::fs::write(&wsfile, "x").unwrap();
        let spec = SessionSpec {
            id: "t5".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: wsfile.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = match b.exec("t5", &["/bin/echo".into(), "hi".into()], 30, OUTPUT_CAP) {
            Ok(r) => r,
            Err(_) => {
                // Only a child resuming this caller can land here (its setup
                // `?`-returned). Kill it now, or the rest of the test body
                // runs in two processes and the parent hangs in waitpid.
                unsafe { libc::_exit(99) };
            }
        };
        // The child died in setup (125 = chdir); the workload never ran.
        assert_eq!(r.exit_code, Some(125), "child must _exit on setup failure");
        assert!(
            r.stdout.is_empty(),
            "workload must not run after failed setup"
        );
        // Written exactly once — by the parent. The parent proceeds only after
        // reaping the child, so a resuming child would append first and this
        // would read "xx".
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&marker)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "x",
            "forked child resumed the caller as a duplicate process"
        );
        b.destroy("t5").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exec_failure_exits_127_with_message() {
        // execve fails -> child_die(127) with a static message into the
        // captured stderr pipe. (Also locks that the message is written in
        // full: v0 hardcoded a length that truncated it.)
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-execfail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t6".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = b
            .exec("t6", &["/nonexistent/toolcage-test-prog".into()], 30, OUTPUT_CAP)
            .unwrap();
        assert_eq!(r.exit_code, Some(127));
        assert!(
            String::from_utf8_lossy(&r.stderr).contains("toolcage: exec failed"),
            "stderr: {:?}",
            String::from_utf8_lossy(&r.stderr)
        );
        b.destroy("t6").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every zombie direct child of this test process (from /proc/<pid>/stat).
    fn zombie_children() -> Vec<i32> {
        let me = std::process::id() as i32;
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return out;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Ok(pid) = name.parse::<i32>() else { continue };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            // "pid (comm) state ppid ..." — comm may contain spaces and ')',
            // so split after the last ')' instead of on whitespace.
            let Some((_, rest)) = stat.rsplit_once(") ") else { continue };
            let mut it = rest.split_whitespace();
            let (Some(state), Some(ppid)) = (it.next(), it.next()) else {
                continue;
            };
            let Ok(ppid) = ppid.parse::<i32>() else { continue };
            if ppid == me && state == "Z" {
                out.push(pid);
            }
        }
        out
    }

    #[test]
    fn parent_setup_failure_is_fail_closed() {
        // Contract for the parent's post-fork error paths (everything between
        // fork() and the go signal): a failed setup must not release a
        // detached workload — one with no supervisor, no timeout, no output
        // capture and no outcome event — and must not leave a zombie behind.
        //
        // Forced via the reserved session id "t-inject-parent-fail" (see
        // isolated_exec): none of that setup is driven by user input, so the
        // path is otherwise unreachable without fault injection. The id is the
        // injection switch, so the tests running concurrently in this binary
        // are unaffected.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-parentfail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("ran");
        let spec = SessionSpec {
            id: "t-inject-parent-fail".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = b.exec(
            &spec.id,
            &[
                "/bin/sh".into(),
                "-c".into(),
                format!("touch {}", marker.display()),
            ],
            30,
            OUTPUT_CAP,
        );
        assert!(
            r.is_err(),
            "injected setup failure must surface as an error, got {r:?}"
        );
        assert!(
            !marker.exists(),
            "workload must not run when the parent's setup fails"
        );
        // The child must be killed AND reaped before the error returns.
        for _ in 0..20 {
            if zombie_children().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            zombie_children().is_empty(),
            "failed setup left zombie children: {:?}",
            zombie_children()
        );
        b.destroy(&spec.id).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier0_workload_is_pid1_of_its_own_pid_namespace() {
        // CLONE_NEWPID makes the workload init of a fresh PID namespace, so
        // getpid() inside it is 1. The old shape (fork + unshare(CLONE_NEWPID))
        // left the *calling* process in the host PID namespace — unshare only
        // moves future children — so the workload ran host-side, where kill(2)
        // is allowed against every process sharing its uid: other sessions'
        // processes and the supervisor itself.
        //
        // `$$` is the shell's getpid() — /proc is still the host's procfs, so
        // /proc/self would misleadingly show the host pid.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-pidns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t-pidns".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = b
            .exec("t-pidns", &["/bin/sh".into(), "-c".into(), "echo $$".into()], 30, OUTPUT_CAP)
            .unwrap();
        assert_eq!(r.exit_code, Some(0), "sh -c 'echo $$' failed: {r:?}");
        assert_eq!(
            String::from_utf8_lossy(&r.stdout).trim(),
            "1",
            "workload must be PID 1 of its own PID namespace (got {})",
            String::from_utf8_lossy(&r.stdout).trim()
        );
        b.destroy("t-pidns").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_execs_never_inherit_a_held_lock() {
        // clone() — unlike fork() — runs no pthread_atfork handler, so any libc
        // lock another thread of this process holds at clone time stays locked
        // in the child forever (it has no other thread to release it). A child
        // path that calls a locking glibc wrapper — set*id's setxid broadcast
        // being the one that bit here — then parks in futex_wait and the exec
        // is eventually killed as a timeout. That is why the code between
        // clone and execve is raw syscalls only; this exercises it under real
        // contention: concurrent clones while other threads churn the
        // allocator. A regression shows up as execs that hang to the 30s
        // deadline (exit_code: None) instead of returning promptly.
        //
        // Like any race test this is probabilistic: with the locking wrapper it
        // failed ~5 runs in 12 here.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        // Keep libc locks hot in this process while the execs clone.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let churn: Vec<_> = (0..4)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let mut v = Vec::with_capacity(64);
                        v.extend_from_slice(&[7u8; 64]);
                        drop(v);
                    }
                })
            })
            .collect();

        let workers: Vec<_> = (0..8)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..3 {
                        let dir = std::env::temp_dir().join(format!(
                            "tc-ns-lock-{}-{t}-{i}",
                            std::process::id()
                        ));
                        std::fs::create_dir_all(&dir).unwrap();
                        let id = format!("lock-{t}-{i}");
                        let spec = SessionSpec {
                            id: id.clone(),
                            tier: Tier::Tier0,
                            mem_mb: 0,
                            workspace_mb: 0,
                            workspace: dir.display().to_string(),
                        };
                        let mut b = NsBackend::new();
                        b.create(&spec).unwrap();
                        let start = Instant::now();
                        let r = b
                            .exec(&id, &["/bin/echo".into(), "ok".into()], 30, OUTPUT_CAP)
                            .unwrap();
                        assert_eq!(
                            r.exit_code,
                            Some(0),
                            "concurrent exec must not hang or be killed: {r:?}"
                        );
                        assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "ok");
                        assert!(
                            start.elapsed() < Duration::from_secs(20),
                            "exec hung (inherited lock?): {:?}",
                            start.elapsed()
                        );
                        b.destroy(&id).unwrap();
                        let _ = std::fs::remove_dir_all(&dir);
                    }
                })
            })
            .collect();

        for h in workers {
            h.join().unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in churn {
            h.join().unwrap();
        }
    }

    #[test]
    fn large_output_does_not_deadlock_or_timeout() {
        // Regression for the wait-then-drain deadlock: the parent used to
        // reap the child before reading the pipes, so a workload writing more
        // than the 64 KiB pipe buffer blocked in write(2) forever, was
        // SIGKILLed at the 30 s deadline and recorded as a timeout — with
        // truncated=false and only the buffered ~64 KiB of output.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-bigout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t8".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        // 768 KiB: well under OUTPUT_CAP, but larger than the pipe buffer
        // (64 KiB by default; coreutils raises it via F_SETPIPE_SZ, up to
        // /proc/sys/fs/pipe-max-size, 1 MiB on this host). Anything over the
        // pipe buffer is what used to deadlock. Written into the workspace up
        // front (the sandbox's /dev is not readable) and echoed back by cat.
        let payload = vec![b'a'; 768 * 1024];
        std::fs::write(dir.join("big.bin"), &payload).unwrap();
        let src = dir.join("big.bin").display().to_string();
        let start = Instant::now();
        let r = b
            .exec("t8", &["/bin/cat".into(), src], 30, OUTPUT_CAP)
            .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            r.exit_code,
            Some(0),
            "a large-output run must reach its real exit code, not be killed: {r:?}"
        );
        assert_eq!(
            r.stdout.len(),
            768 * 1024,
            "all output must be captured (got {} bytes)",
            r.stdout.len()
        );
        assert!(!r.truncated, "256 KiB is under the OUTPUT_CAP of 1 MiB");
        assert!(
            elapsed < Duration::from_secs(10),
            "large output must not stall until the exec deadline (took {elapsed:?})"
        );
        b.destroy("t8").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn over_cap_output_truncates_but_still_reports_exit_code() {
        // Past OUTPUT_CAP the excess is discarded (truncated=true) but the
        // workload must still run to completion and report its exit code:
        // dropping the drain entirely would block the child on write(2) again.
        // 2 MiB also exceeds every pipe buffer on this host, so this is the
        // deterministic regression for the wait-then-drain deadlock.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-overcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t9".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        // 2 MiB on stdout, over the 1 MiB cap.
        let payload = vec![b'b'; 2 * 1024 * 1024];
        std::fs::write(dir.join("huge.bin"), &payload).unwrap();
        let src = dir.join("huge.bin").display().to_string();
        let r = b.exec("t9", &["/bin/cat".into(), src], 30, OUTPUT_CAP).unwrap();
        assert_eq!(
            r.exit_code,
            Some(0),
            "over-cap output must not be turned into a timeout: {r:?}"
        );
        assert!(r.truncated, "output past OUTPUT_CAP must set truncated");
        assert_eq!(r.stdout.len(), OUTPUT_CAP);
        b.destroy("t9").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exec_limits_timeout_honored() {
        // timeout_secs is now honored by the Tier0 backend (previously ignored:
        // every run was killed at the hardcoded 30s). A 10s sleep with a 2s
        // timeout must be killed promptly, not after 30s.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-timeout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spec = SessionSpec {
            id: "t-timeout".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let start = Instant::now();
        let r = b.exec("t-timeout", &["/bin/sleep".into(), "10".into()], 2, OUTPUT_CAP).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(
            r.exit_code,
            None,
            "a timeout-killed run must return exit_code None, got {:?}",
            r.exit_code
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "timeout kill must be prompt, not the old 30s deadline (took {elapsed:?})"
        );
        b.destroy("t-timeout").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exec_limits_cap_honored() {
        // cap is now honored by the Tier0 backend (previously ignored:
        // every run used the hardcoded 1 MiB). Output past cap is truncated
        // and the flag set.
        if !isolated() {
            eprintln!("skip: tier0 namespace stack unavailable (userns/mount/net/ipc/pid/uts)");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cap: usize = 100;
        let spec = SessionSpec {
            id: "t-cap".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        // Produce 2000 bytes, well over the 100-byte cap.
        let payload = vec![b'z'; 2000];
        std::fs::write(dir.join("big.bin"), &payload).unwrap();
        let src = dir.join("big.bin").display().to_string();
        let r = b.exec("t-cap", &["/bin/cat".into(), src], 30, cap).unwrap();
        assert_eq!(
            r.exit_code,
            Some(0),
            "cat must complete even when output is truncated, got {:?}",
            r.exit_code
        );
        assert!(r.truncated, "output past cap must set truncated");
        assert_eq!(
            r.stdout.len(),
            cap,
            "output must be truncated to cap, got {}",
            r.stdout.len()
        );
        b.destroy("t-cap").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
