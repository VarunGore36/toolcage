//! Tier 0 driver v1: real kernel isolation.
//!
//! `exec(id, argv)` forks a child which, *before* exec'ing the workload,
//! applies (in order): a new user namespace (root only inside it), mount +
//! PID + network + IPC + UTS namespaces, a private mount tree, bind-mounted
//! read-only system dirs, a writable `/workspace`, a Landlock ruleset
//! restricting file access, and a seccomp-BPF filter blocking sockets,
//! namespace manipulation, mounts, ptrace and module/kexec ops. Only then is
//! argv exec'd. The parent waits (bounded by the supervisor's timeout), reads
//! capped output and reports the exit code.
//!
//! This is a genuine kernel boundary for Tier0. It needs unprivileged user
//! namespaces (`/proc/sys/kernel/unprivileged_userns_clone`); without them
//! `exec` fails closed with an error instead of silently falling back to a
//! direct spawn.
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
    syscall, BPF_A, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, EPERM, SECCOMP_MODE_FILTER,
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SIGKILL, STDERR_FILENO, STDOUT_FILENO,
    WEXITSTATUS, WIFEXITED, WNOHANG,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::fcntl::{open, OFlag};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::unistd::{close, fork, pipe2, ForkResult};
use toolcage_backend::{Backend, CommandResult, SessionSpec, Tier};

const OUTPUT_CAP: usize = 1024 * 1024;
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub userns: bool,
    pub cgroup2: bool,
    /// Landlock ABI detected live via `landlock_create_ruleset`; -1 = unavailable.
    pub landlock_abi: i32,
    pub seccomp: bool,
}

/// Real userns probe: fork a child that tries `unshare(CLONE_NEWUSER)` and
/// report the outcome. Reading /proc/sys/kernel/unprivileged_userns_clone is
/// NOT enough — that sysctl is Debian-specific and absent on e.g. Ubuntu 24.04
/// runners, where AppArmor blocks unprivileged user namespaces while the
/// sysctl is missing (the old probe said "yes" and every exec died with 126).
/// The forked child does only async-signal-safe work (unshare + _exit), so
/// this is safe from a multithreaded caller.
fn userns_works() -> bool {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let mut status: c_int = 0;
            loop {
                let r = unsafe { libc::waitpid(child.as_raw(), &mut status, 0) };
                if r == child.as_raw() {
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
        Ok(ForkResult::Child) => {
            let ok = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        Err(_) => false,
    }
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
            userns: userns_works(),
            cgroup2: std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            landlock_abi: landlock_abi(),
            seccomp: true,
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
            userns_works(),
            "unprivileged user namespaces unavailable on this host; tier0 cannot isolate"
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
    fn exec(&mut self, id: &str, argv: &[String]) -> anyhow::Result<CommandResult> {
        let spec = self
            .sessions
            .get(id)
            .cloned()
            .with_context(|| format!("session {id} not created"))?;
        isolated_exec(&spec, argv)
    }
}

fn isolated_exec(spec: &SessionSpec, argv: &[String]) -> anyhow::Result<CommandResult> {
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

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: original process, allocation is fine here.
            close(out_w)?;
            close(err_w)?;
            close(ready_w)?;
            close(go_r)?;

            // Wait until the child has created its user namespace.
            let mut b = [0u8; 1];
            let n = unsafe { libc::read(ready_r.as_raw_fd(), b.as_mut_ptr() as *mut c_void, 1) };
            anyhow::ensure!(n == 1, "child did not signal readiness");

            // Rootless uid/gid map: the parent writes the child's maps.
            // Order matters: setgroups=deny must be written BEFORE gid_map,
            // otherwise gid_map is rejected with EPERM.
            let uid = unsafe { getuid() };
            let gid = unsafe { getgid() };
            let pid_raw = child.as_raw();
            std::fs::write(format!("/proc/{pid_raw}/setgroups"), "deny")
                .context("write child setgroups")?;
            std::fs::write(format!("/proc/{pid_raw}/uid_map"), format!("0 {uid} 1\n"))
                .context("write child uid_map (needs unprivileged userns)")?;
            // gid_map is best-effort: some kernels require CAP_SETGID for the
            // parent to write it. If it fails, the child still runs.
            let _ = std::fs::write(format!("/proc/{pid_raw}/gid_map"), format!("0 {gid} 1\n"));

            // Child may now become root (inside its own user namespace only).
            let _ =
                unsafe { libc::write(go_w.as_raw_fd(), &[1u8] as *const u8 as *const c_void, 1) };

            let deadline = Instant::now() + EXEC_TIMEOUT;
            let mut timed_out = false;
            let mut status: c_int = 0;
            let child_raw = child.as_raw();
            let exit_code = loop {
                match unsafe { libc::waitpid(child_raw, &mut status, WNOHANG) } {
                    0 => {
                        if Instant::now() > deadline {
                            let _ = unsafe { libc::kill(child_raw, SIGKILL) };
                            timed_out = true;
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

            let mut truncated = false;
            let mut read_capped = |fd: RawFd| -> Vec<u8> {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut c_void, tmp.len()) };
                    match n {
                        0 => break,
                        n if n > 0 => {
                            let n = n as usize;
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.len() > OUTPUT_CAP {
                                buf.truncate(OUTPUT_CAP);
                                truncated = true;
                                let mut drain = [0u8; 65536];
                                while unsafe {
                                    libc::read(fd, drain.as_mut_ptr() as *mut c_void, drain.len())
                                } > 0
                                {}
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                buf
            };
            let stdout = read_capped(out_r.as_raw_fd());
            let stderr = read_capped(err_r.as_raw_fd());
            let _ = close(out_r);
            let _ = close(err_r);
            let _ = close(ready_r);
            let _ = close(go_w);

            Ok(CommandResult {
                exit_code: if timed_out { None } else { exit_code },
                stdout,
                stderr,
                truncated,
            })
        }
        Ok(ForkResult::Child) => {
            // --- CHILD: zero allocation between fork and execve ---
            close(out_r).ok();
            close(err_r).ok();
            close(ready_r).ok();
            close(go_w).ok();

            // 1. User namespace: root only inside it. On failure THIS process
            // must die here: `?` would return into the caller's control flow
            // and leave a duplicate supervisor running around (see child_die).
            if unshare(CloneFlags::CLONE_NEWUSER).is_err() {
                child_die(
                    126,
                    b"toolcage: unshare CLONE_NEWUSER failed (unprivileged_userns_clone?)\n",
                );
            }
            let _ = unsafe {
                libc::write(ready_w.as_raw_fd(), &[1u8] as *const u8 as *const c_void, 1)
            };
            let mut b = [0u8; 1];
            let _ = unsafe { libc::read(go_r.as_raw_fd(), b.as_mut_ptr() as *mut c_void, 1) };

            // Root inside this namespace only.
            let _ = unsafe { libc::setresgid(0, 0, 0) };
            let _ = unsafe { libc::setresuid(0, 0, 0) };

            // 2. Remaining namespaces (backed by capabilities inside the userns).
            if unshare(
                CloneFlags::CLONE_NEWNS
                    | CloneFlags::CLONE_NEWNET
                    | CloneFlags::CLONE_NEWIPC
                    | CloneFlags::CLONE_NEWPID
                    | CloneFlags::CLONE_NEWUTS,
            )
            .is_err()
            {
                child_die(126, b"toolcage: unshare mount/net/ipc/pid/uts failed\n");
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
                child_die(125, b"toolcage: chdir workspace failed\n");
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
                child_die(127, b"toolcage: exec failed\n");
            }
            // execve returns only on failure; the _exit is belt and braces so
            // this arm stays diverging.
            unsafe { libc::_exit(127) };
        }
        Err(e) => anyhow::bail!("fork failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Forked-child failure handling (between fork() and execve()): NEVER allocate
// — the child of a multithreaded parent can deadlock in malloc (another thread
// may have held the allocator lock at fork). And NEVER `?`/return: a child that
// returns resumes the CALLER's control flow as a duplicate process. Static
// byte messages + _exit only.
// ---------------------------------------------------------------------------

/// Report a fatal child-side failure, then terminate THIS process.
/// Exit codes: 124 Landlock boundary, 125 chdir, 126 namespace setup, 127 exec.
fn child_die(code: i32, msg: &[u8]) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::_exit(code as c_int);
    }
}

/// Non-fatal child-side warning for best-effort layers (Landlock, seccomp).
fn child_warn(msg: &[u8]) {
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
    }
}

/// Build the seccomp-BPF filter instructions (allocates — call before fork).
/// Returns the Vec so the caller owns and keeps it alive: `apply_seccomp`'s
/// sock_fprog points into this buffer. v0 bug: this returned a bare sock_fprog
/// whose backing Vec was dropped here — a use-after-free.
fn build_seccomp_insns() -> Vec<sock_filter> {
    let mut insns: Vec<sock_filter> = Vec::new();
    insns.push(sock_filter {
        code: (BPF_LD | BPF_W | BPF_A) as u16,
        jt: 0,
        jf: 0,
        k: 0, // A = seccomp_data.nr (offset 0)
    });
    for &nr in BLOCKED_SYSCALLS {
        insns.push(sock_filter {
            code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
            jt: 1,
            jf: 0,
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
        // Make sure no_new_privs is set (required for unprivileged seccomp).
        let r1 = unsafe { prctl(38, 1, 0, 0, 0) }; // PR_SET_NO_NEW_PRIVS = 38
        if r1 != 0 {
            child_warn(b"toolcage: no_new_privs unavailable, seccomp skipped\n");
            return;
        }
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
            b"toolcage: landlock not ported on this arch; refusing to run without the fs boundary\n",
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
                b"toolcage: landlock create_ruleset unavailable; refusing to run without the fs boundary\n",
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
                    b"toolcage: landlock restrict_self failed; refusing to run\n",
                );
            }
        } else {
            child_die(
                124,
                b"toolcage: landlock add_rule failed; refusing to run\n",
            );
        }
        let _ = unsafe { libc::close(ruleset as c_int) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

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
        p.userns && p.landlock_abi >= 0
    }

    #[test]
    fn tier0_exec_runs_command() {
        if !isolated() {
            eprintln!("skip: unprivileged user namespaces unavailable");
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
        let r = b.exec("t1", &["/bin/true".into()]).unwrap();
        assert_eq!(r.exit_code, Some(0));
        let r = b
            .exec("t1", &["/bin/echo".into(), "hello-cage".into()])
            .unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&r.stdout), "hello-cage\n");
        b.destroy("t1").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier0_network_isolated() {
        if !isolated() {
            eprintln!("skip: unprivileged user namespaces unavailable");
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
        let r = b.exec("t2", &["./net-helper".into()]).unwrap();
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
            eprintln!("skip: unprivileged user namespaces unavailable");
            return;
        }
        let dir = std::env::temp_dir().join(format!("tc-ns-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("env.sh"), "#!/bin/sh\nenv\n").unwrap();
        let _ =
            std::fs::set_permissions(dir.join("env.sh"), std::fs::Permissions::from_mode(0o755));
        let spec = SessionSpec {
            id: "t3".into(),
            tier: Tier::Tier0,
            mem_mb: 0,
            workspace_mb: 0,
            workspace: dir.display().to_string(),
        };
        let mut b = NsBackend::new();
        b.create(&spec).unwrap();
        let r = b.exec("t3", &["./env.sh".into()]).unwrap();
        assert_eq!(r.exit_code, Some(0));
        let out = String::from_utf8_lossy(&r.stdout);
        // env is cleared before exec (only PATH); a shell may add PWD/SHLVL/_,
        // but no secret or identifying vars should leak.
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
            eprintln!("skip: unprivileged user namespaces unavailable");
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
        // First insn loads seccomp_data.nr into the accumulator.
        assert_eq!(insns[0].code, (BPF_LD | BPF_W | BPF_A) as u16);
        // Last insn is the fall-through allow; every blocked syscall is
        // matched in between and returns EPERM.
        assert_eq!(insns[insns.len() - 1].code, (BPF_RET | BPF_K) as u16);
        assert_eq!(insns[insns.len() - 1].k, SECCOMP_RET_ALLOW);
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
            eprintln!("skip: unprivileged user namespaces unavailable");
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
        let r = match b.exec("t5", &["/bin/echo".into(), "hi".into()]) {
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
            eprintln!("skip: unprivileged user namespaces unavailable");
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
            .exec("t6", &["/nonexistent/toolcage-test-prog".into()])
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
}
