//! Tier 1 gVisor driver v1: real runsc exec.
//!
//! `exec(id, argv)` shells out to `runsc exec <id> -- <argv>`, streaming
//! stdout/stderr with caps + timeout kill. `create()` builds an OCI bundle
//! (config.json + rootfs), then `runsc create` + `runsc start`. `destroy()`
//! runs `runsc kill` + `runsc delete`.
//!
//! This is a genuine kernel-boundary tier for Tier1: the container shares the
//! host kernel but runsc intercepts syscalls in userspace. Needs runsc
//! installed (Debian pkg or tarball; post Sep-2026 install requires sidecar
//! binaries — `doctor` checks `runsc --version`).
//!
//! Without runsc present, every operation fails closed with an error — never
//! silently falls back to a direct spawn.
//!
//! REVIEW:
//! - runsc create/start typically need root or setuid; unprivileged hosts
//!   will fail closed here, which is correct.
//! - The OCI rootfs must exist at /var/lib/toolcage/rootfs (golden image,
//!   see plan §11 images/build.sh). create() fails closed if missing.
//! - runsc exec streams I/O over runsc's own channel; we cap + truncate like
//!   Tier0.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use toolcage_backend::{Backend, CommandResult, SessionSpec, Tier};

const OUTPUT_CAP: usize = 1024 * 1024;

/// The container's long-running init (`process.args` in the OCI spec). This is
/// NOT the workload — `create` + repeated `exec` needs the container alive
/// between commands, so the init is a pause loop. Operator-controlled; the
/// rootfs must provide /bin/sh and sleep (the alpine image does).
const INIT_ARGS: &[&str] = &["/bin/sh", "-c", "while :; do sleep 3600; done"];

/// argv for `runsc create`. The bundle is a FLAG and the container id is the
/// single positional: upstream rejects two positionals with a usage error
/// (`if f.NArg() != 1`), so `create <id> <bundle>` never worked.
fn runsc_create_args(id: &str, bundle: &std::path::Path) -> Vec<String> {
    vec![
        "create".into(),
        "--bundle".into(),
        bundle.display().to_string(),
        id.into(),
    ]
}

fn runsc_start_args(id: &str) -> Vec<String> {
    vec!["start".into(), id.into()]
}

fn runsc_exec_args(id: &str, argv: &[String]) -> Vec<String> {
    let mut a = vec!["exec".into(), id.into(), "--".into()];
    a.extend(argv.iter().cloned());
    a
}

/// Kill a container's processes with SIGKILL. runsc's default signal is
/// SIGTERM, which a workload may trap or ignore — a timed-out workload must
/// actually die.
fn runsc_kill_args(id: &str) -> Vec<String> {
    vec!["kill".into(), id.into(), "KILL".into()]
}

fn runsc_delete_args(id: &str) -> Vec<String> {
    vec!["delete".into(), id.into()]
}

pub struct GvBackend {
    pub runsc_path: PathBuf,
    pub sessions: HashMap<String, SessionSpec>,
}

impl Default for GvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl GvBackend {
    pub fn new() -> Self {
        Self {
            runsc_path: find_runsc(),
            sessions: HashMap::new(),
        }
    }

    /// Verify runsc is actually executable (not just a stale PATH entry).
    pub fn runsc_present(&self) -> bool {
        Command::new(&self.runsc_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// OCI bundle config.json for runsc. Read-only rootfs, workspace bind
    /// mount, full namespace set, no capabilities, noNewPrivileges.
    ///
    /// `process.args` is the container's long-running init, not the workload:
    /// the session model (`create` then repeated `exec`) needs the container
    /// alive between commands, and runsc rejects a spec with no args
    /// ("Spec.Process.Arg must be defined"). Operator-controlled, never
    /// guest-supplied. Requires /bin/sh and sleep in the rootfs (the alpine
    /// image has both).
    pub fn bundle_config(session: &str, rootfs: &str, workspace: &str) -> serde_json::Value {
        serde_json::json!({
            "ociVersion": "1.0.0",
            "id": session,
            "root": { "path": rootfs, "readonly": true },
            "mounts": [
                // /proc first: maskedPaths/readonlyPaths below reference it,
                // and the runtime expects the mount to exist.
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/workspace", "type": "bind", "source": workspace, "options": ["rw", "rbind"] },
            ],
            "linux": {
                "namespaces": [
                    { "type": "pid" },
                    { "type": "ipc" },
                    { "type": "uts" },
                    { "type": "mount" },
                    { "type": "network" },
                ],
                "resources": {
                    // Deny-all: the rule must set all:true to mean "no device
                    // nodes". `all:false` matches nothing and enforces nothing.
                    "devices": [ { "allow": false, "all": true } ]
                },
                "maskedPaths": [
                    "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                    "/proc/timer_list", "/proc/timer_stats", "/proc/scsi", "/proc/fb",
                    "/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
                ],
                "readonlyPaths": [
                    "/proc/asound", "/proc/cpuinfo", "/proc/meminfo", "/proc/net",
                    "/proc/stat", "/proc/uptime", "/proc/version",
                ],
            },
            "process": {
                "user": { "uid": 0, "gid": 0 },
                "args": INIT_ARGS,
                "cwd": "/",
                "terminal": false,
                "capabilities": {
                    "bounding": [],
                    "effective": [],
                    "inheritable": [],
                    "permitted": [],
                    "ambient": [],
                },
                "noNewPrivileges": true,
            },
        })
    }

    fn bundle_dir(id: &str) -> PathBuf {
        PathBuf::from(format!("/run/toolcage/{id}"))
    }

    fn rootfs_dir() -> PathBuf {
        PathBuf::from("/var/lib/toolcage/rootfs")
    }
}

fn find_runsc() -> PathBuf {
    for p in [
        "/usr/bin/runsc",
        "/usr/local/bin/runsc",
        "/opt/toolcage/bin/runsc",
    ] {
        if PathBuf::from(p).exists() {
            return PathBuf::from(p);
        }
    }
    // PATH fallback
    if let Ok(out) = Command::new("which").arg("runsc").output() {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return PathBuf::from(trimmed);
                }
            }
        }
    }
    PathBuf::from("runsc") // hope it's in PATH
}

impl Backend for GvBackend {
    fn tier(&self) -> Tier {
        Tier::Tier1
    }

    fn capabilities(&self) -> toolcage_backend::TierCaps {
        toolcage_backend::TierCaps {
            separate_kernel: false, // user-space kernel, shared host kernel underneath
            syscall_filter: true,
            fs_mount_enforced: true,
            net_vsock_only: false, // veth-to-proxy, not vsock
            snapshot_pool: false,
        }
    }

    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(
            spec.tier == Tier::Tier0 || spec.tier == Tier::Tier1,
            "gvisor backend cannot honor {:?}",
            spec.tier
        );
        anyhow::ensure!(
            self.runsc_present(),
            "runsc not installed; tier1 unavailable"
        );

        let bundle_dir = Self::bundle_dir(&spec.id);
        let rootfs = Self::rootfs_dir();

        // Create bundle directory structure
        std::fs::create_dir_all(bundle_dir.join("rootfs"))?;
        std::fs::create_dir_all(bundle_dir.join("workspace"))?;

        // Write config.json
        let config = Self::bundle_config(&spec.id, rootfs.to_str().unwrap_or(""), &spec.workspace);
        let config_json = serde_json::to_string_pretty(&config)?;
        std::fs::write(bundle_dir.join("config.json"), config_json)?;

        // runsc create --bundle <dir> <id> (bundle is a flag; the id is the
        // single positional — two positionals is a usage error upstream).
        let status = Command::new(&self.runsc_path)
            .args(runsc_create_args(&spec.id, &bundle_dir))
            .status()
            .context("runsc create failed")?;
        anyhow::ensure!(status.success(), "runsc create exited with {status}");

        // runsc start <id>
        let status = Command::new(&self.runsc_path)
            .args(runsc_start_args(&spec.id))
            .status()
            .context("runsc start failed")?;
        anyhow::ensure!(status.success(), "runsc start exited with {status}");

        self.sessions.insert(spec.id.clone(), spec.clone());
        Ok(())
    }

    fn destroy(&mut self, id: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.runsc_present(),
            "runsc not installed; tier1 unavailable"
        );

        // SIGKILL the container's processes (runsc's default is SIGTERM, which
        // a workload may trap), then delete once it has actually stopped:
        // deleting a still-running container fails ("container still running")
        // and leaks it.
        let _ = Command::new(&self.runsc_path)
            .args(runsc_kill_args(id))
            .status();

        let mut last = None;
        for _ in 0..50 {
            let st = Command::new(&self.runsc_path)
                .args(runsc_delete_args(id))
                .status()
                .context("runsc delete failed")?;
            if st.success() {
                self.sessions.remove(id);
                return Ok(());
            }
            last = Some(st);
            thread::sleep(Duration::from_millis(100));
        }
        anyhow::ensure!(
            last.map(|s| s.success()).unwrap_or(false),
            "runsc delete exited with {:?}",
            last
        );
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
        anyhow::ensure!(
            self.runsc_present(),
            "runsc not installed; tier1 unavailable"
        );
        anyhow::ensure!(self.sessions.contains_key(id), "session {id} not created");
        anyhow::ensure!(!argv.is_empty(), "empty argv");

        // runsc exec <id> -- <argv...>
        let mut cmd = Command::new(&self.runsc_path);
        cmd.args(runsc_exec_args(id, argv));

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .context("runsc exec spawn failed")?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let (tx_out, rx_out) = channel();
        let (tx_err, rx_err) = channel();

        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.take((cap + 1) as u64).read_to_end(&mut buf);
            let _ = tx_out.send(buf);
        });
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.take((cap + 1) as u64).read_to_end(&mut buf);
            let _ = tx_err.send(buf);
        });

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let mut timed_out = false;
        let exit_code = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st.code(),
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        // SIGKILL the in-sandbox workload too: the runsc exec
                        // client may outlive (or fail to signal) the workload,
                        // which would keep running after the exec is recorded
                        // as timed out. runsc kill's default is SIGTERM, which
                        // a workload may trap.
                        let _ = Command::new(&self.runsc_path)
                            .args(runsc_kill_args(id))
                            .status();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
        };
        // Reap the child so no zombie is left behind after a timeout kill.
        let _ = child.wait();

        let mut truncated = timed_out;
        let mut stdout_buf = rx_out
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        let mut stderr_buf = rx_err
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();

        if stdout_buf.len() > cap {
            stdout_buf.truncate(cap);
            truncated = true;
        }
        if stderr_buf.len() > cap {
            stderr_buf.truncate(cap);
            truncated = true;
        }

        Ok(CommandResult {
            exit_code: if timed_out { None } else { exit_code },
            stdout: stdout_buf,
            stderr: stderr_buf,
            truncated,
        })
    }
}

/// Doctor probe: what the host can provide for Tier 1 (gVisor/runsc).
#[derive(Debug, Default)]
pub struct GvProbe {
    pub runsc_present: bool,
    pub runsc_version: Option<String>,
}

impl GvBackend {
    /// Prerequisite probe for `doctor` (no root needed for the report).
    pub fn probe() -> GvProbe {
        let runsc_path = find_runsc();
        let present = Command::new(&runsc_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let version = if present {
            Command::new(&runsc_path)
                .arg("--version")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        } else {
            None
        };
        GvProbe {
            runsc_present: present,
            runsc_version: version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolcage_backend::Backend;

    #[test]
    fn tier1_honors_t0_t1_not_t2() {
        let b = GvBackend::new();
        assert!(b.honors("tier0"));
        assert!(b.honors("gvisor"));
        assert!(b.honors("runsc"));
        assert!(!b.honors("firecracker"));
        assert!(!b.honors("tier2"));
    }

    #[test]
    fn bundle_config_structure() {
        let cfg = GvBackend::bundle_config("sess1", "/var/lib/toolcage/rootfs", "/tmp/workspace");
        assert_eq!(cfg["ociVersion"], "1.0.0");
        assert_eq!(cfg["id"], "sess1");
        assert_eq!(cfg["root"]["path"], "/var/lib/toolcage/rootfs");
        assert_eq!(cfg["root"]["readonly"], true);
        // /proc must be mounted: maskedPaths/readonlyPaths reference it and the
        // runtime expects the mount to exist.
        let mounts = cfg["mounts"].as_array().unwrap();
        assert!(
            mounts.iter().any(|m| m["destination"] == "/proc"),
            "a /proc mount is required"
        );
        let ws = mounts
            .iter()
            .find(|m| m["destination"] == "/workspace")
            .expect("workspace mount");
        assert_eq!(ws["source"], "/tmp/workspace");
        let opts: Vec<&str> = ws["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(opts.contains(&"rw"));
        assert!(opts.contains(&"rbind"));
        let ns_types: Vec<&str> = cfg["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        assert!(ns_types.contains(&"network"));
        assert!(ns_types.contains(&"pid"));
        assert!(ns_types.contains(&"mount"));
        // no capabilities, noNewPrivileges
        assert_eq!(
            cfg["process"]["capabilities"]["bounding"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(cfg["process"]["noNewPrivileges"], true);
        // runsc rejects a spec with no process.args ("Spec.Process.Arg must be
        // defined") — the container's long-running init is required.
        let args = cfg["process"]["args"].as_array().expect("process.args");
        assert!(!args.is_empty(), "process.args must be defined for runsc");
        assert_eq!(cfg["process"]["cwd"], "/");
        // Deny-all devices: `all:false` matches nothing and enforces nothing.
        assert_eq!(cfg["linux"]["resources"]["devices"][0]["all"], true);
        assert_eq!(cfg["linux"]["resources"]["devices"][0]["allow"], false);
    }

    #[test]
    fn runsc_command_shapes_match_upstream() {
        // `runsc create` takes the bundle as --bundle and the id as the single
        // positional; two positionals is a usage error upstream (`f.NArg() != 1`).
        let bundle = std::path::Path::new("/run/toolcage/sess1");
        assert_eq!(
            runsc_create_args("sess1", bundle),
            vec![
                "create".to_string(),
                "--bundle".to_string(),
                "/run/toolcage/sess1".to_string(),
                "sess1".to_string()
            ]
        );
        assert_eq!(runsc_start_args("sess1"), vec!["start".to_string(), "sess1".to_string()]);
        assert_eq!(
            runsc_exec_args("sess1", &["/bin/echo".into(), "hi".into()]),
            vec![
                "exec".to_string(),
                "sess1".to_string(),
                "--".to_string(),
                "/bin/echo".to_string(),
                "hi".to_string()
            ]
        );
        // Kill must be SIGKILL: runsc's default is SIGTERM, which a workload
        // can trap, so a timed-out workload would survive.
        assert_eq!(
            runsc_kill_args("sess1"),
            vec!["kill".to_string(), "sess1".to_string(), "KILL".to_string()]
        );
        assert_eq!(runsc_delete_args("sess1"), vec!["delete".to_string(), "sess1".to_string()]);
    }

    #[test]
    fn exec_fails_without_runsc() {
        let mut b = GvBackend::new();
        if b.runsc_present() {
            eprintln!("skip: runsc is installed on this host");
            return;
        }
        let err = b.exec("nonexistent", &["/bin/echo".into(), "hi".into()], 30, OUTPUT_CAP);
        assert!(err.is_err(), "exec without runsc must fail closed");
    }

    #[test]
    fn create_fails_without_runsc() {
        let mut b = GvBackend::new();
        if b.runsc_present() {
            eprintln!("skip: runsc is installed on this host");
            return;
        }
        let spec = SessionSpec {
            id: "s1".into(),
            tier: Tier::Tier1,
            mem_mb: 1024,
            workspace_mb: 0,
            workspace: "/tmp".into(),
        };
        let err = b.create(&spec);
        assert!(err.is_err(), "create without runsc must fail closed");
    }

    #[test]
    fn probe_reports_runsc_presence() {
        let p = GvBackend::probe();
        // runsc_present and runsc_version must be consistent:
        // if present, version is Some; if absent, version is None.
        assert_eq!(p.runsc_present, p.runsc_version.is_some());
    }
}
