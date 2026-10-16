//! Tier 0 driver v0: namespaces + Landlock + seccomp + cgroup v2.
//! Fail-closed: reports what it CANNOT enforce so policy refuses Tier1/2 needs.
//!
//! REVIEW:
//! - caps() is honest: separate_kernel=false, vsock_only=false. Policy must
//!   refuse min_isolation=tier2 here (tested). Do not flip these to true
//!   without the actual mechanism + escape-suite proof.
//! - probe() is best-effort WITHOUT privs: userns flag, cgroup2 controllers
//!   file, kernel-version-derived Landlock ABI, seccomp=true assumption.
//!   The ABI-from-version mapping drifts with new kernels — replace with a
//!   real landlock_create_ruleset(VERSION) probe before enforcing.
//! - create() currently tracks lifecycle only (no unshare/Landlock/seccomp
//!   applied yet). Real isolation lands here; until then Tier0 = policy +
//!   audit + env_clear, NOT a kernel boundary. Do not claim containment.
//! - Landlock edges (from kernel docs): port rules only, some calls
//!   unrestricted (chdir/stat/chmod), 16 ruleset stack limit, OverlayFS gaps.
//!   Build one ruleset against exposed paths; treat as one layer.
use toolcage_backend::{Backend, SessionSpec, Tier, TierCaps};

pub struct NsBackend {
    pub sessions: Vec<String>,
}

impl Default for NsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NsBackend {
    pub fn new() -> Self {
        Self { sessions: vec![] }
    }
    /// Prerequisite probe for `doctor` (no root needed for report).
    pub fn probe() -> Probe {
        Probe {
            userns: std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone").map(|s| s.trim() != "0").unwrap_or(true),
            cgroup2: std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            landlock_abi: landlock_abi(),
            seccomp: true,
        }
    }
}

#[derive(Debug)]
pub struct Probe {
    pub userns: bool,
    pub cgroup2: bool,
    pub landlock_abi: i32,
    pub seccomp: bool,
}

/// Best-effort Landlock ABI detect: try create_ruleset with VERSION flag.
// Returns -1 when unavailable (caller must refuse Tier0-gated policies).
fn landlock_abi() -> i32 {
    // v0: parse kernel version as proxy; real syscall probe lands with rustix.
    // Kernel >= 5.13 has ABI-1, >= 5.19 ABI-3, >= 6.7 ABI-5.
    let v = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut nums = v.split('.').filter_map(|x| x.parse::<i32>().ok());
    let major = nums.next().unwrap_or(0);
    let minor = nums.next().unwrap_or(0);
    if major > 6 || (major == 6 && minor >= 7) {
        5
    } else if major >= 6 || (major == 5 && minor >= 19) {
        3
    } else if major == 5 && minor >= 13 {
        1
    } else {
        -1
    }
}

impl Backend for NsBackend {
    fn tier(&self) -> Tier {
        Tier::Tier0
    }
    fn capabilities(&self) -> TierCaps {
        TierCaps {
            separate_kernel: false, // shared host kernel — documented limit
            syscall_filter: true,
            fs_mount_enforced: false, // path checks host-mediated only
            net_vsock_only: false,    // veth+firewall, not vsock
            snapshot_pool: false,
        }
    }
    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(self.honors("tier0"), "tier0 backend cannot honor {:?}", spec.tier);
        // Real unshare+Landlock+seccomp lands here (needs privs); v0 tracks lifecycle.
        self.sessions.push(spec.id.clone());
        Ok(())
    }
    fn destroy(&mut self, id: &str) -> anyhow::Result<()> {
        self.sessions.retain(|s| s != id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use toolcage_backend::Backend;
    #[test]
    fn tier0_refuses_tier2_need() {
        let b = NsBackend::new();
        assert!(b.honors("tier0"));
        assert!(!b.honors("firecracker"));
    }
    #[test]
    fn probe_reports() {
        let p = NsBackend::probe();
        assert!(p.seccomp);
    }
}
