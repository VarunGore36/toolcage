//! Tier 1 gVisor driver v0: runsc OCI bundle.
//! Fits hosts without KVM. Syscall overhead + compat gaps documented;
//! install is multi-file release (Debian pkg or tarball, post Sep-2026).
//!
//! REVIEW:
//! - Position: user-space kernel in front of the host kernel — narrower than
//!   Tier0, weaker than Tier2 (shared host kernel underneath). honors(tier0/1)
//!   but NOT tier2 (tested); CLI must keep enforcing that.
//! - bundle_config() is a skeleton JSON (ro root, /workspace bind, net
//!   annotation). Real runsc needs a full OCI spec + rootfs; install format
//!   changed in 2026 (sidecar binaries required) — `doctor` should check
//!   `runsc --version` + sidecars, not just which-runsc.
//! - runsc_present probed via `which`; a stale PATH entry lies. Verify by
//!   executing version query at session create and fail closed on mismatch.
use toolcage_backend::{Backend, SessionSpec, Tier, TierCaps};

pub struct GvBackend {
    pub runsc_present: bool,
}

impl Default for GvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl GvBackend {
    pub fn new() -> Self {
        Self { runsc_present: which_runsc() }
    }
    /// OCI bundle config for runsc (v0 skeleton: bundle dir + rootfs + mounts).
    pub fn bundle_config(session: &str, rootfs: &str) -> serde_json::Value {
        serde_json::json!({
            "ociVersion": "1.0.0",
            "id": session,
            "root": { "path": rootfs, "readonly": true },
            "mounts": [{ "destination": "/workspace", "type": "bind", "source": format!("/run/toolcage/{session}.ws"), "options": ["rw"] }],
            "annotations": { "toolcage.tier": "gvisor", "toolcage.net": "veth-to-proxy" },
        })
    }
}

fn which_runsc() -> bool {
    std::process::Command::new("which").arg("runsc").output().map(|o| o.status.success()).unwrap_or(false)
}

impl Backend for GvBackend {
    fn tier(&self) -> Tier {
        Tier::Tier1
    }
    fn capabilities(&self) -> TierCaps {
        TierCaps {
            separate_kernel: false, // user-space kernel, shared host kernel underneath
            syscall_filter: true,
            fs_mount_enforced: true,
            net_vsock_only: false,
            snapshot_pool: false,
        }
    }
    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(self.honors("tier1") || spec.tier == Tier::Tier0, "tier mismatch");
        let _ = Self::bundle_config(&spec.id, "/var/lib/toolcage/rootfs");
        Ok(())
    }
    fn destroy(&mut self, _id: &str) -> anyhow::Result<()> {
        Ok(())
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
        assert!(!b.honors("firecracker"));
    }
}
