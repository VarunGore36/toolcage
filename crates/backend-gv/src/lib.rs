//! Tier 1 gVisor driver v0: runsc OCI bundle.
//! Fits hosts without KVM. Syscall overhead + compat gaps documented;
//! install is multi-file release (Debian pkg or tarball, post Sep-2026).
use toolcage_backend::{Backend, SessionSpec, Tier, TierCaps};

pub struct GvBackend {
    pub runsc_present: bool,
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
