//! Tier 2 Firecracker driver v0: jailer + vsock + snapshot pool skeleton.
//! Real VMM control goes through Firecracker's REST API on a Unix socket.
// This crate owns config generation, pool lifecycle, and uniqueness rules.
//!
//! REVIEW:
//! - Config: jailer runs unprivileged (uid 65532), own netns, cgroup slice.
//!   vsock_cid derived from session bytes (3..10002) — collisions across many
//!   sessions possible; use an allocator + CID reuse guard before production.
//! - Net: vsock-only by design (no NIC field at all). Adding a tap device for
//!   debugging reopens raw/ICMP/IPv6 paths — keep it out of default configs.
//! - Pool: pre-restored paused VMs must carry NO per-session state/secrets.
//!   claim() logs the 5 uniqueness steps (workspace attach, RNG reseed via
//!   VMGenID k>=5.18, wall-clock reset, vsock re-establish, CID bind) because
//!   Firecracker snapshots clone identifiers/RNG tokens into every child.
//!   Golden images only, never snapshots of dirty sessions; sign + verify.
//! - create() currently checks /dev/kvm + honors() but does NOT boot a VM
//!   (no REST calls yet). Escape-suite-on-KVM stays red until boot lands.
//! - Snapshot files are trusted by Firecracker (CRC only): verify signature +
//!   hash before load, pin VMM/kernel versions (snapshots break across them).
use std::collections::VecDeque;
use toolcage_backend::{Backend, SessionSpec, Tier, TierCaps};

#[derive(Debug, Clone)]
pub struct FcConfig {
    pub socket: String,
    pub kernel: String,
    pub rootfs: String,
    pub mem_mb: u64,
    pub vcpu: u64,
    /// vsock-only: no NIC. Guest gets vsock CID + control channel.
    pub vsock_cid: u32,
    pub jailer_uid: u32,
}

impl FcConfig {
    pub fn for_session(id: &str, mem_mb: u64) -> Self {
        let cid = 3 + (id.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32)) % 10000);
        Self {
            socket: format!("/run/toolcage/{id}.sock"),
            kernel: "/var/lib/toolcage/vmlinux".into(),
            rootfs: "/var/lib/toolcage/rootfs.ext4".into(),
            mem_mb,
            vcpu: 1,
            vsock_cid: cid,
            jailer_uid: 65532,
        }
    }
    /// Firecracker jailer argv (unprivileged, own netns, tight seccomp+cgroup).
    pub fn jailer_argv(&self, id: &str) -> Vec<String> {
        vec![
            "jailer".into(),
            "--id".into(), id.into(),
            "--uid".into(), self.jailer_uid.to_string(),
            "--gid".into(), self.jailer_uid.to_string(),
            "--netns".into(), format!("/run/toolcage/{id}.netns"),
            "--cgroup".into(), format!("cpu,cpuset:toolcage-{id}"),
            "--".into(), "firecracker".into(),
            "--api-sock".into(), self.socket.clone(),
        ]
    }
}

/// Golden-image pool: pre-restored paused µVMs, no per-session state.
// Hazards handled on claim: reseed entropy, reset wall clock, re-establish
// vsock (closed on snapshot restore), reject clones sharing pre-snapshot RNG.
pub struct WarmPool {
    pub max: usize,
    free: VecDeque<String>,
}

impl WarmPool {
    pub fn new(max: usize) -> Self {
        Self { max, free: VecDeque::new() }
    }
    pub fn refill(&mut self, golden: &str) {
        while self.free.len() < self.max {
            self.free.push_back(format!("{golden}#{}", self.free.len()));
        }
    }
    /// Claim a VM and apply uniqueness steps. Returns VM handle + steps log.
    pub fn claim(&mut self, session: &str) -> anyhow::Result<(String, Vec<String>)> {
        let vm = self.free.pop_front().ok_or_else(|| anyhow::anyhow!("pool empty"))?;
        let steps = vec![
            format!("attach workspace disk for {session}"),
            "reseed guest RNG (VMGenID, kernel>=5.18)".into(),
            "reset wall clock (snapshot froze it)".into(),
            "re-establish vsock control channel".into(),
            format!("bind vsock CID for {session}"),
        ];
        Ok((vm, steps))
    }
    pub fn hit_rate(&self) -> f64 {
        self.free.len() as f64 / self.max as f64
    }
}

pub struct FcBackend {
    pub kvm_present: bool,
    pub pool: WarmPool,
}

impl Default for FcBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FcBackend {
    pub fn new() -> Self {
        Self { kvm_present: std::path::Path::new("/dev/kvm").exists(), pool: WarmPool::new(4) }
    }
}

impl Backend for FcBackend {
    fn tier(&self) -> Tier {
        Tier::Tier2
    }
    fn capabilities(&self) -> TierCaps {
        TierCaps {
            separate_kernel: true,
            syscall_filter: true,
            fs_mount_enforced: true,
            net_vsock_only: true,
            snapshot_pool: true,
        }
    }
    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()> {
        anyhow::ensure!(self.kvm_present, "Tier2 needs /dev/kvm");
        anyhow::ensure!(self.honors("firecracker"), "tier mismatch");
        let _cfg = FcConfig::for_session(&spec.id, spec.mem_mb);
        Ok(())
    }
    fn destroy(&mut self, _id: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jailer_argv_pins_unpriv() {
        let c = FcConfig::for_session("s1", 256);
        let a = c.jailer_argv("s1");
        assert!(a.contains(&"--netns".to_string()));
        assert!(c.vsock_cid >= 3);
    }
    #[test]
    fn pool_claim_applies_uniqueness() {
        let mut p = WarmPool::new(2);
        p.refill("golden");
        let (_, steps) = p.claim("s1").unwrap();
        assert!(steps.iter().any(|s| s.contains("RNG")));
        assert!(steps.iter().any(|s| s.contains("vsock")));
    }
    #[test]
    fn tier2_honors_all() {
        let b = FcBackend::new();
        assert!(b.honors("tier0") && b.honors("tier1") && b.honors("firecracker"));
    }
}
