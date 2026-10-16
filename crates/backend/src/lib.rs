//! Backend trait v0: one API, three tiers. Policy engine uses
//! capabilities() to refuse policies a tier cannot honor (fail-closed).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Tier {
    Tier0,
    Tier1,
    Tier2,
}

impl Tier {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tier0" | "ns" | "landlock" => Ok(Tier::Tier0),
            "tier1" | "gvisor" | "runsc" => Ok(Tier::Tier1),
            "tier2" | "firecracker" | "microvm" => Ok(Tier::Tier2),
            _ => anyhow::bail!("unknown tier {s}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TierCaps {
    pub separate_kernel: bool,
    pub syscall_filter: bool,
    pub fs_mount_enforced: bool,
    pub net_vsock_only: bool,
    pub snapshot_pool: bool,
}

#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub id: String,
    pub tier: Tier,
    pub mem_mb: u64,
    pub workspace_mb: u64,
}

pub trait Backend {
    fn tier(&self) -> Tier;
    fn capabilities(&self) -> TierCaps;
    /// Returns true if this backend can honor the policy's min_isolation.
    fn honors(&self, min_isolation: &str) -> bool {
        let need = Tier::parse(min_isolation).unwrap_or(Tier::Tier2);
        matches!(
            (need, self.tier()),
            (Tier::Tier0, _)
                | (Tier::Tier1, Tier::Tier1 | Tier::Tier2)
                | (Tier::Tier2, Tier::Tier2)
        )
    }
    fn create(&mut self, spec: &SessionSpec) -> anyhow::Result<()>;
    fn destroy(&mut self, id: &str) -> anyhow::Result<()>;
}
