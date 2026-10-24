//! Backend trait v0: one API, three tiers. Policy engine uses
//! capabilities() to refuse policies a tier cannot honor (fail-closed).
//!
//! REVIEW:
//! - honors() encodes the lattice Tier0 < Tier1 < Tier2: a backend honors its
//!   own tier and everything below, never above. A new tier must slot into
//!   this match explicitly; the wildcard `_ => false` keeps unknown pairs
//!   denied. Callers (CLI run --tier) must deny+exit(2) on false, never
//!   silently fall back to a weaker tier.
//! - Tier::parse accepts aliases ("ns", "gvisor", "microvm"); unknown strings
//!   bail. Do not add a lenient default — explicit tiers only.
//! - SessionSpec carries budgets (mem/workspace MB) but no enforcement here;
//!   enforcement belongs in each driver (cgroup/rate-limiter) + supervisor.
//!   capabilities() is advisory data for the policy engine, not a guarantee.
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
    /// Host path bind-mounted as `/workspace` inside Tier0 (enforced by policy).
    pub workspace: String,
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
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
    /// Run argv inside an isolated session. Tier0 implements this with
    /// namespaces + Landlock + seccomp; other tiers return Err until wired.
    /// `timeout_secs` bounds wall-clock time; `cap` bounds each output stream.
    /// Kill on timeout (fail-closed); truncation flagged in audit outcome.
    fn exec(
        &mut self,
        _id: &str,
        _argv: &[String],
        _timeout_secs: u64,
        _cap: usize,
    ) -> anyhow::Result<CommandResult> {
        anyhow::bail!("backend exec not implemented for tier {:?}", self.tier())
    }
}
