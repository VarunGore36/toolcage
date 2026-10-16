//! Policy v0: YAML-shaped struct + default-deny evaluator stub (M1).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub tool: String,
    pub min_isolation: String,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub action: String,
    pub host: Option<String>,
}

pub fn decide(policy: &Policy, req: &Request) -> bool {
    // M1 stub: default deny unless explicitly handled in later milestone.
    // Forbid metadata always.
    if let Some(h) = &req.host {
        if h.contains("169.254.169.254") {
            return false;
        }
    }
    let _ = policy;
    let _ = req;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_always_denied() {
        let p = Policy { tool: "t".into(), min_isolation: "tier0".into() };
        assert!(!decide(&p, &Request { action: "net.connect".into(), host: Some("169.254.169.254".into()) }));
    }
}
