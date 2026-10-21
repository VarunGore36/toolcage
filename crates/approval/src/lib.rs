//! Approval gates v0: actions matching require_for pause for out-of-band decision.
//! Timeout = deny. Every pause + decision is audit-logged by the caller.
//!
//! REVIEW:
//! - needs_approval() matches (action, method?, host?) with empty lists as
//!   wildcards. Adding a path axis? Keep wildcard semantics explicit — an
//!   absent list must mean "all", never "none", or gates silently stop firing.
//! - Queue is in-memory with monotonic appr-N ids. Restart loses pending +
//!   decided maps: in-flight approvals resolve to deny on restart (fail-closed
//!   only if callers treat unknown ids as deny — enforce that at call sites).
//! - decide() on unknown id returns false; resolve() unknown returns None
//!   (still waiting). Callers must map None-after-timeout to deny, never to
//!   allow, and audit the timeout as its own event.
//! - No approver auth here: whoever calls decide() approves. Bind approver
//!   identity + audit actor before exposing beyond local operator CLI.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub action: String,
    pub methods: Vec<String>,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub id: String,
    pub action: String,
    pub host: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Deny,
}

pub fn needs_approval(
    rules: &[ApprovalRule],
    action: &str,
    method: Option<&str>,
    host: Option<&str>,
) -> bool {
    rules.iter().any(|r| {
        if r.action != action {
            return false;
        }
        if !r.methods.is_empty() {
            let m = method.unwrap_or("");
            if !r.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
                return false;
            }
        }
        if !r.hosts.is_empty() {
            let h = host.unwrap_or("");
            if !r.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                return false;
            }
        }
        true
    })
}

#[derive(Debug, Default)]
pub struct Queue {
    pending: HashMap<String, Pending>,
    decided: HashMap<String, Verdict>,
    counter: u64,
}

impl Queue {
    pub fn request(&mut self, action: &str, host: Option<&str>, method: Option<&str>) -> String {
        self.counter += 1;
        let id = format!("appr-{}", self.counter);
        self.pending.insert(
            id.clone(),
            Pending {
                id: id.clone(),
                action: action.into(),
                host: host.map(|s| s.to_string()),
                method: method.map(|s| s.to_string()),
            },
        );
        id
    }
    pub fn decide(&mut self, id: &str, v: Verdict) -> bool {
        if self.pending.remove(id).is_some() {
            self.decided.insert(id.to_string(), v);
            true
        } else {
            false
        }
    }
    /// Resolve: Some(true)=approved, Some(false)=denied/timeout, None=still waiting.
    pub fn resolve(&self, id: &str) -> Option<bool> {
        self.decided.get(id).map(|v| *v == Verdict::Approve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn post_to_github_needs_approval_get_does_not() {
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec!["POST".into()],
            hosts: vec!["github".into()],
        }];
        assert!(needs_approval(
            &rules,
            "http.request",
            Some("POST"),
            Some("github")
        ));
        assert!(!needs_approval(
            &rules,
            "http.request",
            Some("GET"),
            Some("github")
        ));
        let mut q = Queue::default();
        let id = q.request("http.request", Some("github"), Some("POST"));
        assert_eq!(q.resolve(&id), None);
        assert!(q.decide(&id, Verdict::Deny));
        assert_eq!(q.resolve(&id), Some(false));
    }
}
