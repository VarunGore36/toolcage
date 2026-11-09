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
        // Fail closed on unknown: an absent/empty method or host is UNKNOWN,
        // not "matches nothing" — a method-less request could be the gated
        // method, so the gate must fire and let the operator decide. Only a
        // KNOWN-and-non-matching value (GET against a POST gate, evil
        // against a github gate) proves the rule does not apply.
        //
        // History note: commit 4cf7729 got this right ("an unknown method or
        // host cannot dodge a gate"); 5135ab7 — on a branch named
        // fix/approval-fail-closed, with a message claiming the opposite —
        // inverted the predicate into fail-open. The tests' MESSAGES
        // described the correct behavior while their assertions had been
        // flipped to pin the dodge. This restores 4cf7729's semantics and
        // re-aligns the assertions with their own messages.
        if !r.methods.is_empty() {
            let m = method.unwrap_or("");
            if !m.is_empty() && !r.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
                return false;
            }
        }
        if !r.hosts.is_empty() {
            let h = host.unwrap_or("");
            if !h.is_empty() && !r.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
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
        if let Some((k, _)) = self.pending.remove_entry(id) {
            self.decided.insert(k, v);
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

    #[test]
    fn unknown_method_or_host_cannot_dodge_a_gate() {
        // An absent/empty method or host is UNKNOWN, not "matches nothing" —
        // a gate written for POST+github must not be escaped by simply not
        // spelling the method or the host: the gate fires and the operator
        // decides. (policy::needs_approval had the same bug; this is the
        // same fix. 5135ab7 inverted this predicate while its message
        // claimed the opposite — the assertions below now agree with their
        // own messages.)
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec!["POST".into()],
            hosts: vec!["github".into()],
        }];
        assert!(
            needs_approval(&rules, "http.request", None, Some("github")),
            "an unknown method must not dodge a method-constrained gate"
        );
        assert!(
            needs_approval(&rules, "http.request", Some("POST"), None),
            "an unknown host must not dodge a host-constrained gate"
        );
        assert!(needs_approval(&rules, "http.request", None, None));
        // Known-and-wrong values still do not trigger the gate.
        assert!(!needs_approval(
            &rules,
            "http.request",
            Some("GET"),
            Some("github")
        ));
        assert!(!needs_approval(
            &rules,
            "http.request",
            Some("POST"),
            Some("evil")
        ));
        // And the wrong action never triggers it.
        assert!(!needs_approval(&rules, "proc.exec", None, None));
    }
}

#[cfg(test)]
mod gate_semantics_matrix_tests {
    use super::*;

    /// The full decision table for a gate constrained to (methods=[POST],
    /// hosts=[github]) — plus the wildcard and wrong-action axes. The
    /// invariant: UNKNOWN fires (it could be the gated value), KNOWN-WRONG
    /// passes, MATCH fires, absent list = wildcard.
    #[test]
    fn decision_table() {
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec!["POST".into()],
            hosts: vec!["github".into()],
        }];
        let n = |m: Option<&str>, h: Option<&str>| needs_approval(&rules, "http.request", m, h);

        // MATCH fires.
        assert!(n(Some("POST"), Some("github")));
        assert!(n(Some("post"), Some("GitHub"))); // case-insensitive both axes

        // UNKNOWN fires (could be the gated value).
        assert!(n(None, Some("github")));
        assert!(n(Some(""), Some("github")));
        assert!(n(Some("POST"), None));
        assert!(n(Some("POST"), Some("")));
        assert!(n(None, None));
        assert!(n(Some(""), Some("")));

        // KNOWN-WRONG passes.
        assert!(!n(Some("GET"), Some("github")));
        assert!(!n(Some("DELETE"), Some("github")));
        assert!(!n(Some("POST"), Some("evil")));
        assert!(!n(Some("GET"), Some("evil")));

        // Wrong action never fires, whatever the axes.
        assert!(!needs_approval(&rules, "fs.write", None, None));
        assert!(!needs_approval(
            &rules,
            "fs.write",
            Some("POST"),
            Some("github")
        ));
    }

    /// Wildcard axes: an absent list matches EVERYTHING — including unknown
    /// values. (The module header's warning: an absent list must mean "all",
    /// never "none", or gates silently stop firing.)
    #[test]
    fn wildcard_axes_match_everything_including_unknown() {
        // Wildcard methods, constrained host.
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec![],
            hosts: vec!["github".into()],
        }];
        let n = |m: Option<&str>, h: Option<&str>| needs_approval(&rules, "http.request", m, h);
        assert!(n(Some("GET"), Some("github")));
        assert!(n(None, Some("github"))); // unknown method, wildcard methods
        assert!(n(Some("POST"), None)); // unknown host still fires (host constrained)
        assert!(!n(Some("GET"), Some("evil"))); // known-wrong host passes

        // Constrained method, wildcard host.
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec!["POST".into()],
            hosts: vec![],
        }];
        let n = |m: Option<&str>, h: Option<&str>| needs_approval(&rules, "http.request", m, h);
        assert!(n(Some("POST"), Some("evil")));
        assert!(n(Some("POST"), None)); // unknown host, wildcard hosts
        assert!(!n(Some("GET"), Some("github"))); // known-wrong method passes

        // Fully wildcard: every request of the action fires.
        let rules = vec![ApprovalRule {
            action: "http.request".into(),
            methods: vec![],
            hosts: vec![],
        }];
        assert!(needs_approval(&rules, "http.request", None, None));
        assert!(needs_approval(
            &rules,
            "http.request",
            Some("GET"),
            Some("evil")
        ));
    }

    /// Multiple rules: ANY matching rule fires (the .any() semantics), and a
    /// rule that is known-wrong on either axis does not mask a later rule
    /// that matches.
    #[test]
    fn any_matching_rule_fires() {
        let rules = vec![
            ApprovalRule {
                action: "http.request".into(),
                methods: vec!["GET".into()],
                hosts: vec!["github".into()],
            },
            ApprovalRule {
                action: "http.request".into(),
                methods: vec!["POST".into()],
                hosts: vec!["registry".into()],
            },
        ];
        let n = |m: Option<&str>, h: Option<&str>| needs_approval(&rules, "http.request", m, h);
        assert!(n(Some("GET"), Some("github")));
        assert!(n(Some("POST"), Some("registry")));
        assert!(!n(Some("GET"), Some("registry")));
        assert!(!n(Some("POST"), Some("github")));
        // Unknown values: each constrained rule fires (first one wins).
        assert!(n(None, None));
        assert!(n(None, Some("github")));
    }
}
