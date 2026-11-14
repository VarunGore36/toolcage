//! Approval gates v0: actions matching require_for pause for out-of-band decision.
//! Timeout = deny. Every pause + decision is audit-logged by the caller.
//!
//! GATE POLARITY (needs_approval): for a constrained axis, UNKNOWN fires the
//! gate and KNOWN-WRONG passes it:
//!   method/host = None or empty  -> UNKNOWN  -> gate FIRES (it could be the
//!                                   gated value; the operator decides)
//!   method/host = known, wrong   -> KNOWN-WRONG -> gate passes
//!   list absent/empty            -> wildcard   -> matches everything
//! An inversion of the first rule turns every gate into a rubber stamp for
//! any request that omits the field the gate is written for.
//!
//! History: 4cf7729 established this polarity ("an unknown method or host
//! cannot dodge a gate"); 5135ab7 — on a branch named fix/approval-fail-
//! closed, with a message claiming the opposite — inverted it to fail-open;
//! the tests' messages kept describing the correct behavior while their
//! assertions pinned the dodge, and THREAT_MODEL I3 kept claiming the fix
//! existed. Restored in the approval-gate series; the decision-table tests
//! now pin it from both crates.
//!
//! REVIEW:
//! - needs_approval() matches (action, method?, host?) with empty lists as
//!   wildcards. Adding a path axis? Keep wildcard semantics explicit — an
//!   absent list must mean "all", never "none", or gates silently stop firing.
//!   Keep the UNKNOWN-fires rule per axis too: a new axis with the inverted
//!   polarity is the same bug in a new place.
//! - Queue is in-memory with monotonic appr-N ids. Restart loses pending +
//!   decided maps: in-flight approvals resolve to deny on restart (fail-closed
//!   only if callers treat unknown ids as deny — enforce that at call sites).
//! - decide() on unknown id returns false; resolve() unknown returns None
//!   (still waiting). Callers must map None-after-timeout to deny, never to
//!   allow, and audit the timeout as its own event. decide() on an
//!   already-decided id returns false: the first verdict stands.
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
    /// Wall-clock seconds at request() time. The crate has no clock of its
    /// own — the caller's sweep passes `now` — but the timestamp is captured
    /// here so "timeout = deny" is enforceable from the recorded data.
    pub created_at: u64,
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
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A pre-epoch clock yields 0: the entry simply never looks
            // expired relative to a sane `now`, and the caller's timeout
            // sweep stays the enforcement point. Fail-closed behavior on a
            // broken clock belongs to the caller's timeout, not here.
            .unwrap_or(0);
        self.pending.insert(
            id.clone(),
            Pending {
                id: id.clone(),
                action: action.into(),
                host: host.map(|s| s.to_string()),
                method: method.map(|s| s.to_string()),
                created_at,
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

    /// Enforce "timeout = deny": every pending request older than
    /// `timeout_secs` is moved to decided-Deny, and the swept ids are
    /// returned so the caller can audit each timeout as its own event.
    ///
    /// The caller supplies `now` (wall-clock seconds) — the crate keeps no
    /// clock of its own, and a caller that never sweeps never times out
    /// (fail-closed pressure stays with whoever pauses the action, since a
    /// pause that never resolves must block the action, not wave it
    /// through).
    pub fn sweep_expired(&mut self, now: u64, timeout_secs: u64) -> Vec<String> {
        let expired: Vec<String> = self
            .pending
            .values()
            .filter(|p| now.saturating_sub(p.created_at) >= timeout_secs)
            .map(|p| p.id.clone())
            .collect();
        for id in &expired {
            if let Some((k, _)) = self.pending.remove_entry(id) {
                self.decided.insert(k, Verdict::Deny);
            }
        }
        expired
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

#[cfg(test)]
mod queue_contract_tests {
    use super::*;

    /// The Queue contract the module header states and callers must be able
    /// to rely on:
    /// - resolve() on an unknown id is None (still waiting) — callers must
    ///   map None-after-timeout to DENY, never to allow
    /// - decide() on an unknown id returns false (nothing was decided)
    /// - decide() on an already-decided id returns false (no re-deciding:
    ///   the first verdict stands)
    /// - a decided id resolves to its verdict forever
    #[test]
    fn queue_contract_pins() {
        let mut q = Queue::default();

        // Unknown id: nothing pending, nothing decided.
        assert!(
            !q.decide("appr-999", Verdict::Approve),
            "unknown id must not decide"
        );
        assert_eq!(
            q.resolve("appr-999"),
            None,
            "unknown id resolves to None (still waiting)"
        );

        // Approve path.
        let a = q.request("http.request", Some("github"), Some("POST"));
        assert_eq!(q.resolve(&a), None);
        assert!(q.decide(&a, Verdict::Approve));
        assert_eq!(q.resolve(&a), Some(true));
        // Re-decide is refused: the first verdict stands.
        assert!(
            !q.decide(&a, Verdict::Deny),
            "already-decided id must not re-decide"
        );
        assert_eq!(q.resolve(&a), Some(true));

        // Deny path.
        let d = q.request("http.request", Some("github"), Some("POST"));
        assert!(q.decide(&d, Verdict::Deny));
        assert_eq!(q.resolve(&d), Some(false));
        assert!(!q.decide(&d, Verdict::Approve));
        assert_eq!(q.resolve(&d), Some(false));

        // Ids are monotonic: two requests never share an id.
        let x = q.request("http.request", None, None);
        let y = q.request("http.request", None, None);
        assert_ne!(x, y);
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    /// "Timeout = deny" is the documented contract; sweep_expired enforces
    /// it: expired pendings become decided-Deny (and resolve as such
    /// forever), fresh ones keep waiting, and the swept ids come back for
    /// the caller to audit each timeout as its own event.
    #[test]
    fn sweep_moves_expired_to_deny_and_returns_their_ids() {
        let mut q = Queue::default();
        let a = q.request("http.request", Some("github"), Some("POST"));
        let b = q.request("http.request", Some("github"), Some("POST"));
        // Backdate both: a is beyond the timeout, b is fresh.
        q.pending.get_mut(&a).unwrap().created_at = 1_000;
        q.pending.get_mut(&b).unwrap().created_at = 1_990;

        let swept = q.sweep_expired(2_000, 60);
        assert_eq!(swept, vec![a.clone()]);

        // Swept: denied forever, decided-Deny, no re-deciding.
        assert_eq!(q.resolve(&a), Some(false));
        assert!(!q.decide(&a, Verdict::Approve));
        assert_eq!(q.resolve(&a), Some(false));

        // Fresh: still waiting, still decidable.
        assert_eq!(q.resolve(&b), None);
        assert!(q.decide(&b, Verdict::Approve));
        assert_eq!(q.resolve(&b), Some(true));

        // Sweeping again finds nothing new.
        assert!(q.sweep_expired(2_000, 60).is_empty());
    }

    #[test]
    fn verdict_approve_then_sweep_stays_approved() {
        let mut q = super::Queue::default();
        let id = q.request("http.request", Some("example.com"), Some("GET"));
        // Approve first
        assert!(q.decide(&id, super::Verdict::Approve));
        assert_eq!(q.resolve(&id), Some(true));
        // Sweeping should not change an already-decided verdict
        q.sweep_expired(1_000_000, 60);
        assert_eq!(q.resolve(&id), Some(true));
    }

    #[test]
    fn verdict_deny_then_sweep_stays_denied() {
        let mut q = super::Queue::default();
        let id = q.request("http.request", Some("evil.com"), Some("POST"));
        // Deny first
        assert!(q.decide(&id, super::Verdict::Deny));
        assert_eq!(q.resolve(&id), Some(false));
        // Sweeping should not change an already-decided verdict
        q.sweep_expired(1_000_000, 60);
        assert_eq!(q.resolve(&id), Some(false));
    }
}
