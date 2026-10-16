//! Egress proxy v0: allowlisted tunnels + service aliases, no guest DNS.
//! Guest calls `alias.internal` or allowlisted host; proxy resolves and decides.
//! Raw sockets / ICMP / IPv6 / direct metadata have no path — only this API.
//!
//! REVIEW:
//! - Guest never dials: decide() returns an UPSTREAM the host dials; the guest
//!   string is only a policy key. Adding a real dialer? Keep it here, never in
//!   guest-reachable code, and resolve DNS here (guest DNS = exfil channel).
//! - Alias mapping is policy-checked on the OPERATOR alias ("github"), not the
//!   guest string ("github.internal"). New aliases must map explicitly; a
//!   fallback that dials the guest string verbatim would be an open proxy.
//! - Method/path enforced per rule; empty methods/paths in a rule means "no
//!   constraint on that axis" — narrow rules instead of relying on callers.
//! - Budgets are in-memory HashMaps, not persisted or shared across processes.
//!   Restart resets them; multi-proxy deployments need a shared counter or a
//!   single proxy. Over-budget returns false (deny), never allows + logs.
//! - Metadata deny comes from policy::decide; proxy must not add a second,
//!   weaker check that could disagree. Single choke point: all guest net flows
//!   through decide(), including future UDP/WS tunnels.
use std::collections::HashMap;
use toolcage_policy::{Policy, Request};

/// alias -> real upstream host. Guest never learns the real hostname/IP.
pub fn alias_map() -> HashMap<String, String> {
    HashMap::from([
        ("github".to_string(), "api.github.com".to_string()),
        ("github.internal".to_string(), "api.github.com".to_string()),
        ("registry".to_string(), "registry.npmjs.org".to_string()),
    ])
}

#[derive(Debug, Clone)]
pub struct ProxyDecision {
    pub allow: bool,
    pub rule_ids: Vec<String>,
    pub reason: String,
    /// Upstream host the proxy will dial (guest never dials directly).
    pub upstream: Option<String>,
}

/// Single choke point for all guest network. Policy + alias + metadata forbid.
pub fn decide(policy: &Policy, alias_or_host: &str, method: &str, path: &str) -> ProxyDecision {
    let aliases = alias_map();
    let key = alias_or_host.to_ascii_lowercase();
    // Resolve alias first: guest uses alias, proxy maps to real host for upstream,
    // but policy is checked against the alias the operator wrote.
    let policy_host = if aliases.contains_key(&key) {
        // Find the operator-facing alias name (e.g. "github").
        // If guest used "github.internal", check policy for "github".
        if policy.net.hosts.iter().any(|h| {
            h.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("github"))
        }) && key.starts_with("github")
        {
            "github".to_string()
        } else {
            key.clone()
        }
    } else {
        key.clone()
    };
    let req = Request {
        action: "http.request".into(),
        host: Some(policy_host),
        method: Some(method.to_string()),
        path: Some(path.to_string()),
        fs_path: None,
        argv: None,
    };
    let d = toolcage_policy::decide(policy, &req);
    if !d.allow {
        return ProxyDecision { allow: false, rule_ids: d.rule_ids, reason: d.reason, upstream: None };
    }
    let upstream = aliases.get(&key).cloned().unwrap_or(key);
    ProxyDecision { allow: true, rule_ids: d.rule_ids, reason: "proxy allow".into(), upstream: Some(upstream) }
}

/// Per-destination budgets (M2 damage bound). Returns false when over budget.
#[derive(Debug, Default)]
pub struct Budgets {
    pub bytes: HashMap<String, u64>,
    pub requests: HashMap<String, u64>,
}

impl Budgets {
    pub fn check(&mut self, dest: &str, bytes: u64, max_bytes: u64, max_req: u64) -> bool {
        let b = self.bytes.entry(dest.to_string()).or_insert(0);
        let r = self.requests.entry(dest.to_string()).or_insert(0);
        if *r >= max_req || *b + bytes > max_bytes {
            return false;
        }
        *b += bytes;
        *r += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Policy {
        toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
    }
    #[test]
    fn alias_resolves_and_allows() {
        let d = decide(&sample(), "github.internal", "GET", "/repos/acme/app/issues/1");
        assert!(d.allow);
        assert_eq!(d.upstream.as_deref(), Some("api.github.com"));
    }
    #[test]
    fn metadata_has_no_path() {
        for h in ["169.254.169.254", "metadata.google.internal", "instance-data"] {
            let d = decide(&sample(), h, "GET", "/");
            assert!(!d.allow, "{h} must be denied");
        }
    }
    #[test]
    fn raw_unknown_host_denied() {
        let d = decide(&sample(), "evil.example.com", "GET", "/");
        assert!(!d.allow);
    }
    #[test]
    fn budgets_bound_damage() {
        let mut b = Budgets::default();
        assert!(b.check("github", 100, 150, 2));
        assert!(!b.check("github", 100, 150, 2)); // over bytes
    }
}
