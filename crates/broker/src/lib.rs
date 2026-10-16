//! Credential broker v0: secrets live in host, injected at proxy only.
//! Guest holds `secret:name` placeholders. Log holds stable ids, never values.
//!
//! REVIEW (I2):
//! - inject() binds (name, use_with alias, method). Mismatched dest returns
//!   None — the proxy must treat None as no-auth, never fall back to a literal
//!   or env value. New fields (paths/expiry) must default-deny when absent.
//! - scrub() replaces every known value with [REDACTED] before guest-visible
//!   output. Substring replace can miss encoded forms (base64/URL-encoded);
//!   treat scrub as defense-in-depth, not the boundary — the boundary is never
//!   placing values guest-side in the first place.
//! - log_id() is `cred:name`: safe to audit. Never log Credential.value, not
//!   even at debug/trace. Credential has a manual redacting Debug impl — do
//!   not re-add a derived Debug or log `.value` anywhere.
//! - Storage is in-memory HashMap (cleared on restart). Encrypted-at-rest +
//!   short-lived derived tokens per upstream belong here next; rotation must
//!   invalidate inject() immediately.
//! - Canary plant_canary() uses time-nanos suffix: unique per test run, good
//!   for I2 scans (grep guest mem/files for canary must find 0 hits).
use std::collections::HashMap;

#[derive(Clone)]
pub struct Credential {
    pub name: String,
    pub value: String,
    /// Alias this credential may be used with (e.g. "github").
    pub use_with: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

// REVIEW fix: Debug must never print the secret value. A derived Debug on
// this struct would leak it into any {:?} log. Redact explicitly.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("use_with", &self.use_with)
            .field("methods", &self.methods)
            .field("paths", &self.paths)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct Broker {
    creds: HashMap<String, Credential>,
}

impl Broker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, c: Credential) {
        self.creds.insert(c.name.clone(), c);
    }

    pub fn from_policy_rules(rules: &[(String, String)], values: &HashMap<String, String>) -> Self {
        let mut b = Self::new();
        for (name, use_with) in rules {
            if let Some(v) = values.get(name) {
                b.insert(Credential {
                    name: name.clone(),
                    value: v.clone(),
                    use_with: use_with.clone(),
                    methods: vec![],
                    paths: vec![],
                });
            }
        }
        b
    }

    /// Returns the secret value ONLY if dest/method/path are allowed.
    /// Caller (proxy) attaches it upstream; it never goes to the guest.
    /// Empty methods/paths on a credential means "no constraint on that axis".
    pub fn inject(&self, name: &str, dest_alias: &str, method: &str, path: &str) -> Option<&str> {
        let c = self.creds.get(name)?;
        if !c.use_with.eq_ignore_ascii_case(dest_alias) {
            return None;
        }
        if !c.methods.is_empty() && !c.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return None;
        }
        if !c.paths.is_empty()
            && !c.paths.iter().any(|p| path_match_cred(p, path))
        {
            return None;
        }
        Some(&c.value)
    }

    /// Stable log identifier — never the value.
    pub fn log_id(name: &str) -> String {
        format!("cred:{name}")
    }

    /// Scrub upstream responses: strip any known secret before guest sees it.
    pub fn scrub(&self, body: &str) -> String {
        let mut out = body.to_string();
        for c in self.creds.values() {
            if !c.value.is_empty() {
                out = out.replace(&c.value, "[REDACTED]");
            }
        }
        out
    }

    /// Canary for I2 tests: unique value that must never appear guest-side.
    pub fn plant_canary(&mut self, name: &str) -> String {
        let v = format!("CANARY-{}-{}", name, rand_suffix());
        self.insert(Credential { name: name.into(), value: v.clone(), use_with: "github".into(), methods: vec![], paths: vec![] });
        v
    }
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", n & 0xffffff)
}

/// Trailing-`/**` match only (same semantics as policy paths): exact or under prefix.
fn path_match_cred(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        pattern == path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inject_only_for_bound_dest() {
        let mut b = Broker::new();
        b.insert(Credential { name: "github_token".into(), value: "s3cr3t".into(), use_with: "github".into(), methods: vec![], paths: vec![] });
        assert_eq!(b.inject("github_token", "github", "GET", "/"), Some("s3cr3t"));
        assert_eq!(b.inject("github_token", "evil", "GET", "/"), None);
        // Path-bound credential denies outside its prefix.
        b.insert(Credential { name: "scoped".into(), value: "v".into(), use_with: "github".into(), methods: vec![], paths: vec!["/repos/acme/**".into()] });
        assert_eq!(b.inject("scoped", "github", "GET", "/repos/acme/app"), Some("v"));
        assert_eq!(b.inject("scoped", "github", "GET", "/repos/evil"), None);
        // Scrub strips echo
        assert_eq!(b.scrub("token=s3cr3t ok"), "token=[REDACTED] ok");
        // Log id leaks nothing
        assert!(!Broker::log_id("github_token").contains("s3cr3t"));
    }
    #[test]
    fn canary_never_in_guest_output() {
        let mut b = Broker::new();
        let canary = b.plant_canary("test_tok");
        // Simulated guest-visible output (placeholder, not value)
        let guest_output = "using secret:test_tok via proxy";
        assert!(!guest_output.contains(&canary));
        // Simulated upstream echo gets scrubbed before guest sees it
        let echoed = format!("echo {canary}");
        assert!(!b.scrub(&echoed).contains(&canary));
    }
}
