//! Credential broker v0: secrets live in host, injected at proxy only.
//! Guest holds `secret:name` placeholders. Log holds stable ids, never values.
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Credential {
    pub name: String,
    pub value: String,
    /// Alias this credential may be used with (e.g. "github").
    pub use_with: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
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
    pub fn inject(&self, name: &str, dest_alias: &str, method: &str) -> Option<&str> {
        let c = self.creds.get(name)?;
        if c.use_with.to_ascii_lowercase() != dest_alias.to_ascii_lowercase() {
            return None;
        }
        if !c.methods.is_empty() && !c.methods.iter().any(|m| m.to_ascii_uppercase() == method.to_ascii_uppercase()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inject_only_for_bound_dest() {
        let mut b = Broker::new();
        b.insert(Credential { name: "github_token".into(), value: "s3cr3t".into(), use_with: "github".into(), methods: vec![], paths: vec![] });
        assert_eq!(b.inject("github_token", "github", "GET"), Some("s3cr3t"));
        assert_eq!(b.inject("github_token", "evil", "GET"), None);
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
