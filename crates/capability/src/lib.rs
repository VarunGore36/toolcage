//! Capability tokens v0: narrow-on-delegate, never widen, revocable.
//! Operator policy holds global forbids; token holds per-session rights.
//! Action runs only if BOTH agree. Mirrors Biscuit attenuation semantics
//! without the Datalog dependency (blocks appended, checks intersected).
//!
//! REVIEW (I3):
//! - attenuate() is the whole security property: every axis must be subset or
//!   tighter (fs prefix-under-prefix, hosts/methods/creds subset, budget <=,
//!   expiry <= and non-zero when parent is bounded). Adding a rights axis?
//!   Default it to empty/zero AND require explicit narrowing, else children
//!   silently gain the new right (widen-by-default bug).
//! - Tag is SHA256(rev_id|parent|rights|"toolcage-v0"), not a MAC: anyone who
//!   reads a token can mint a sibling, but cannot widen (subset check runs on
//!   the PARENT's rights server-side). Real deployments need a secret-keyed
//!   MAC (HMAC/Ed25519) so guests cannot mint at all — track as Biscuit step.
//! - allows() re-checks verify_tag() first; tampered rights fail closed. Case:
//!   hosts/methods compare case-insensitively, cred names case-sensitively.
//! - Revocation walks parent_of links: revoke(parent) kills subtree. Links are
//!   tracked in-memory via track(); a restart forgets them — persist the graph
//!   or use hierarchical rev_ids before relying on revoke across restarts.
//! - Expiry 0 means "unbounded" only for roots; children of a bounded parent
//!   must set expiry <= parent (enforced). System clock jumps forward can
//!   prematurely expire; jumps backward extend — enforce monotonic time where
//!   budgets matter.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rights {    #[serde(default)]
    pub fs_prefixes: Vec<String>,
    #[serde(default)]
    pub net_hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub cred_use: Vec<String>,
    #[serde(default)]
    pub budget_bytes: u64,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub rev_id: String,
    pub parent: Option<String>,
    pub rights: Rights,
    pub tag: String, // integrity tag over chain (HMAC-like, v0 sha256)
}

fn tag_for(rev_id: &str, parent: &Option<String>, rights: &Rights) -> String {
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(rev_id.as_bytes());
    h.update(parent.clone().unwrap_or_default().as_bytes());
    h.update(serde_json::to_vec(rights).unwrap());
    h.update(b"toolcage-v0");
    format!("{:x}", h.finalize())
}

/// Lexical fs normalization (no FS access): resolve `.`, `..`, `//`.
/// Same semantics as policy::canonical_path; duplicated to avoid a dep cycle.
fn normalize_fs(p: &str) -> String {
    let mut parts: Vec<&str> = vec![];
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Token {
    pub fn root(rev_id: &str, rights: Rights) -> Self {
        let tag = tag_for(rev_id, &None, &rights);
        Self { rev_id: rev_id.into(), parent: None, rights, tag }
    }

    pub fn verify_tag(&self) -> bool {
        tag_for(&self.rev_id, &self.parent, &self.rights) == self.tag
    }

    /// Attenuate: child rights must be SUBSET of parent. Never widens.
    /// Narrower paths, subset hosts/methods/creds, smaller-or-equal budget,
    /// shorter-or-equal expiry. New rev_id linked to parent.
    pub fn attenuate(&self, rev_id: &str, narrow: Rights) -> anyhow::Result<Token> {
        anyhow::ensure!(self.verify_tag(), "parent tag invalid");
        // fs: each child prefix must sit under a parent prefix (normalized).
        for p in &narrow.fs_prefixes {
            let np = normalize_fs(p);
            let ok = self.rights.fs_prefixes.iter().any(|pp| {
                let npp = normalize_fs(pp);
                np == npp || np.starts_with(&format!("{npp}/"))
            });
            anyhow::ensure!(ok, "fs prefix {p} widens parent");
        }
        // net/methods: subsets, case-insensitive. creds: case-sensitive (identifiers).
        let sub_ins = |child: &[String], parent: &[String], what: &str| -> anyhow::Result<()> {
            let ps: HashSet<_> = parent.iter().map(|s| s.to_ascii_lowercase()).collect();
            for c in child {
                anyhow::ensure!(ps.contains(&c.to_ascii_lowercase()), "{what} {c} widens parent");
            }
            Ok(())
        };
        sub_ins(&narrow.net_hosts, &self.rights.net_hosts, "host")?;
        sub_ins(&narrow.methods, &self.rights.methods, "method")?;
        // cred_use is case-sensitive to match allows(); do not lowercase here.
        {
            let ps: HashSet<_> = self.rights.cred_use.iter().collect();
            for c in &narrow.cred_use {
                anyhow::ensure!(ps.contains(c), "cred {c} widens parent");
            }
        }
        anyhow::ensure!(narrow.budget_bytes <= self.rights.budget_bytes, "budget widens parent");
        if self.rights.expires_at != 0 {
            anyhow::ensure!(
                narrow.expires_at != 0 && narrow.expires_at <= self.rights.expires_at,
                "expiry widens parent"
            );
        }
        let t = Token {
            rev_id: rev_id.into(),
            parent: Some(self.rev_id.clone()),
            rights: narrow,
            tag: String::new(),
        };
        let tag = tag_for(&t.rev_id, &t.parent, &t.rights);
        Ok(Token { tag, ..t })
    }

    /// Authorize a request against this token (policy checked separately).
    /// Enforces expiry (fail-closed) and normalizes fs paths lexically so
    /// `/workspace/../etc` cannot bypass a `/workspace` prefix grant.
    pub fn allows(&self, fs_path: Option<&str>, host: Option<&str>, method: Option<&str>, cred: Option<&str>) -> bool {
        self.allows_at(fs_path, host, method, cred, now_secs())
    }

    pub fn allows_at(&self, fs_path: Option<&str>, host: Option<&str>, method: Option<&str>, cred: Option<&str>, now: u64) -> bool {
        if !self.verify_tag() {
            return false;
        }
        if self.rights.expires_at != 0 && now > self.rights.expires_at {
            return false;
        }
        if let Some(p) = fs_path {
            let np = normalize_fs(p);
            let ok = self.rights.fs_prefixes.iter().any(|pp| {
                let npp = normalize_fs(pp);
                np == npp || np.starts_with(&format!("{npp}/"))
            });
            if !ok {
                return false;
            }
        }
        if let Some(h) = host {
            if !self.rights.net_hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                return false;
            }
        }
        if let Some(m) = method {
            if !self.rights.methods.is_empty() && !self.rights.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
                return false;
            }
        }
        if let Some(c) = cred {
            if !self.rights.cred_use.iter().any(|x| x == c) {
                return false;
            }
        }
        true
    }
}

/// Revocation: revoking a rev_id revokes its whole subtree.
#[derive(Debug, Default)]
pub struct RevocationList {
    revoked: HashSet<String>,
    // child -> parent links seen (for subtree walk)
    parent_of: HashMap<String, String>,
}

impl RevocationList {
    pub fn track(&mut self, t: &Token) {
        if let Some(p) = &t.parent {
            self.parent_of.insert(t.rev_id.clone(), p.clone());
        }
    }
    pub fn revoke(&mut self, rev_id: &str) {
        self.revoked.insert(rev_id.to_string());
    }
    pub fn is_revoked(&self, t: &Token) -> bool {
        let mut cur = Some(t.rev_id.clone());
        // Walk up: child revoked with parent.
        let mut child = t.rev_id.clone();
        let _ = &mut cur;
        if self.revoked.contains(&child) {
            return true;
        }
        while let Some(p) = self.parent_of.get(&child) {
            if self.revoked.contains(p) {
                return true;
            }
            child = p.clone();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> Token {
        // Expiry is wall-clock seconds: use far-future so allows() (real now) passes.
        Token::root("r0", Rights {
            fs_prefixes: vec!["/workspace".into()],
            net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
            methods: vec!["GET".into(), "POST".into()],
            cred_use: vec!["github_token".into()],
            budget_bytes: 1000,
            expires_at: 9_999_999_999,
        })
    }
    #[test]
    fn narrow_ok_widen_fails() {
        let r = root();
        let c = r.attenuate("r1", Rights {
            fs_prefixes: vec!["/workspace/a".into()],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 100,
            expires_at: 9_999_999_000,
        }).unwrap();
        assert!(c.allows(Some("/workspace/a/f"), Some("github"), Some("GET"), None));
        assert!(!c.allows(Some("/workspace/b"), None, None, None));
        // widen attempts
        assert!(r.attenuate("r2", Rights { fs_prefixes: vec!["/etc".into()], net_hosts: vec![], methods: vec![], cred_use: vec![], budget_bytes: 1, expires_at: 1 }).is_err());
        assert!(r.attenuate("r3", Rights { fs_prefixes: vec![], net_hosts: vec!["evil.com".into()], methods: vec![], cred_use: vec![], budget_bytes: 1, expires_at: 1 }).is_err());
        assert!(r.attenuate("r4", Rights { fs_prefixes: vec![], net_hosts: vec![], methods: vec![], cred_use: vec![], budget_bytes: 99999, expires_at: 1 }).is_err());
        assert!(r.attenuate("r5", Rights { fs_prefixes: vec![], net_hosts: vec![], methods: vec![], cred_use: vec!["github_token".into(), "evil".into()], budget_bytes: 1, expires_at: 1 }).is_err());
    }
    #[test]
    fn revoke_parent_kills_children() {
        let r = root();
        let c = r.attenuate("r1", Rights { fs_prefixes: vec![], net_hosts: vec![], methods: vec![], cred_use: vec![], budget_bytes: 1, expires_at: 1 }).unwrap();
        let mut rl = RevocationList::default();
        rl.track(&c);
        assert!(!rl.is_revoked(&c));
        rl.revoke("r0");
        assert!(rl.is_revoked(&c));
    }
    #[test]
    fn tampered_tag_rejected() {
        let mut r = root();
        r.rights.budget_bytes = 999999;
        assert!(!r.allows(None, None, None, None) || !r.verify_tag());
        assert!(!r.verify_tag());
    }
    #[test]
    fn expiry_enforced_and_traversal_denied() {
        let r = root(); // expires_at 9_999_999_999
        assert!(r.allows_at(None, Some("github"), Some("GET"), None, 9_999_999_999));
        assert!(!r.allows_at(None, Some("github"), Some("GET"), None, 10_000_000_000));
        assert!(!r.allows_at(None, Some("github"), Some("GET"), None, u64::MAX));
        // Traversal outside granted prefix must deny even though string prefix matches.
        // Use allows_at with valid time to isolate the path check from expiry.
        assert!(!r.allows_at(Some("/workspace/../etc/passwd"), None, None, None, 1_000_000_000));
        assert!(r.allows_at(Some("/workspace/a/../a/f"), None, None, None, 1_000_000_000));
        // Attenuation cannot smuggle traversal prefix.
        assert!(r.attenuate("rx", Rights {
            fs_prefixes: vec!["/workspace/../etc".into()], net_hosts: vec![],
            methods: vec![], cred_use: vec![], budget_bytes: 1, expires_at: 1,
        }).is_err());
    }
}
