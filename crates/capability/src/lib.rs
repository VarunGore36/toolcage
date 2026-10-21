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
//! - Tag is HMAC-SHA256 keyed with the host's `Key` over the length-prefixed
//!   canonical (rev_id|parent|rights|domain): a guest that reads a token can
//!   neither mint a sibling nor widen anything without the key. The key never
//!   enters a token or a guest. (v0 used unkeyed SHA256 — anyone could mint;
//!   fixed here. Verification is constant-time via the `hmac` crate.)
//! - allows() re-checks verify_tag(key) first; tampered rights fail closed.
//!   Case: hosts/methods compare case-insensitively, cred names case-sensitively.
//!   An empty rights list grants NOTHING on that axis (all four axes now agree;
//!   v0 made empty `methods` a wildcard, which let attenuate() widen a child
//!   by narrowing methods to [] — found by the property test).
//! - Revocation walks parent_of links: revoke(parent) kills subtree. Links are
//!   tracked in-memory via track(); a restart forgets them — persist the graph
//!   or use hierarchical rev_ids before relying on revoke across restarts.
//! - Expiry 0 means "unbounded" only for roots; children of a bounded parent
//!   must set expiry <= parent (enforced). System clock jumps forward can
//!   prematurely expire; jumps backward extend — enforce monotonic time where
//!   budgets matter.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rights {
    #[serde(default)]
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
    /// HMAC-SHA256 tag (hex) over the chain under the host `Key`.
    pub tag: String,
}

/// Secret MAC key for capability tags. Host-side only: it is never serialized
/// into a token, never logged, never sent to a guest. Tokens minted or
/// attenuated under one key fail verification under any other, so a guest that
/// reads a token cannot mint siblings or widen anything (I3).
#[derive(Clone)]
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([redacted])")
    }
}

impl Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse a 64-char hex key. Errors (never panics) on wrong length or
    /// non-hex input.
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let b = s.as_bytes();
        anyhow::ensure!(
            b.len() == 64 && b.iter().all(|c| c.is_ascii_hexdigit()),
            "key must be 64 hex chars, got {} chars",
            b.len()
        );
        let mut bytes = [0u8; 32];
        for (i, slot) in bytes.iter_mut().enumerate() {
            // Safe to slice: ASCII hexdigits only, even offsets.
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| anyhow::anyhow!("bad key hex"))?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || !b.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..b.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn feed(mac: &mut Hmac<Sha256>, part: &[u8]) {
    // Length prefixes avoid concatenation ambiguity ("ab"+"c" vs "a"+"bc").
    mac.update(&(part.len() as u64).to_le_bytes());
    mac.update(part);
}

/// Unfinalized HMAC over the canonical token body. Length-prefixed fields,
/// keyed with the host secret (I3).
fn mac_for(key: &Key, rev_id: &str, parent: &Option<String>, rights: &Rights) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("hmac accepts keys of any length");
    feed(&mut mac, rev_id.as_bytes());
    feed(&mut mac, parent.clone().unwrap_or_default().as_bytes());
    feed(
        &mut mac,
        &serde_json::to_vec(rights).expect("rights serialize"),
    );
    feed(&mut mac, b"toolcage-cap-v1");
    mac
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
    /// Mint a root token under the host key.
    pub fn root(key: &Key, rev_id: &str, rights: Rights) -> Self {
        let tag = hex_lower(&mac_for(key, rev_id, &None, &rights).finalize().into_bytes());
        Self {
            rev_id: rev_id.into(),
            parent: None,
            rights,
            tag,
        }
    }

    /// Constant-time tag check against the host key. A token minted under any
    /// other key (or hand-edited) fails here and everywhere downstream.
    pub fn verify_tag(&self, key: &Key) -> bool {
        let Some(raw) = hex_bytes(&self.tag) else {
            return false;
        };
        mac_for(key, &self.rev_id, &self.parent, &self.rights)
            .verify_slice(&raw)
            .is_ok()
    }

    /// Attenuate: child rights must be SUBSET of parent. Never widens.
    /// Narrower paths, subset hosts/methods/creds, smaller-or-equal budget,
    /// shorter-or-equal expiry. New rev_id linked to parent.
    /// Parent must verify under the key (fail-closed): no key, no delegation.
    pub fn attenuate(&self, key: &Key, rev_id: &str, narrow: Rights) -> anyhow::Result<Token> {
        anyhow::ensure!(self.verify_tag(key), "parent tag invalid");
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
                anyhow::ensure!(
                    ps.contains(&c.to_ascii_lowercase()),
                    "{what} {c} widens parent"
                );
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
        anyhow::ensure!(
            narrow.budget_bytes <= self.rights.budget_bytes,
            "budget widens parent"
        );
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
        let tag = hex_lower(
            &mac_for(key, &t.rev_id, &t.parent, &t.rights)
                .finalize()
                .into_bytes(),
        );
        Ok(Token { tag, ..t })
    }

    /// Authorize a request against this token (policy checked separately).
    /// Enforces expiry (fail-closed) and normalizes fs paths lexically so
    /// `/workspace/../etc` cannot bypass a `/workspace` prefix grant.
    pub fn allows(
        &self,
        key: &Key,
        fs_path: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        cred: Option<&str>,
    ) -> bool {
        self.allows_at(key, fs_path, host, method, cred, now_secs())
    }

    pub fn allows_at(
        &self,
        key: &Key,
        fs_path: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        cred: Option<&str>,
        now: u64,
    ) -> bool {
        if !self.verify_tag(key) {
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
            if !self
                .rights
                .net_hosts
                .iter()
                .any(|x| x.eq_ignore_ascii_case(h))
            {
                return false;
            }
        }
        if let Some(m) = method {
            // Empty methods = NOTHING granted on this axis (consistent with
            // fs/net/cred below). v0 treated empty as "any method" — a wildcard
            // that let attenuate() narrow `methods` to [] and thereby WIDEN
            // the child (found by the 200-seed property test).
            if !self
                .rights
                .methods
                .iter()
                .any(|x| x.eq_ignore_ascii_case(m))
            {
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
    fn key() -> Key {
        Key::from_bytes([7u8; 32])
    }
    fn other_key() -> Key {
        Key::from_bytes([9u8; 32])
    }
    fn root() -> Token {
        // Expiry is wall-clock seconds: use far-future so allows() (real now) passes.
        Token::root(
            &key(),
            "r0",
            Rights {
                fs_prefixes: vec!["/workspace".into()],
                net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
                methods: vec!["GET".into(), "POST".into()],
                cred_use: vec!["github_token".into()],
                budget_bytes: 1000,
                expires_at: 9_999_999_999,
            },
        )
    }
    #[test]
    fn narrow_ok_widen_fails() {
        let r = root();
        let c = r
            .attenuate(
                &key(),
                "r1",
                Rights {
                    fs_prefixes: vec!["/workspace/a".into()],
                    net_hosts: vec!["github".into()],
                    methods: vec!["GET".into()],
                    cred_use: vec![],
                    budget_bytes: 100,
                    expires_at: 9_999_999_000,
                },
            )
            .unwrap();
        assert!(c.allows(
            &key(),
            Some("/workspace/a/f"),
            Some("github"),
            Some("GET"),
            None
        ));
        assert!(!c.allows(&key(), Some("/workspace/b"), None, None, None));
        // widen attempts
        assert!(r
            .attenuate(
                &key(),
                "r2",
                Rights {
                    fs_prefixes: vec!["/etc".into()],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 1,
                    expires_at: 1
                }
            )
            .is_err());
        assert!(r
            .attenuate(
                &key(),
                "r3",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec!["evil.com".into()],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 1,
                    expires_at: 1
                }
            )
            .is_err());
        assert!(r
            .attenuate(
                &key(),
                "r4",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 99999,
                    expires_at: 1
                }
            )
            .is_err());
        assert!(r
            .attenuate(
                &key(),
                "r5",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec!["github_token".into(), "evil".into()],
                    budget_bytes: 1,
                    expires_at: 1
                }
            )
            .is_err());
    }
    #[test]
    fn forged_token_minted_without_host_key_is_rejected() {
        // Regression for the v0 forgeability hole (unkeyed SHA256 tag): a guest
        // that reads a token can mint a "sibling" under its own key, but the
        // host key rejects it everywhere — verify_tag and allows both fail.
        let r = root();
        let forged = Token::root(
            &other_key(),
            "evil",
            Rights {
                fs_prefixes: vec!["/".into()],
                net_hosts: vec!["evil.com".into()],
                methods: vec!["GET".into(), "POST".into(), "DELETE".into()],
                cred_use: vec!["github_token".into()],
                budget_bytes: u64::MAX,
                expires_at: 9_999_999_999,
            },
        );
        assert!(
            !forged.verify_tag(&key()),
            "forged tag must not verify under the host key"
        );
        assert!(!forged.allows(
            &key(),
            Some("/"),
            Some("evil.com"),
            Some("DELETE"),
            Some("github_token")
        ));
        // A real token under the host key still verifies; the forged one does
        // not, even though its own tag is internally consistent.
        assert!(r.verify_tag(&key()));
        assert!(forged.verify_tag(&other_key()));
        // Delegation from a forged parent is refused too (fail-closed).
        assert!(forged
            .attenuate(
                &key(),
                "c",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 1,
                    expires_at: 1
                }
            )
            .is_err());
    }
    #[test]
    fn revoke_parent_kills_children() {
        let r = root();
        let c = r
            .attenuate(
                &key(),
                "r1",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 1,
                    expires_at: 1,
                },
            )
            .unwrap();
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
        assert!(!r.allows(&key(), None, None, None, None) || !r.verify_tag(&key()));
        assert!(!r.verify_tag(&key()));
    }
    #[test]
    fn wrong_key_rejected_and_key_hex_roundtrips() {
        let r = root();
        assert!(!r.verify_tag(&other_key()));
        assert!(!r.allows(&other_key(), None, Some("github"), None, None));
        let k = Key::from_hex(&key().to_hex()).unwrap();
        assert!(r.verify_tag(&k));
        // Malformed keys are errors, not panics.
        assert!(Key::from_hex("beef").is_err());
        assert!(Key::from_hex(&"z".repeat(64)).is_err());
    }
    #[test]
    fn expiry_enforced_and_traversal_denied() {
        let r = root(); // expires_at 9_999_999_999
        assert!(r.allows_at(
            &key(),
            None,
            Some("github"),
            Some("GET"),
            None,
            9_999_999_999
        ));
        assert!(!r.allows_at(
            &key(),
            None,
            Some("github"),
            Some("GET"),
            None,
            10_000_000_000
        ));
        assert!(!r.allows_at(&key(), None, Some("github"), Some("GET"), None, u64::MAX));
        // Traversal outside granted prefix must deny even though string prefix matches.
        // Use allows_at with valid time to isolate the path check from expiry.
        assert!(!r.allows_at(
            &key(),
            Some("/workspace/../etc/passwd"),
            None,
            None,
            None,
            1_000_000_000
        ));
        assert!(r.allows_at(
            &key(),
            Some("/workspace/a/../a/f"),
            None,
            None,
            None,
            1_000_000_000
        ));
        // Attenuation cannot smuggle traversal prefix.
        assert!(r
            .attenuate(
                &key(),
                "rx",
                Rights {
                    fs_prefixes: vec!["/workspace/../etc".into()],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 1,
                    expires_at: 1,
                }
            )
            .is_err());
    }
}
