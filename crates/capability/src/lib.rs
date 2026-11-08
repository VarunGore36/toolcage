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
//!   tracked via track() and persisted alongside revoked IDs in save()/load()
//!   (plus hierarchical `/` prefix matching and signed ancestor lineage) so
//!   subtree revocation survives restarts.
//! - Expiry 0 means "unbounded" only for roots; children of a bounded parent
//!   must set expiry <= parent (enforced). System clock jumps forward can
//!   prematurely expire; jumps backward extend — enforce monotonic time where
//!   budgets matter.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

/// Delegation depth bound. The ancestor chain is carried (and signed) in
/// every token; a bound keeps a token's size linear in a sane number of hops.
const MAX_CHAIN_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub rev_id: String,
    pub parent: Option<String>,
    /// Signed lineage, root first, immediate parent last. The token only used
    /// to carry its immediate parent, so a 2-hop chain whose INTERMEDIATE was
    /// never track()ed (always true when just the leaf is presented) walked
    /// off the end of `parent_of` and survived its root's revocation.
    #[serde(default)]
    pub ancestors: Vec<String>,
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

/// A rev_id names a token in the audit trail and the revocation list: keep it
/// to the portable identifier charset (the guest-agent id rule) and non-empty,
/// so it cannot smuggle control characters into logs or collide with the
/// empty key of the revocation map.
pub fn validate_rev_id(rev: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!rev.is_empty() && rev.len() <= 64, "rev_id bounds");
    anyhow::ensure!(
        !rev.starts_with('/')
            && !rev.ends_with('/')
            && !rev.contains("//")
            && rev.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-' || b == b'/'
            })
            && rev.split('/').all(|seg| seg != "." && seg != ".."),
        "bad rev_id charset"
    );
    Ok(())
}

fn feed(mac: &mut Hmac<Sha256>, part: &[u8]) {
    // Length prefixes avoid concatenation ambiguity ("ab"+"c" vs "a"+"bc").
    mac.update(&(part.len() as u64).to_le_bytes());
    mac.update(part);
}

/// Unfinalized HMAC over the canonical token body. Length-prefixed fields,
/// keyed with the host secret (I3).
fn mac_for(
    key: &Key,
    rev_id: &str,
    parent: &Option<String>,
    ancestors: &[String],
    rights: &Rights,
) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("hmac accepts keys of any length");
    feed(&mut mac, rev_id.as_bytes());
    // Distinguish None from Some(...). They used to feed identically — both
    // empty via unwrap_or_default — so a root (parent: None) and a
    // hand-crafted Some("") token shared a tag: the chain SHAPE was forgeable
    // without the key. The discriminant byte makes the two distinct.
    match parent {
        None => feed(&mut mac, &[0u8]),
        Some(p) => {
            feed(&mut mac, &[1u8]);
            feed(&mut mac, p.as_bytes());
        }
    }
    // The lineage is signed with the rest: it must not be strippable or
    // extendable, or a holder could hide a revoked ancestor.
    feed(&mut mac, &(ancestors.len() as u64).to_le_bytes());
    for anc in ancestors {
        feed(&mut mac, anc.as_bytes());
    }
    feed(
        &mut mac,
        &serde_json::to_vec(rights).expect("rights serialize"),
    );
    feed(&mut mac, b"toolcage-cap-v1");
    mac
}

/// Lexical fs normalization (no FS access): resolve `.`, `..`, `//`.
/// Same semantics as policy::canonical_path; duplicated to avoid a dep cycle.
/// True when the normalized prefix `npp` covers the normalized path `np`.
///
/// The root prefix covers everything. The obvious `np.starts_with(&format!("{npp}/"))`
/// breaks for it — that builds "//", which matches no normalized path — so a
/// token granted `fs_prefixes: ["/"]` allowed nothing and could not even be
/// narrowed to a subpath.
fn fs_prefix_covers(npp: &str, np: &str) -> bool {
    npp == "/" || np == npp || np.starts_with(&format!("{npp}/"))
}

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
    /// Mint a root token under the host key. The rev_id is validated: it names
    /// the token in audit and revocation.
    pub fn root(key: &Key, rev_id: &str, rights: Rights) -> anyhow::Result<Self> {
        validate_rev_id(rev_id)?;
        let ancestors = Vec::new();
        let tag = hex_lower(
            &mac_for(key, rev_id, &None, &ancestors, &rights)
                .finalize()
                .into_bytes(),
        );
        Ok(Self {
            rev_id: rev_id.into(),
            parent: None,
            ancestors,
            rights,
            tag,
        })
    }

    /// Constant-time tag check against the host key. A token minted under any
    /// other key (or hand-edited) fails here and everywhere downstream.
    pub fn verify_tag(&self, key: &Key) -> bool {
        // The lineage is attacker-controlled JSON: bound it before the MAC
        // sees it (an oversized chain is a memory amplifier; garbage ids are
        // not something any signer would have produced).
        if self.ancestors.len() > MAX_CHAIN_DEPTH
            || self.ancestors.iter().any(|a| validate_rev_id(a).is_err())
        {
            return false;
        }
        let Some(raw) = hex_bytes(&self.tag) else {
            return false;
        };
        mac_for(
            key,
            &self.rev_id,
            &self.parent,
            &self.ancestors,
            &self.rights,
        )
        .verify_slice(&raw)
        .is_ok()
    }

    /// Attenuate: child rights must be SUBSET of parent. Never widens.
    /// Narrower paths, subset hosts/methods/creds, smaller-or-equal budget,
    /// shorter-or-equal expiry. New rev_id linked to parent.
    /// Parent must verify under the key (fail-closed): no key, no delegation.
    pub fn attenuate(&self, key: &Key, rev_id: &str, narrow: Rights) -> anyhow::Result<Token> {
        validate_rev_id(rev_id)?;
        anyhow::ensure!(self.verify_tag(key), "parent tag invalid");
        anyhow::ensure!(
            self.ancestors.len() < MAX_CHAIN_DEPTH,
            "delegation depth exceeds {MAX_CHAIN_DEPTH}"
        );
        // fs: each child prefix must sit under a parent prefix (normalized).
        for p in &narrow.fs_prefixes {
            let np = normalize_fs(p);
            let ok = self
                .rights
                .fs_prefixes
                .iter()
                .any(|pp| fs_prefix_covers(&normalize_fs(pp), &np));
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
        // 0 = no token-level budget (like expires_at = 0 = no expiry), so a
        // bounded parent must not delegate an unbounded child.
        if self.rights.budget_bytes != 0 {
            anyhow::ensure!(narrow.budget_bytes != 0, "budget widens parent");
        }
        if self.rights.expires_at != 0 {
            anyhow::ensure!(
                narrow.expires_at != 0 && narrow.expires_at <= self.rights.expires_at,
                "expiry widens parent"
            );
        }
        let mut ancestors = self.ancestors.clone();
        ancestors.push(self.rev_id.clone());
        let t = Token {
            rev_id: rev_id.into(),
            parent: Some(self.rev_id.clone()),
            ancestors,
            rights: narrow,
            tag: String::new(),
        };
        let tag = hex_lower(
            &mac_for(key, &t.rev_id, &t.parent, &t.ancestors, &t.rights)
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
            let ok = self
                .rights
                .fs_prefixes
                .iter()
                .any(|pp| fs_prefix_covers(&normalize_fs(pp), &np));
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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    revoked: HashSet<String>,
    // child -> parent links seen (persisted alongside `revoked` so subtree
    // walks survive process restarts).
    #[serde(default)]
    parent_of: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PersistedRevocation {
    Graph {
        revoked: HashSet<String>,
        #[serde(default)]
        parent_of: HashMap<String, String>,
    },
    LegacySet(HashSet<String>),
}

impl RevocationList {
    /// Save the revoked ids and tracked parent links to a JSON file for later
    /// use with --revocation-file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a revocation list previously written by save(). Accepts both the
    /// object format (`{revoked, parent_of}`) and legacy bare-array files.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        match serde_json::from_str::<PersistedRevocation>(&data)? {
            PersistedRevocation::Graph { revoked, parent_of } => Ok(Self { revoked, parent_of }),
            PersistedRevocation::LegacySet(revoked) => Ok(Self {
                revoked,
                parent_of: HashMap::new(),
            }),
        }
    }

    /// Merge another revocation list (revoked ids + parent links) into `self`.
    pub fn merge(&mut self, other: Self) {
        self.revoked.extend(other.revoked);
        self.parent_of.extend(other.parent_of);
    }
}

impl RevocationList {
    pub fn track(&mut self, t: &Token) {
        if let Some(p) = &t.parent {
            self.parent_of.insert(t.rev_id.clone(), p.clone());
        }
        for pair in t.ancestors.windows(2) {
            self.parent_of.insert(pair[1].clone(), pair[0].clone());
        }
    }
    pub fn revoke(&mut self, rev_id: &str) {
        self.revoked.insert(rev_id.to_string());
    }

    // Hierarchical `/` prefix match: revoking "org/team-a" revokes
    // "org/team-a/sess-1" even without explicit link tracking.
    #[inline]
    fn has_revoked_prefix(&self, id: &str) -> bool {
        for (idx, b) in id.bytes().enumerate() {
            if b == b'/' && idx > 0 && self.revoked.contains(&id[..idx]) {
                return true;
            }
        }
        false
    }

    pub fn is_revoked(&self, t: &Token) -> bool {
        if self.revoked.contains(t.rev_id.as_str()) || self.has_revoked_prefix(&t.rev_id) {
            return true;
        }
        // The signed lineage covers every hop regardless of what was
        // track()ed: revoking any ancestor revokes the whole subtree, which
        // is the README's claim ("including ones that were never tracked
        // explicitly").
        if t.ancestors
            .iter()
            .any(|a| self.revoked.contains(a.as_str()) || self.has_revoked_prefix(a))
        {
            return true;
        }
        // Belt and braces: walk tracked links too (the token's own parent
        // first), for tokens whose lineage predates this field.
        //
        // A seen set terminates the walk: track() records links from
        // UNVERIFIED input (it never checks the tag), so a hostile pair
        // a→b, b→a could make the walk spin forever.
        let mut seen: HashSet<&str> = HashSet::new();
        seen.insert(t.rev_id.as_str());
        let mut next = t.parent.as_deref();
        while let Some(p) = next {
            if !seen.insert(p) {
                break; // cycle: stop, don't loop forever
            }
            if self.revoked.contains(p) || self.has_revoked_prefix(p) {
                return true;
            }
            next = self.parent_of.get(p).map(String::as_str);
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
        .unwrap()
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
        )
        .unwrap();
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
    fn revoke_parent_kills_untracked_children() {
        // The subtree must hold even for a descendant that was never track()ed:
        // the old walk used only parent_of (tracked links), so revoking a
        // parent missed any child presented without a tracked link — the
        // attacker's move is simply to not track.
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
        // NOTE: no rl.track(&c) — the child is presented cold.
        assert!(!rl.is_revoked(&c));
        rl.revoke("r0");
        assert!(
            rl.is_revoked(&c),
            "revoking the parent must revoke an untracked child"
        );
    }

    #[test]
    fn revoke_root_kills_untracked_multi_hop_descendant() {
        // VULN-01 reproduction: README says "revoking a rev_id kills every
        // token delegated from it, including ones that were never tracked
        // explicitly". A 2-hop chain presented cold (the mcp paths only ever
        // see the LEAF token) must die when the root is revoked.
        let k = key();
        let root = root();
        let child = root.attenuate(&k, "r1", root.rights.clone()).unwrap();
        let grandchild = child.attenuate(&k, "r2", child.rights.clone()).unwrap();
        let mut rl = RevocationList::default();
        // Nothing tracked — exactly the fresh-process case.
        rl.revoke("r0");
        assert!(
            rl.is_revoked(&grandchild),
            "revoking r0 must revoke the untracked 2-hop grandchild r2"
        );
    }

    #[test]
    fn ancestor_lineage_is_signed_and_cannot_be_stripped() {
        // The lineage only helps if a holder cannot edit it: stripping (or
        // padding) ancestors would hide a revoked root from is_revoked. It is
        // covered by the tag, so any edit fails verification first.
        let k = key();
        let root = root();
        let child = root.attenuate(&k, "r1", root.rights.clone()).unwrap();
        let grandchild = child.attenuate(&k, "r2", child.rights.clone()).unwrap();
        assert_eq!(
            grandchild.ancestors,
            vec!["r0".to_string(), "r1".to_string()],
            "lineage is root-first, immediate parent last"
        );
        // Strip the lineage.
        let mut stripped = grandchild.clone();
        stripped.ancestors.clear();
        assert!(!stripped.verify_tag(&key()), "stripped lineage must fail");
        // Hide just the revoked root.
        let mut hidden = grandchild.clone();
        hidden.ancestors.remove(0);
        assert!(!hidden.verify_tag(&key()), "hidden ancestor must fail");
        // Pad with an unrelated ancestor.
        let mut padded = grandchild.clone();
        padded.ancestors.push("r9".into());
        assert!(!padded.verify_tag(&key()), "padded lineage must fail");
        // A garbage id in the chain is refused before the MAC even runs.
        let mut garbage = grandchild.clone();
        garbage.ancestors = vec!["a b".into()];
        assert!(!garbage.verify_tag(&key()));
        // The intact token is still good.
        assert!(grandchild.verify_tag(&key()));
    }

    #[test]
    fn revoke_walk_terminates_on_a_cycle() {
        // track() records links from UNVERIFIED input (it never checks the
        // tag), so a hostile pair a→b, b→a can be planted. is_revoked must
        // terminate, not spin forever on the cycle.
        let mk = |rev_id: &str, parent: &str| Token {
            rev_id: rev_id.into(),
            parent: Some(parent.into()),
            ancestors: Vec::new(),
            rights: Rights {
                fs_prefixes: vec![],
                net_hosts: vec![],
                methods: vec![],
                cred_use: vec![],
                budget_bytes: 0,
                expires_at: 0,
            },
            tag: String::new(),
        };
        let mut rl = RevocationList::default();
        rl.track(&mk("a", "b"));
        rl.track(&mk("b", "a"));
        rl.revoke("x"); // nothing on the cycle is revoked
        let t = mk("c", "a");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(rl.is_revoked(&t));
        });
        let res = rx.recv_timeout(std::time::Duration::from_secs(2));
        assert!(res.is_ok(), "is_revoked must terminate on a parent cycle");
        assert!(!res.unwrap(), "an unrevoked cycle is not revoked");

        // Same walk, with a cycle member revoked: still terminates, and the
        // revocation is seen.
        let mut rl = RevocationList::default();
        rl.track(&mk("a", "b"));
        rl.track(&mk("b", "a"));
        rl.revoke("b");
        let t = mk("c", "a");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(rl.is_revoked(&t));
        });
        let res = rx.recv_timeout(std::time::Duration::from_secs(2));
        assert!(res.is_ok(), "is_revoked must terminate on a revoked cycle");
        assert!(res.unwrap(), "a revoked ancestor revokes through a cycle");
    }

    #[test]
    fn root_fs_prefix_grants_and_narrows() {
        // "/" must cover everything. The old `starts_with(&format!("{npp}/"))`
        // built "//" for the root and matched no normalized path: a token
        // granted ["/"] allowed NOTHING, and narrowing it to a subpath failed
        // with "widens parent".
        let k = key();
        let mk = |prefixes: Vec<&str>| {
            Token::root(
                &k,
                "r",
                Rights {
                    fs_prefixes: prefixes.into_iter().map(String::from).collect(),
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 0,
                    expires_at: 9_999_999_999,
                },
            )
            .unwrap()
        };
        let root = mk(vec!["/"]);
        assert!(root.allows(&k, Some("/workspace/f"), None, None, None));
        assert!(root.allows(&k, Some("/"), None, None, None));
        assert!(root.allows(&k, Some("/etc/passwd"), None, None, None));

        // Narrowing a root grant to a subpath must work, and must really
        // narrow: the child sees only its subtree.
        let child = root
            .attenuate(
                &k,
                "c",
                Rights {
                    fs_prefixes: vec!["/workspace".into()],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 0,
                    expires_at: 9_999_999_000,
                },
            )
            .expect("a root grant can be narrowed to a subpath");
        assert!(child.allows(&k, Some("/workspace/x"), None, None, None));
        assert!(!child.allows(&k, Some("/etc/passwd"), None, None, None));

        // The reverse still fails: a subpath parent cannot be widened to "/".
        let parent = mk(vec!["/workspace"]);
        let wide = parent.rights.clone();
        let mut wide = wide;
        wide.fs_prefixes = vec!["/".into()];
        assert!(
            parent.attenuate(&k, "w", wide).is_err(),
            "widening to the root must still be refused"
        );
    }

    #[test]
    fn rev_id_is_validated_at_mint_and_delegation() {
        // The rev_id names the token in the audit trail and keys the
        // revocation map: control characters smuggle into logs, an oversized
        // one amplifies memory, and "" collides on the empty key.
        let k = key();
        let rights = || Rights {
            fs_prefixes: vec!["/workspace".into()],
            net_hosts: vec![],
            methods: vec![],
            cred_use: vec![],
            budget_bytes: 0,
            expires_at: 9_999_999_999,
        };
        for rev in ["", "a b", "a\nInjected: 1", "a\0b", &"x".repeat(65)] {
            assert!(
                Token::root(&k, rev, rights()).is_err(),
                "rev_id {rev:?} must be refused at mint"
            );
        }
        let root = Token::root(&k, "root-1.2_3", rights()).unwrap();
        for rev in ["", "a b", "a\nInjected: 1", &"x".repeat(65)] {
            assert!(
                root.attenuate(&k, rev, rights()).is_err(),
                "rev_id {rev:?} must be refused at delegation"
            );
        }
        assert!(root.attenuate(&k, "child-1", rights()).is_ok());
    }

    #[test]
    fn none_parent_and_empty_some_parent_do_not_collide() {
        // mac_for fed parent.unwrap_or_default(), so parent=None and
        // parent=Some("") produced the SAME tag. The chain shape was therefore
        // forgeable without the key: take a valid root, relabel it as a child
        // of "" (or the reverse), and the tag still verifies.
        let r = root();
        assert!(r.verify_tag(&key()));
        let relabeled = Token {
            rev_id: r.rev_id.clone(),
            parent: Some(String::new()),
            ancestors: r.ancestors.clone(),
            rights: r.rights.clone(),
            tag: r.tag.clone(),
        };
        assert!(
            !relabeled.verify_tag(&key()),
            "parent=None and parent=Some(\"\") must not share a tag"
        );
        // And the other direction: a token minted with Some("") must not pass
        // as a root.
        let child_of_empty = {
            let t = Token {
                rev_id: "r9".into(),
                parent: Some(String::new()),
                ancestors: Vec::new(),
                rights: r.rights.clone(),
                tag: String::new(),
            };
            // Mint its real tag under the key (simulate what a signer would do).
            let tag = hex_lower(
                &mac_for(&key(), &t.rev_id, &t.parent, &t.ancestors, &t.rights)
                    .finalize()
                    .into_bytes(),
            );
            Token { tag, ..t }
        };
        assert!(child_of_empty.verify_tag(&key()));
        let as_root = Token {
            rev_id: child_of_empty.rev_id.clone(),
            parent: None,
            ancestors: child_of_empty.ancestors.clone(),
            rights: child_of_empty.rights.clone(),
            tag: child_of_empty.tag.clone(),
        };
        assert!(
            !as_root.verify_tag(&key()),
            "a child of the empty parent must not pass as a root"
        );
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
    #[test]
    fn revocation_list_save_load_roundtrip() {
        let k = Key::from_bytes([7u8; 32]);
        let root = Token::root(
            &k,
            "root-1",
            Rights {
                fs_prefixes: vec!["/workspace".into()],
                net_hosts: vec![],
                methods: vec![],
                cred_use: vec![],
                budget_bytes: 0,
                expires_at: 0,
            },
        )
        .unwrap();
        let child = root
            .attenuate(
                &k,
                "child-2",
                Rights {
                    fs_prefixes: vec![],
                    net_hosts: vec![],
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: 0,
                    expires_at: 0,
                },
            )
            .unwrap();

        let mut rl = RevocationList::default();
        rl.track(&child);
        rl.revoke("root-1");
        rl.revoke("child-2");

        let dir = std::env::temp_dir().join(format!("tc-revoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revocation.json");

        rl.save(&path).unwrap();

        let loaded = RevocationList::load(&path).unwrap();
        assert!(
            loaded.is_revoked(&root),
            "root-1 must be revoked after load"
        );
        assert!(
            loaded.is_revoked(&child),
            "child-2 must be revoked after load"
        );

        // Empty revocation list roundtrips.
        let empty = RevocationList::default();
        let empty_path = dir.join("empty.json");
        empty.save(&empty_path).unwrap();
        let loaded_empty = RevocationList::load(&empty_path).unwrap();
        assert!(
            !loaded_empty.is_revoked(&root),
            "root-1 must not be revoked in empty list"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_revocation_graph_across_restarts() {
        let dir = std::env::temp_dir().join(format!("tc-revoke-graph-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("graph.json");

        // Multi-hop legacy tokens without signed `ancestors`: relies on `parent_of`
        // persisting across save()/load().
        let child = Token {
            rev_id: "c1".into(),
            parent: Some("r0".into()),
            ancestors: vec![],
            rights: Rights::default(),
            tag: String::new(),
        };
        let grandchild = Token {
            rev_id: "c2".into(),
            parent: Some("c1".into()),
            ancestors: vec![],
            rights: Rights::default(),
            tag: String::new(),
        };

        let mut rl = RevocationList::default();
        rl.track(&child);
        rl.track(&grandchild);
        rl.revoke("r0");
        assert!(rl.is_revoked(&grandchild));

        rl.save(&path).unwrap();
        let loaded = RevocationList::load(&path).unwrap();
        assert!(
            loaded.is_revoked(&grandchild),
            "persisted parent_of link graph must revoke 2-hop legacy grandchild after restart"
        );

        // Legacy bare-array format must still load cleanly.
        let legacy_path = dir.join("legacy.json");
        std::fs::write(&legacy_path, r#"["legacy-root"]"#).unwrap();
        let loaded_legacy = RevocationList::load(&legacy_path).unwrap();
        let tok = Token {
            rev_id: "legacy-root".into(),
            parent: None,
            ancestors: vec![],
            rights: Rights::default(),
            tag: String::new(),
        };
        assert!(loaded_legacy.is_revoked(&tok));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hierarchical_rev_id_revokes_descendants_without_tracking() {
        let mut rl = RevocationList::default();
        rl.revoke("org/team-a");

        let leaf = Token {
            rev_id: "org/team-a/sess-9/leaf".into(),
            parent: None,
            ancestors: vec![],
            rights: Rights::default(),
            tag: String::new(),
        };
        let sibling = Token {
            rev_id: "org/team-a-other/sess-1".into(),
            parent: None,
            ancestors: vec![],
            rights: Rights::default(),
            tag: String::new(),
        };
        assert!(
            rl.is_revoked(&leaf),
            "hierarchical prefix org/team-a must revoke org/team-a/sess-9/leaf cold"
        );
        assert!(
            !rl.is_revoked(&sibling),
            "prefix check must respect '/' boundary and not revoke org/team-a-other"
        );
    }
}
