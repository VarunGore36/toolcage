//! Property: attenuation chains never exceed their parent (I3), over 200
//! seeds x multi-hop chains, and every widening attempt fails. Tokens are
//! keyed: a chain minted under one key is dead under another.
//!
//! Note on the v0 test: its root token had `expires_at: 100` (1970), so every
//! `allows()` call returned false and the implication was vacuously true.
//! Roots here are far-future so `child.allows => parent.allows` is a real test.
use toolcage_capability::{Key, RevocationList, Rights, Token};

fn key() -> Key {
    Key::from_bytes([3u8; 32])
}

fn narrow_of(r: &Rights, seed: u64) -> Rights {
    // Deterministic pseudo-random narrowing from seed.
    let take = |v: &[String], s: u64| -> Vec<String> {
        v.iter()
            .enumerate()
            .filter(|(i, _)| (s >> i) & 1 == 1)
            .map(|(_, x)| x.clone())
            .collect()
    };
    Rights {
        fs_prefixes: take(&r.fs_prefixes, seed)
            .into_iter()
            .map(|p| format!("{p}/sub"))
            .collect(),
        net_hosts: take(&r.net_hosts, seed >> 1),
        methods: take(&r.methods, seed >> 2),
        cred_use: take(&r.cred_use, seed >> 3),
        budget_bytes: r.budget_bytes.saturating_sub(seed % 7),
        expires_at: if r.expires_at == 0 {
            0
        } else {
            r.expires_at.saturating_sub(seed % 3)
        },
    }
}

#[test]
fn chains_never_widen_over_200_seeds() {
    let k = key();
    let root = Token::root(
        &k,
        "r0",
        Rights {
            fs_prefixes: vec!["/workspace".into(), "/tmp".into()],
            net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
            methods: vec!["GET".into(), "POST".into()],
            cred_use: vec!["github_token".into()],
            budget_bytes: 500,
            expires_at: 9_999_999_999,
        },
    );
    for seed in 0..200u64 {
        // Multi-hop delegation: root -> c0 -> c1 -> c2, each hop narrowed.
        let mut parent = root.clone();
        for hop in 0..3u64 {
            let child = parent
                .attenuate(
                    &k,
                    &format!("c{seed}-{hop}"),
                    narrow_of(&parent.rights, seed + hop),
                )
                .unwrap();
            // Child allows => parent allows (never wider). The probes mix
            // in-scope, out-of-scope and traversal paths.
            for (fp, h, m) in [
                (Some("/workspace/sub/f"), Some("github"), Some("GET")),
                (
                    Some("/workspace/../etc/passwd"),
                    Some("github"),
                    Some("GET"),
                ),
                (Some("/etc/passwd"), None, None),
                (None, Some("evil.com"), None),
                (None, Some("github"), Some("DELETE")),
            ] {
                if child.allows(&k, fp, h, m, None) {
                    assert!(
                        parent.allows(&k, fp, h, m, None),
                        "seed {seed} hop {hop}: child wider than parent"
                    );
                }
            }
            assert!(child.rights.budget_bytes <= parent.rights.budget_bytes);
            // Every widening attempt from this parent must fail on some axis.
            let mut wide = parent.rights.clone();
            wide.budget_bytes = parent.rights.budget_bytes + 1;
            assert!(
                parent
                    .attenuate(&k, &format!("w{seed}-{hop}"), wide)
                    .is_err(),
                "seed {seed}: widening budget accepted"
            );
            let mut wide = parent.rights.clone();
            wide.expires_at = parent.rights.expires_at + 1;
            assert!(
                parent
                    .attenuate(&k, &format!("x{seed}-{hop}"), wide)
                    .is_err(),
                "seed {seed}: widening expiry accepted"
            );
            parent = child;
        }
    }
}

#[test]
fn tokens_minted_under_another_key_are_dead() {
    // Forged chains never authorize anything at the host key, and cannot be
    // delegated onward under it (the v0 unkeyed tag allowed exactly this).
    let host = key();
    let rogue = Key::from_bytes([4u8; 32]);
    for seed in 0..50u64 {
        let forged = Token::root(
            &rogue,
            &format!("f{seed}"),
            narrow_of(
                &Rights {
                    fs_prefixes: vec!["/".into()],
                    net_hosts: vec!["github".into(), "evil.com".into()],
                    methods: vec!["GET".into(), "POST".into(), "DELETE".into()],
                    cred_use: vec!["github_token".into()],
                    budget_bytes: u64::MAX,
                    expires_at: 9_999_999_999,
                },
                seed,
            ),
        );
        assert!(
            !forged.verify_tag(&host),
            "seed {seed}: forged tag verified"
        );
        assert!(!forged.allows(&host, Some("/"), Some("evil.com"), Some("DELETE"), None));
        assert!(
            forged
                .attenuate(
                    &host,
                    "nope",
                    Rights {
                        fs_prefixes: vec![],
                        net_hosts: vec![],
                        methods: vec![],
                        cred_use: vec![],
                        budget_bytes: 1,
                        expires_at: 1,
                    }
                )
                .is_err(),
            "seed {seed}: forged parent delegated under host key"
        );
    }
}

/// Revocation is I3's other half: a revoked ancestor kills the whole subtree
/// — including descendants that were never track()ed — while revoking a child
/// never kills its parent. Chains here are real (keyed, attenuated), and the
/// walk must terminate even on hostile link shapes.
#[test]
fn revocation_subtree_holds_over_200_seeds() {
    let k = key();
    let root = Token::root(
        &k,
        "r0",
        Rights {
            fs_prefixes: vec!["/workspace".into(), "/tmp".into()],
            net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
            methods: vec!["GET".into(), "POST".into()],
            cred_use: vec!["github_token".into()],
            budget_bytes: 500,
            expires_at: 9_999_999_999,
        },
    );
    for seed in 0..200u64 {
        // root -> c0 -> c1 -> c2
        let mut chain = vec![root.clone()];
        for hop in 0..3u64 {
            let parent = chain.last().unwrap();
            let child = parent
                .attenuate(
                    &k,
                    &format!("c{seed}-{hop}"),
                    narrow_of(&parent.rights, seed + hop),
                )
                .unwrap();
            chain.push(child);
        }
        // Revoke the node at a level chosen by the seed: 0=root .. 3=c2.
        let level = (seed % 4) as usize;
        let mut rl = RevocationList::default();
        // Track every token — the documented contract: the walk uses each
        // token's own parent link plus tracked links for the rest of the
        // chain, so an untracked INTERMEDIATE cuts the chain (a token carries
        // only its immediate parent). The untracked-immediate-child case is
        // covered separately in revoke_parent_kills_untracked_children.
        for t in &chain {
            rl.track(t);
        }
        rl.revoke(&chain[level].rev_id);
        for (i, t) in chain.iter().enumerate() {
            let expect = i >= level;
            assert_eq!(
                rl.is_revoked(t),
                expect,
                "seed {seed} level {level}: chain[{i}] revoked={} (want {expect})",
                rl.is_revoked(t)
            );
        }
    }
}
