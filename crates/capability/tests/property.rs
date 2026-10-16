//! Property: random attenuation chains never exceed their parent (I3).
use toolcage_capability::{Rights, Token};

fn narrow_of(r: &Rights, seed: u64) -> Rights {
    // Deterministic pseudo-random narrowing from seed.
    let take = |v: &[String], s: u64| -> Vec<String> {
        v.iter().enumerate().filter(|(i, _)| (s >> i) & 1 == 1).map(|(_, x)| x.clone()).collect()
    };
    Rights {
        fs_prefixes: take(&r.fs_prefixes, seed).into_iter().map(|p| format!("{p}/sub")).collect(),
        net_hosts: take(&r.net_hosts, seed >> 1),
        methods: take(&r.methods, seed >> 2),
        cred_use: take(&r.cred_use, seed >> 3),
        budget_bytes: r.budget_bytes.saturating_sub((seed % 7) as u64),
        expires_at: if r.expires_at == 0 { 0 } else { r.expires_at.saturating_sub(seed % 3) },
    }
}

#[test]
fn chains_never_widen_over_200_seeds() {
    let root = Token::root("r0", Rights {
        fs_prefixes: vec!["/workspace".into(), "/tmp".into()],
        net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
        methods: vec!["GET".into(), "POST".into()],
        cred_use: vec!["github_token".into()],
        budget_bytes: 500,
        expires_at: 100,
    });
    for seed in 0..200u64 {
        let child = root.attenuate(&format!("c{seed}"), narrow_of(&root.rights, seed)).unwrap();
        // Child allows => parent allows (never wider).
        for (fp, h, m) in [(Some("/workspace/sub/f"), Some("github"), Some("GET")), (Some("/etc/passwd"), None, None), (None, Some("evil.com"), None)] {
            if child.allows(fp, h, m, None) {
                assert!(root.allows(fp, h, m, None), "seed {seed}: child wider than parent");
            }
        }
        assert!(child.rights.budget_bytes <= root.rights.budget_bytes);
    }
}
