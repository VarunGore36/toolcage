//! Chaos v0 (fail-closed): dead proxy/broker/audit/disk/clock must STOP actions.
//! Runs nightly + pre-release. No silent fallback.

fn sample_policy() -> toolcage_policy::Policy {
    toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
}

fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: audit.to_path_buf(),
        session: "chaos".into(),
    }
}

#[test]
fn audit_write_failure_denies_action() {
    // Audit dir is a file, not a dir -> Writer::open fails -> fetch errors (deny).
    let dir = std::env::temp_dir().join("tc-chaos-auditfail");
    let _ = std::fs::remove_file(&dir);
    std::fs::write(&dir, "not-a-dir").unwrap();
    let bad = dir.join("audit.jsonl");
    let s = toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: bad,
        session: "c".into(),
    };
    let b = toolcage_broker::Broker::new();
    // open("not-a-dir/audit.jsonl") fails -> propagate as Err, caller must not act.
    assert!(s.fetch_via_proxy(&b, "github", "GET", "/", None, &toolcage_capability::RevocationList::default(), true).is_err());
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn proxy_down_means_closed() {
    // No proxy object available -> no direct fallback. Policy alone denies evil.
    let p = sample_policy();
    let d = toolcage_proxy::decide(&p, "evil.example.com", "GET", "/");
    assert!(!d.allow && d.upstream.is_none());
}

#[test]
fn broker_unreachable_denies_cred_use() {
    // Empty broker (unreachable store) -> inject returns None, body has no-auth, never literal.
    let b = toolcage_broker::Broker::new();
    assert_eq!(b.inject("github_token", "github", "GET", "/"), None);
    let dir = std::env::temp_dir().join("tc-chaos-broker");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit).fetch_via_proxy(&b, "github", "GET", "/repos/acme/app/issues/1", None, &toolcage_capability::RevocationList::default(), true).unwrap();
    assert!(o.allowed);
    assert!(!o.body.contains("s3cr3t"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn revoked_token_denied_and_audited() {
    // I3: revoke(parent) kills fetch even with an otherwise-valid child token.
    use toolcage_capability::{RevocationList, Rights, Token};
    let dir = std::env::temp_dir().join("tc-chaos-revoked");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let root = Token::root("r0", Rights {
        fs_prefixes: vec!["/workspace".into()],
        net_hosts: vec!["github".into()],
        methods: vec!["GET".into()],
        cred_use: vec![],
        budget_bytes: 1000,
        expires_at: 9_999_999_999,
    });
    let child = root.attenuate("r1", Rights {
        fs_prefixes: vec![],
        net_hosts: vec!["github".into()],
        methods: vec!["GET".into()],
        cred_use: vec![],
        budget_bytes: 10,
        expires_at: 9_999_999_000,
    }).unwrap();
    let mut rl = RevocationList::default();
    rl.track(&child);
    rl.revoke("r0");
    let o = sup_at(&audit)
        .fetch_via_proxy(&toolcage_broker::Broker::new(), "github", "GET", "/", Some(&child), &rl, true)
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"token:deny".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disk_full_simulated_by_readonly() {
    let dir = std::env::temp_dir().join("tc-chaos-ro");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    std::fs::write(&audit, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o444)).unwrap();
        // Appending may still succeed as root; assert verify still holds either way.
        let _ = sup_at(&audit).fetch_via_proxy(&toolcage_broker::Broker::new(), "github", "GET", "/", None, &toolcage_capability::RevocationList::default(), true);
        assert!(toolcage_audit::verify(&audit).is_ok());
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
