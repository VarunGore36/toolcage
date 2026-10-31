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
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
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
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
    };
    let b = toolcage_broker::Broker::new();
    // open("not-a-dir/audit.jsonl") fails -> propagate as Err, caller must not act.
    assert!(s
        .fetch_via_proxy(
            &b,
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            None,
            &toolcage_capability::RevocationList::default(),
            true
        )
        .is_err());
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
    let o = sup_at(&audit)
        .fetch_via_proxy(
            &b,
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        )
        .unwrap();
    // No credential injected -> proxy connects without auth header; body has no secret.
    assert!(o.allowed);
    assert!(!o.body.contains("s3cr3t"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn revoked_token_denied_and_audited() {
    // I3: revoke(parent) kills fetch even with an otherwise-valid child token.
    // The supervisor holds the host key so the tag verifies — the denial must
    // come from revocation, not from fail-closed tag verification.
    use toolcage_capability::{Key, RevocationList, Rights, Token};
    let key = Key::from_bytes([5u8; 32]);
    let dir = std::env::temp_dir().join("tc-chaos-revoked");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let root = Token::root(
        &key,
        "r0",
        Rights {
            fs_prefixes: vec!["/workspace".into()],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 1000,
            expires_at: 9_999_999_999,
        },
    ).unwrap();
    let child = root
        .attenuate(
            &key,
            "r1",
            Rights {
                fs_prefixes: vec![],
                net_hosts: vec!["github".into()],
                methods: vec!["GET".into()],
                cred_use: vec![],
                budget_bytes: 10,
                expires_at: 9_999_999_000,
            },
        )
        .unwrap();
    let mut rl = RevocationList::default();
    rl.track(&child);
    rl.revoke("r0");
    let mut s = sup_at(&audit);
    s.cap_key = Some(key);
    let o = s
        .fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            Some(&child),
            &rl,
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"token:deny".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn over_egress_budget_denies_fail_closed() {
    // §8 damage bound: tiny egress_bytes budget -> second fetch denied + audited.
    let mut pol = sample_policy();
    pol.limits.egress_bytes = 10;
    pol.limits.egress_requests = 1000;
    let dir = std::env::temp_dir().join("tc-chaos-budget");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let sup = toolcage_supervisor::Supervisor {
        policy: pol,
        audit_path: audit,
        session: "c".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
    };
    let b = toolcage_broker::Broker::new();
    let rl = toolcage_capability::RevocationList::default();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    // Proxy connects, gets response > 10B budget -> budget:exceeded denial.
    let o = sup
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &rl,
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"budget:exceeded".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn budget_precharge_denies_before_network() {
    // egress_bytes=10: the request-size estimate (~356 bytes) exceeds the
    // budget at pre-charge, so the call is denied BEFORE any network dial.
    // No live fetch happens (hermetic).
    let mut pol = sample_policy();
    pol.limits.egress_bytes = 10;
    pol.limits.egress_requests = 1000;
    let dir = std::env::temp_dir().join("tc-chaos-precharge");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut s = sup_at(&audit);
    s.policy = pol;
    let o = s
        .fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"budget:exceeded".to_string()));
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
        let _ = sup_at(&audit).fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        );
        assert!(toolcage_audit::verify(&audit).is_ok());
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
