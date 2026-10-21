//! Isolation fail-closed (I1/I6): exec never silently degrades to a host spawn.
//! Regression suite for the Tier2/no-backend downgrade: without a wired backend
//! (or the explicit tier0-only opt-in) the call is DENIED and audited — the
//! supervisor must never become an unsandboxed process launcher.
fn sup_at(
    audit: &std::path::Path,
    tier: toolcage_backend::Tier,
    allow_unisolated: bool,
) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap(),
        audit_path: audit.to_path_buf(),
        session: "isolation".into(),
        tier,
        backend: None,
        allow_unisolated,
        cap_key: None,
    }
}

#[test]
fn no_backend_denies_fail_closed() {
    // backend: None without the explicit opt-in -> denial, nothing executed.
    let dir = std::env::temp_dir().join("tc-iso-nobackend");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit, toolcage_backend::Tier::Tier0, false)
        .exec(&["/bin/echo".to_string(), "pwned".to_string()])
        .unwrap();
    assert!(!o.allowed);
    assert!(o.rule_ids.contains(&"isolation:unavailable".to_string()));
    assert!(o.stdout.is_empty(), "denied call must not execute");
    // The denial is recorded and the chain still verifies.
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("isolation:unavailable"));
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier2_without_backend_denies_not_host_spawn() {
    // Regression: Tier2 used to fall through to Command::new on the HOST.
    // A missing cage is a denial, never a silent downgrade to zero isolation.
    let dir = std::env::temp_dir().join("tc-iso-tier2");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit, toolcage_backend::Tier::Tier2, false)
        .exec(&["/bin/echo".to_string(), "pwned".to_string()])
        .unwrap();
    assert!(!o.allowed);
    assert!(o.stdout.is_empty(), "Tier2 must never exec on the host");
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("isolation:unavailable"));
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier2_unisolated_optin_is_refused() {
    // Defense in depth: the escape hatch is tier0-only. A caller that asks for
    // Tier1/2 isolation must never get an unconfined run instead.
    let dir = std::env::temp_dir().join("tc-iso-tier2-optin");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit, toolcage_backend::Tier::Tier2, true)
        .exec(&["/bin/echo".to_string(), "pwned".to_string()])
        .unwrap();
    assert!(!o.allowed);
    assert!(o.rule_ids.contains(&"isolation:downgrade-refused".to_string()));
    assert!(o.stdout.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unisolated_optin_runs_and_is_flagged() {
    // The explicit escape hatch works, and the audit outcome is visibly marked
    // so an unconfined run can never be mistaken for a sandboxed one.
    let dir = std::env::temp_dir().join("tc-iso-optin");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit, toolcage_backend::Tier::Tier0, true)
        .exec(&["/bin/echo".to_string(), "hi".to_string()])
        .unwrap();
    assert!(o.allowed);
    assert!(o.rule_ids.contains(&"isolation:unisolated".to_string()));
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("isolation:unisolated"));
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
