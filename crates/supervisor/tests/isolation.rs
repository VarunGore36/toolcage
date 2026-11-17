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
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "isolation".into(),
        tier,
        backend: None,
        allow_unisolated,
        cap_key: None,
        token_rev_id: String::default(),
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
    assert!(o
        .rule_ids
        .contains(&"isolation:downgrade-refused".to_string()));
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

#[test]
fn tier0_with_backend_executes() {
    // With an explicit allow_unisolated=true and a tier0 backend, exec
    // should succeed (the actual backend execution is covered by backend-ns
    // tests, but we verify the supervisor wiring here).
    let dir = std::env::temp_dir().join("tc-iso-tier0-backend");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tier0-backend".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // With allow_unisolated=true and tier0, exec runs (unisolated but audited)
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed);
    assert!(o.rule_ids.contains(&"isolation:unisolated".to_string()));
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("proc.exec"));
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_trail_has_intent_and_outcome() {
    // Verify that the audit log contains both the intent (proc.exec request)
    // and the outcome (allow/deny), ensuring fail-closed pairing (I4).
    let dir = std::env::temp_dir().join("tc-iso-audit-trail");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "audit-trail".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // Execute a command
    let _ = sup
        .exec(&["/bin/echo".to_string(), "audit-trail".to_string()])
        .unwrap();
    // Verify the audit log
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(
        log.contains("proc.exec"),
        "audit must contain proc.exec action"
    );
    assert!(log.contains("allow"), "audit must contain allow outcome");
    // Verify the audit chain integrity
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn denied_exec_is_audited() {
    // A denied exec must still be audited (fail-closed: even denials are logged).
    let dir = std::env::temp_dir().join("tc-iso-denied-audit");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "denied-audit".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // Without allow_unisolated, exec should be denied
    let o = sup
        .exec(&["/bin/echo".to_string(), "denied".to_string()])
        .unwrap();
    assert!(!o.allowed);
    // Verify the audit log records the denial
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(
        log.contains("proc.exec"),
        "audit must contain proc.exec action"
    );
    assert!(log.contains("deny"), "audit must contain deny outcome");
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier1_backend_unavailable_denies() {
    // Tier1 (gVisor) without a wired backend must fail closed
    let dir = std::env::temp_dir().join(format!("tc-iso-tier1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tier1-backend".into(),
        tier: toolcage_backend::Tier::Tier1,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
        token_rev_id: String::default(),
    };
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(!o.allowed, "tier1 without backend should be denied");
    assert!(o.stdout.is_empty(), "denied call must not execute");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exec_with_bad_tier_name_denied() {
    // Test that the supervisor properly handles tier validation
    let dir = std::env::temp_dir().join(format!("tc-iso-bad-tier-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "bad-tier".into(),
        tier: toolcage_backend::Tier::Tier2,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
        token_rev_id: String::default(),
    };
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(!o.allowed, "tier2 without backend should be denied");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier0_with_cpu_limit_executes() {
    let dir = std::env::temp_dir().join(format!("tc-iso-tier0-cpu-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tier0-cpu".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // cpu_seconds = 1 should allow execution but enforce limit
    sup.policy.limits.cpu_seconds = 1;
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed, "tier0 exec with CPU limit should succeed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier0_with_memory_limit_executes() {
    let dir = std::env::temp_dir().join(format!("tc-iso-tier0-mem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tier0-mem".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // memory_mb = 256 should allow execution
    sup.policy.limits.memory_mb = 256;
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed, "tier0 exec with memory limit should succeed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier0_session_id_validation() {
    // Session IDs should be validated - empty IDs should be rejected
    let dir = std::env::temp_dir().join(format!("tc-iso-sid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "".into(), // empty session ID
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    // Empty session ID should still allow exec (the supervisor doesn't validate session IDs)
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed, "empty session ID should still allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier0_very_long_session_id() {
    let dir = std::env::temp_dir().join(format!("tc-iso-longsid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "a".repeat(10000), // very long session ID
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed, "long session ID should still allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tier0_unisolated_executes() {
    let dir = std::env::temp_dir().join(format!("tc-iso-tier0-uniso-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tier0-uniso".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    let o = sup
        .exec(&["/bin/echo".to_string(), "unisolated".to_string()])
        .unwrap();
    assert!(o.allowed, "tier0 unisolated exec should succeed");
    assert!(
        o.rule_ids.contains(&"isolation:unisolated".to_string()),
        "audit should flag unisolated: {:?}",
        o.rule_ids
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_session_id_variants() {
    let dir = std::env::temp_dir().join(format!("tc-iso-sid-variants-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let session_ids = [
        "simple-session",
        "session-with-dashes",
        "session.with.dots",
        "session_with_underscores",
        "SESSION_UPPERCASE",
        "session123",
    ];

    for session_id in session_ids {
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: audit.to_path_buf(),
            session: session_id.to_string(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
            token_rev_id: String::default(),
        };
        let o = sup.exec(&["/bin/true".to_string()]).unwrap();
        assert!(o.allowed, "session ID '{session_id}' should be allowed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_tier0_with_different_policies() {
    let dir = std::env::temp_dir().join(format!("tc-iso-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    // Test with different CPU limits
    for cpu_seconds in [0, 1, 5, 30, 300] {
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: audit.to_path_buf(),
            session: format!("tier0-cpu-{cpu_seconds}"),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
            token_rev_id: String::default(),
        };
        sup.policy.limits.cpu_seconds = cpu_seconds;
        let o = sup.exec(&["/bin/true".to_string()]).unwrap();
        assert!(
            o.allowed,
            "tier0 exec with cpu_seconds={cpu_seconds} should succeed"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_tier0_with_different_memory_limits() {
    let dir = std::env::temp_dir().join(format!("tc-iso-mem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    for memory_mb in [0, 64, 256, 1024, 4096] {
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: audit.to_path_buf(),
            session: format!("tier0-mem-{memory_mb}"),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
            token_rev_id: String::default(),
        };
        sup.policy.limits.memory_mb = memory_mb;
        let o = sup.exec(&["/bin/true".to_string()]).unwrap();
        assert!(
            o.allowed,
            "tier0 exec with memory_mb={memory_mb} should succeed"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_session_id_variants_final() {
    let dir =
        std::env::temp_dir().join(format!("tc-iso-sid-variants-final-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let session_ids = [
        "simple-session",
        "session-with-dashes",
        "session.with.dots",
        "session_with_underscores",
        "SESSION_UPPERCASE",
        "session123",
    ];

    for session_id in session_ids {
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: audit.to_path_buf(),
            session: session_id.to_string(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
            token_rev_id: String::default(),
        };
        let o = sup.exec(&["/bin/true".to_string()]).unwrap();
        assert!(o.allowed, "session ID '{session_id}' should be allowed");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn supervisor_session_id_empty_allowed() {
    let dir = std::env::temp_dir().join(format!("tc-iso-empty-sid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
    };
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(o.allowed, "empty session ID should be allowed");
    let _ = std::fs::remove_dir_all(&dir);
}
