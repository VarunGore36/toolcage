//! Audit trail tests — verifies exec intent and outcome are both recorded
//! in the audit log (fail-closed pairing: every intent has an outcome).

fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "audit-trail".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::default(),
        cap_key: None,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    }
}

#[test]
fn audit_trail_records_intent_and_outcome() {
    let dir = std::env::temp_dir().join("tc-audit-trail");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let o = sup_at(&audit)
        .exec_limits(&["/bin/true".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);

    let log = std::fs::read_to_string(&audit).unwrap();
    // Audit must contain both intent (allow) and outcome records
    assert!(
        log.contains("proc.exec"),
        "audit must contain proc.exec action"
    );
    assert!(log.contains("allow"), "audit must contain allow decision");

    // Verify the audit chain integrity
    toolcage_audit::verify(&audit).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_trail_records_denial() {
    let dir = std::env::temp_dir().join("tc-audit-deny");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    // Use an empty argv which should be denied
    let o = sup_at(&audit)
        .exec_limits(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo pwned".to_string(),
            ],
            5,
            1024,
        )
        .unwrap();
    assert!(!o.allowed, "shell with inline code must be denied");

    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("deny"), "audit must contain deny decision");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_trail_records_exec_with_argv() {
    let dir = std::env::temp_dir().join(format!("tc-audit-argv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "audit-argv".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
        token_rev_id: String::default(),
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };
    let o = sup
        .exec(&[
            "/bin/echo".to_string(),
            "hello".to_string(),
            "world".to_string(),
        ])
        .unwrap();
    assert!(o.allowed);
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("proc.exec"), "audit must contain proc.exec");
    assert!(log.contains("allow"), "audit must contain allow outcome");
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn audit_trail_records_denied_exec() {
    let dir = std::env::temp_dir().join(format!("tc-audit-deny-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "audit-deny".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
        token_rev_id: String::default(),
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };
    let o = sup.exec(&["/bin/true".to_string()]).unwrap();
    assert!(
        !o.allowed,
        "tier0 without allow_unisolated should be denied"
    );
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("proc.exec"), "audit must contain proc.exec");
    assert!(log.contains("deny"), "audit must contain deny outcome");
    toolcage_audit::verify(&audit).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
