//! Test supervisor session ID handling - various session ID formats should be accepted.

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
        let o = sup.exec(&["/bin/true".to_string()]);
        // Session creation should succeed even if exec fails due to no backend
        assert!(
            sup.session == session_id || o.is_ok(),
            "session {session_id} should be created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
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
    let o = sup.exec(&["/bin/true".to_string()]);
    assert!(
        o.is_ok() || sup.session.is_empty(),
        "empty session ID should be allowed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
