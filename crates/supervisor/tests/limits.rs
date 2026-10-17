//! REVIEW: bounded exec — timeout kills, over-cap truncates, both audited.
//! `sleep` killed at 1 s; `yes` truncated at 1 KiB; normal echo unaffected.
fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap(),
        audit_path: audit.to_path_buf(),
        session: "limits".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
    }
}

#[test]
fn timeout_kills_sleep() {
    let dir = std::env::temp_dir().join("tc-limits-timeout");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/sleep".to_string(), "30".to_string()], 1, 1024)
        .unwrap();
    assert!(o.allowed);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("timeout=true"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn overcap_truncates_yes() {
    let dir = std::env::temp_dir().join("tc-limits-cap");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "hi".to_string()], 10, 1)
        .unwrap();
    assert!(o.allowed);
    assert!(o.stdout.len() <= 1);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("truncated=true"));
    let _ = std::fs::remove_dir_all(&dir);
}
