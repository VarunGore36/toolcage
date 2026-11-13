//! Egress limit enforcement tests — verifies egress budgets are checked
//! during exec and enforced via precharge/true-up.


fn make_sup_with_egress(
    audit: &std::path::Path,
    egress_bytes: u64,
    egress_requests: u64,
) -> toolcage_supervisor::Supervisor {
    let mut policy = toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
        .unwrap();
    policy.limits.egress_bytes = egress_bytes;
    policy.limits.egress_requests = egress_requests;
    toolcage_supervisor::Supervisor {
        policy,
        audit_path: audit.to_path_buf(),
        session: "egress".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::new(),
        cap_key: None,
    }
}

#[test]
fn egress_bytes_excessive_rejected_at_session() {
    let dir = std::env::temp_dir().join("tc-egress-bytes");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_egress(&audit, 2 * 1024 * 1024 * 1024 * 1024, 0)
        .exec(&["/bin/true".to_string()])
        .unwrap();
    assert!(!o.allowed, "excessive egress_bytes must reject exec");
    assert!(o.rule_ids.iter().any(|r| r.contains("egress-bytes-excessive")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn egress_requests_excessive_rejected_at_session() {
    let dir = std::env::temp_dir().join("tc-egress-req");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_egress(&audit, 0, 2_000_000_000)
        .exec(&["/bin/true".to_string()])
        .unwrap();
    assert!(!o.allowed, "excessive egress_requests must reject exec");
    assert!(o.rule_ids.iter().any(|r| r.contains("egress-requests-excessive")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn egress_bytes_zero_allows_exec() {
    let dir = std::env::temp_dir().join("tc-egress-zero-bytes");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_egress(&audit, 0, 0)
        .exec(&["/bin/true".to_string()])
        .unwrap();
    assert!(o.allowed, "zero egress_bytes (unlimited) must allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn egress_requests_zero_allows_exec() {
    let dir = std::env::temp_dir().join("tc-egress-zero-req");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_egress(&audit, 0, 0)
        .exec(&["/bin/true".to_string()])
        .unwrap();
    assert!(o.allowed, "zero egress_requests (unlimited) must allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}
