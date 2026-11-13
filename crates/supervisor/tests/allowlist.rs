//! Exec allowlist enforcement tests — verifies that when exec.allowlist is
//! non-empty, ONLY listed binaries may run (denylist bypass fix).
//!
//! These tests construct a Policy programmatically with an exec allowlist
//! and verify the supervisor enforces it.


fn make_sup_with_allowlist(
    audit: &std::path::Path,
    allowlist: Vec<String>,
) -> toolcage_supervisor::Supervisor {
    let mut policy = toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
        .unwrap();
    policy.exec.allowlist = allowlist;
    toolcage_supervisor::Supervisor {
        policy,
        audit_path: audit.to_path_buf(),
        session: "allowlist".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::new(),
        cap_key: None,
    }
}

#[test]
fn allowlist_empty_denylist_applies() {
    // With empty allowlist, denylist is the only gate — shell with inline
    // code should be denied.
    let dir = std::env::temp_dir().join("tc-allow-empty");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_allowlist(&audit, vec![])
        .exec(&["/bin/sh".to_string(), "-c".to_string(), "echo pwned".to_string()])
        .unwrap();
    assert!(!o.allowed, "shell with inline code must be denied without allowlist");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_allows_listed_binary() {
    let dir = std::env::temp_dir().join("tc-allow-listed");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_allowlist(&audit, vec!["echo".to_string()])
        .exec(&["/bin/echo".to_string(), "hello".to_string()])
        .unwrap();
    assert!(o.allowed, "allowlisted binary must be allowed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_denies_unlisted_binary() {
    let dir = std::env::temp_dir().join("tc-allow-unlisted");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_allowlist(&audit, vec!["echo".to_string()])
        .exec(&["/bin/sh".to_string(), "-c".to_string(), "echo pwned".to_string()])
        .unwrap();
    assert!(!o.allowed, "unlisted binary must be denied");
    assert!(o.rule_ids.iter().any(|r| r.contains("not-allowlisted")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_allows_different_path() {
    // Same binary name, different absolute path — should still match
    let dir = std::env::temp_dir().join("tc-allow-path2");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_allowlist(&audit, vec!["echo".to_string()])
        .exec(&["/usr/bin/echo".to_string(), "hello".to_string()])
        .unwrap();
    assert!(o.allowed, "echo at /usr/bin must be allowed when echo is allowlisted");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allowlist_rejects_untrusted_path() {
    // Even if the name matches, an untrusted path (e.g. /workspace) is denied
    let dir = std::env::temp_dir().join("tc-allow-path");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_allowlist(&audit, vec!["echo".to_string()])
        .exec(&["/workspace/echo".to_string(), "hello".to_string()])
        .unwrap();
    assert!(!o.allowed, "allowlisted name at untrusted path must be denied");
    assert!(o.rule_ids.iter().any(|r| r.contains("untrusted-path")));
    let _ = std::fs::remove_dir_all(&dir);
}
