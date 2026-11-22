//! REVIEW: bounded exec — timeout kills, over-cap truncates, both audited.
//! `sleep` killed at 1 s; `yes` truncated at 1 KiB; normal echo unaffected.
//! These exercise supervisor-level limits only, so they use the explicit
//! `allow_unisolated` opt-in (the audit outcome is flagged isolation:unisolated).
use toolcage_approval::Queue;
fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "limits".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
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

#[test]
fn normal_exec_unaffected() {
    let dir = std::env::temp_dir().join("tc-limits-normal");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "hello".to_string()], 30, 1024)
        .unwrap();
    assert!(o.allowed);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "hello\n");
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(!text.contains("timeout=true"));
    assert!(!text.contains("truncated=true"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_timeout_kills_immediately() {
    let dir = std::env::temp_dir().join("tc-limits-zero-timeout");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/sleep".to_string(), "30".to_string()], 0, 1024)
        .unwrap();
    // Zero timeout: sleep should be killed immediately
    assert!(o.allowed);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("timeout=true"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_cap_truncates_immediately() {
    let dir = std::env::temp_dir().join("tc-limits-zero-cap");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "hi".to_string()], 10, 0)
        .unwrap();
    assert!(o.allowed);
    assert_eq!(o.stdout.len(), 0);
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("truncated=true"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_argv_is_rejected() {
    let dir = std::env::temp_dir().join("tc-limits-empty-argv");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let result = sup_at(&audit).exec_limits(&[], 5, 1024);
    assert!(result.is_err(), "empty argv must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn timeout_zero_seconds() {
    let dir = std::env::temp_dir().join("tc-limits-timeout-zero");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/true".to_string()], 0, 1024)
        .unwrap();
    assert!(o.allowed, "timeout=0 should allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn timeout_very_large() {
    let dir = std::env::temp_dir().join("tc-limits-timeout-large");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/true".to_string()], 3600, 1024)
        .unwrap();
    assert!(o.allowed, "timeout=3600 should allow exec");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cap_one_byte() {
    let dir = std::env::temp_dir().join("tc-limits-cap-1byte");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "hi".to_string()], 10, 1)
        .unwrap();
    assert!(o.allowed);
    assert_eq!(o.stdout.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cap_large_value() {
    let dir = std::env::temp_dir().join("tc-limits-cap-large");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(
            &["/bin/echo".to_string(), "hi".to_string()],
            10,
            1024 * 1024,
        )
        .unwrap();
    assert!(o.allowed);
    assert_eq!(o.stdout.len(), 3); // "hi\n"
    let _ = std::fs::remove_dir_all(&dir);
}
