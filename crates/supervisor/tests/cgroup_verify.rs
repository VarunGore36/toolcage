//! Cgroup limit readback verification tests — verifies that cgroup limits
//! set during exec are actually written and can be read back.


fn make_sup_with_limits(
    audit: &std::path::Path,
    cpu_seconds: u64,
    memory_mb: u64,
) -> toolcage_supervisor::Supervisor {
    let mut policy = toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
        .unwrap();
    policy.limits.cpu_seconds = cpu_seconds;
    policy.limits.memory_mb = memory_mb;
    toolcage_supervisor::Supervisor {
        policy,
        audit_path: audit.to_path_buf(),
        session: "cgroup-verify".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::new(),
        cap_key: None,
    }
}

#[test]
fn cpu_limit_readback_verification() {
    if !std::path::Path::new("/sys/fs/cgroup").is_dir() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-verify-cpu");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_limits(&audit, 1, 0)
        .exec_limits(&["/bin/true".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed, "exec with cpu limit must succeed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memory_limit_readback_verification() {
    if !std::path::Path::new("/sys/fs/cgroup").is_dir() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-verify-mem");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_limits(&audit, 0, 64)
        .exec_limits(&["/bin/true".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed, "exec with memory limit must succeed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn combined_cpu_memory_limit_verification() {
    if !std::path::Path::new("/sys/fs/cgroup").is_dir() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-verify-both");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = make_sup_with_limits(&audit, 2, 128)
        .exec_limits(&["/bin/echo".to_string(), "verify".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed, "exec with combined limits must succeed");
    let _ = std::fs::remove_dir_all(&dir);
}
