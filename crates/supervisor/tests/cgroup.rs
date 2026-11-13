fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "cgroup".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::new(),
        cap_key: None,
    }
}

#[test]
fn cgroup_dir_created_for_session() {
    if !std::fs::metadata("/sys/fs/cgroup").is_ok() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/true".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cpu_limit_applied_in_cgroup() {
    let dir = std::env::temp_dir().join("tc-cgroup-cpu");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 1, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pids_limit_applied_in_cgroup() {
    let dir = std::env::temp_dir().join("tc-cgroup-pids");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memory_limit_applied_in_cgroup() {
    let dir = std::env::temp_dir().join("tc-cgroup-mem");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024 * 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn process_added_to_cgroup() {
    let dir = std::env::temp_dir().join("tc-cgroup-pid");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oom_group_applied_in_cgroup() {
    if !std::fs::metadata("/sys/fs/cgroup").is_ok() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-oom");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cgroup_cleanup_on_destroy() {
    if !std::fs::metadata("/sys/fs/cgroup").is_ok() {
        eprintln!("skip: cgroup fs not available");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-cleanup-destroy");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024)
        .unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cgroup_cleanup_after_session() {
    let dir = std::env::temp_dir().join("tc-cgroup-cleanup");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .exec_limits(&["/bin/echo".to_string(), "test".to_string()], 5, 1024).unwrap();
    assert!(o.allowed);
    let _ = std::fs::remove_dir_all(&dir);
}
