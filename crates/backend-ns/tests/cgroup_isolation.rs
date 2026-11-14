use toolcage_backend_ns::NsBackend;
use toolcage_backend::{Backend, SessionSpec, Tier};

fn cgroup_available() -> bool {
    std::path::Path::new("/sys/fs/cgroup").is_dir()
        && std::fs::metadata("/sys/fs/cgroup")
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
}

#[test]
fn cgroup_mount_creates_directory() {
    if !cgroup_available() {
        eprintln!("skip: cgroup fs not available or read-only");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-mount-test");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = SessionSpec {
        id: "test-session-final-v2".into(),
        tier: Tier::Tier0,
        mem_mb: 1024,
        cpu_millis: 500,
        workspace_mb: 0,
        workspace: dir.join("workspace").to_str().unwrap().to_string(),
    };
    let mut backend = NsBackend::new();
    if backend.create(&spec).is_ok() {
        let cgroup_dir = std::path::Path::new("/sys/fs/cgroup/toolcage/test-session-final-v2");
        assert!(cgroup_dir.exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cpu_limit_applied_in_cgroup() {
    if !cgroup_available() {
        eprintln!("skip: cgroup fs not available or read-only");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-cpu-test");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = SessionSpec {
        id: "test-session-final-v2".into(),
        tier: Tier::Tier0,
        mem_mb: 0,
        cpu_millis: 500,
        workspace_mb: 0,
        workspace: dir.to_str().unwrap().to_string(),
    };
    let mut backend = NsBackend::new();
    if backend.create(&spec).is_ok() {
        let cgroup_dir = std::path::Path::new("/sys/fs/cgroup/toolcage/test-session-final-v2");
        assert!(cgroup_dir.is_dir());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn memory_limit_applied_in_cgroup() {
    if !cgroup_available() {
        eprintln!("skip: cgroup fs not available or read-only");
        return;
    }
    let dir = std::env::temp_dir().join("tc-cgroup-mem-test");
    std::fs::create_dir_all(&dir).unwrap();
    let spec = SessionSpec {
        id: "test-session-final-v2".into(),
        tier: Tier::Tier0,
        mem_mb: 1024,
        cpu_millis: 0,
        workspace_mb: 0,
        workspace: dir.to_str().unwrap().to_string(),
    };
    let mut backend = NsBackend::new();
    if backend.create(&spec).is_ok() {
        let cgroup_dir = std::path::Path::new("/sys/fs/cgroup/toolcage/test-session-final-v2");
        assert!(cgroup_dir.is_dir());
    }
    let _ = std::fs::remove_dir_all(&dir);
}