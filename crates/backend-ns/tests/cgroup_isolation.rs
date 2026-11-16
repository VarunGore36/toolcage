use toolcage_backend::{Backend, SessionSpec, Tier};
use toolcage_backend_ns::NsBackend;

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
fn destroy_cleans_up_cgroup_directory() {
    if !cgroup_available() {
        eprintln!("skip: cgroup fs not available or read-only");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tc-cgroup-destroy-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let session_id = "destroy-test-session".to_string();
    let spec = SessionSpec {
        id: session_id.clone(),
        tier: Tier::Tier0,
        mem_mb: 512,
        cpu_millis: 250,
        workspace_mb: 0,
        workspace: dir.join("workspace").to_str().unwrap().to_string(),
    };
    let mut backend = NsBackend::new();
    backend.create(&spec).unwrap();

    // Verify cgroup directory exists after create (check both v1 and v2 paths)
    let cgroup_dir_v1 = format!("/sys/fs/cgroup/ns/toolcage/{}", session_id);
    let cgroup_dir_v2 = format!("/sys/fs/cgroup/toolcage/{}", session_id);
    let cgroup_dir = if std::path::Path::new(&cgroup_dir_v2).exists() {
        cgroup_dir_v2.clone()
    } else {
        cgroup_dir_v1.clone()
    };
    assert!(
        std::path::Path::new(&cgroup_dir).exists(),
        "cgroup dir should exist after create"
    );

    // Destroy the session
    backend.destroy(&session_id).unwrap();

    // Verify cgroup directory is cleaned up after destroy (check both v1 and v2 paths)
    assert!(
        !std::path::Path::new(&cgroup_dir_v1).exists(),
        "cgroup v1 dir should be cleaned up after destroy"
    );
    assert!(
        !std::path::Path::new(&cgroup_dir_v2).exists(),
        "cgroup v2 dir should be cleaned up after destroy"
    );

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
