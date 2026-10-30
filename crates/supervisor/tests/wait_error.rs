//! A wait error must not return with the workload (and its process group)
//! still running: `child.try_wait()?` used to unwind on error, dropping the
//! Child without killing anything — the timeout's fail-closed guarantee broke
//! on exactly the path that most needed it.
//!
//! SIGCHLD=SIG_IGN makes the kernel auto-reap children, so try_wait fails
//! with ECHILD while the workload's grandchildren (same process group) are
//! very much alive. Each tests/*.rs is its own process, so the ignored
//! disposition cannot disturb the other supervisor tests.

use std::os::unix::fs::PermissionsExt;

#[test]
fn wait_error_kills_the_process_group() {
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }

    let dir = std::env::temp_dir().join(format!("tc-waiterr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pid_file = dir.join("grandchild.pid");
    let script = dir.join("forker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/bash\nsleep 30 &\necho $! > {}\n",
            pid_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let policy =
        toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap();
    let mut s = toolcage_supervisor::Supervisor {
        policy,
        audit_path: dir.join("a.jsonl"),
        session: "waiterr".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
    };
    let argv = vec![script.display().to_string()];
    let res = s.exec_limits(&argv, 30, 4096);
    // The wait error surfaces (ECHILD: the kernel auto-reaped the workload).
    match res {
        Err(_) => {}
        Ok(_) => panic!("a wait error must surface"),
    }

    // The grandchild was in the workload's process group and must NOT have
    // survived the error return — that is the leak the `?` caused.
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let proc_path = format!("/proc/{pid}");
    for _ in 0..40 {
        if !std::path::Path::new(&proc_path).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        !std::path::Path::new(&proc_path).exists(),
        "the process group must not outlive a wait error (grandchild {pid} alive)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
