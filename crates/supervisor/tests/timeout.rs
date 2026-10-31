//! The exec timeout must bound the WORKLOAD, not just the direct child.
//!
//! The unconfined spawn (`--unsafe-no-isolation`) SIGKILLed only the direct
//! child on expiry: everything the workload forked kept running on the host
//! past the timeout. The spawn is now a process group leader and the kill
//! takes out the whole group.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "timeout".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        cap_key: None,
    }
}

#[test]
fn timeout_kills_the_whole_process_group() {
    let dir = std::env::temp_dir().join(format!("tc-pgroup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pid_file = dir.join("grandchild.pid");
    let script = dir.join("forker.sh");
    // The workload forks a grandchild and then sleeps: without a group kill
    // the grandchild outlives the direct child and the timeout means nothing
    // to it.
    std::fs::write(
        &script,
        format!(
            "#!/bin/bash\nsleep 30 &\necho $! > {}\nsleep 30\n",
            pid_file.display()
        ),
    )
    .unwrap();
    let mut perm = std::fs::metadata(&script).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script, perm).unwrap();

    let mut s = sup_at(&dir.join("audit.jsonl"));
    let argv = vec![script.display().to_string()];
    let out = s.exec_limits(&argv, 1, 4096).unwrap();
    assert!(out.allowed);
    assert!(
        out.exit_code.is_none(),
        "the run must be recorded as a timeout"
    );

    // The grandchild must die with the group. Poll briefly: it is reparented
    // to init and reaped asynchronously after the SIGKILL.
    let pid: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let proc_path = format!("/proc/{pid}");
    let proc_entry = Path::new(&proc_path);
    for _ in 0..40 {
        if !proc_entry.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        !proc_entry.exists(),
        "forked grandchild (pid {pid}) survived the timeout kill"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
