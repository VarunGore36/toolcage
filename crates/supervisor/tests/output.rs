//! The output reader must drain to EOF: dropping it early closes the pipe and
//! SIGPIPEs the workload mid-write, corrupting its exit code.
//!
//! The unconfined (`--unsafe-no-isolation`) exec used `take(cap + 1)` on each
//! stream — the reader stopped at the cap and dropped the pipe, so a workload
//! writing more than the cap died on SIGPIPE and the run came back as a signal
//! death instead of its real exit code. The reader now drains to EOF while
//! keeping at most `cap` bytes (memory stays bounded).

use std::os::unix::fs::PermissionsExt;

fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
            .unwrap(),
        audit_path: audit.to_path_buf(),
        session: "output".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: true,
        token_rev_id: String::new(),
        cap_key: None,
    }
}

#[test]
fn over_cap_output_does_not_sigpipe_the_writer() {
    let dir = std::env::temp_dir().join(format!("tc-out-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("big.sh");
    // 2 MiB on stdout — far past both the 64 KiB pipe buffer and the cap
    // below, so the writer is still producing when the reader would have
    // stopped.
    std::fs::write(&script, "#!/bin/bash\nhead -c 2000000 /dev/zero\n").unwrap();
    let mut perm = std::fs::metadata(&script).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script, perm).unwrap();

    let mut s = sup_at(&dir.join("audit.jsonl"));
    let argv = vec![script.display().to_string()];
    let out = s.exec_limits(&argv, 30, 4096).unwrap();
    assert!(out.allowed);
    // The writer must finish cleanly: an early reader close cuts its output
    // pipe (SIGPIPE where that is not ignored, EPIPE otherwise) and its
    // status — here the script's own — comes back nonzero.
    assert_eq!(
        out.exit_code,
        Some(0),
        "the writer must not be cut off mid-output (got {:?})",
        out.exit_code
    );
    assert_eq!(out.stdout.len(), 4096, "output is still capped");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn runaway_flood_writer_is_killed_on_overrun_before_timeout() {
    let dir = std::env::temp_dir().join(format!("tc-overrun-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("flood.sh");
    // 64 MiB stream from /dev/zero — exceeds OVERRUN_KILL_BYTES (16 MiB)
    // and must trigger immediate killpg overrun termination rather than
    // waiting for the 30-second timeout.
    std::fs::write(&script, "#!/bin/bash\nhead -c 67108864 /dev/zero\n").unwrap();
    let mut perm = std::fs::metadata(&script).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script, perm).unwrap();

    let audit = dir.join("audit.jsonl");
    let mut s = sup_at(&audit);
    let start = std::time::Instant::now();
    let out = s
        .exec_limits(&[script.display().to_string()], 30, 1024)
        .unwrap();
    let elapsed = start.elapsed();
    assert!(out.allowed);
    assert_eq!(out.stdout.len(), 1024);
    assert!(
        elapsed.as_secs() < 10,
        "runaway writer must be killed on overrun well before 30s timeout (took {:?})",
        elapsed
    );
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("truncated=true"));
    let _ = std::fs::remove_dir_all(&dir);
}
