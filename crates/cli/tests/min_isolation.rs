//! The policy's min_isolation floor must hold even for --unsafe-no-isolation.
//! Previously `wire_backend` returned None (unconfined) before checking
//! min_isolation, so `--unsafe-no-isolation --tier tier0` with a policy
//! demanding tier1/tier2 ran unconfined on the host, silently ignoring the
//! policy floor.

use std::process::Command;

fn cli_run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .status()
        .expect("cli binary runs")
}

fn policy_file(min_isolation: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tc-miniso-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("policy.yaml");
    std::fs::write(
        &p,
        format!(
            "tool: t\nversion: 0\nmin_isolation: {min_isolation}\nfs:\n  mounts:\n    - path: /workspace\n      mode: rw\n      source: session-copy\nnet:\n  mode: allowlist\n  hosts: []\n",
        ),
    )
    .unwrap();
    p
}

#[test]
fn unsafe_no_isolation_cannot_weaken_min_isolation_tier2() {
    // Policy demands tier2; --unsafe-no-isolation --tier tier0 must be denied
    // because tier0 cannot honor the min_isolation floor. Before the fix this
    // ran unconfined on the host.
    let policy = policy_file("tier2");
    let audit = std::env::temp_dir().join(format!("tc-miniso-audit-{}.jsonl", std::process::id()));
    let status = cli_run(&[
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--tier",
        "tier0",
        "--unsafe-no-isolation",
        "--audit",
        audit.to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert!(
        !status.success(),
        "unsafe-no-isolation cannot weaken min_isolation tier2, got {:?}",
        status.code()
    );
}

#[test]
fn unsafe_no_isolation_allowed_when_min_isolation_met() {
    // Policy demands tier0; --unsafe-no-isolation --tier tier0 runs
    // (unconfined, audited) because the floor is met.
    let policy = policy_file("tier0");
    let audit = std::env::temp_dir().join(format!("tc-miniso-audit2-{}.jsonl", std::process::id()));
    let status = cli_run(&[
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--tier",
        "tier0",
        "--unsafe-no-isolation",
        "--audit",
        audit.to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert!(
        status.success(),
        "min_isolation tier0 allows unsafe-no-isolation, got {:?}",
        status.code()
    );
}
