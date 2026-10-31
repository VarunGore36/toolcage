//! CLI exit codes: a child killed by a signal or the wall-clock timeout is a
//! failure, not success. exit_code.unwrap_or(0) used to report both as exit 0.

use std::process::Command;

fn cli_run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .status()
        .expect("cli binary runs")
}

#[test]
fn successful_run_exits_zero() {
    let status = cli_run(&[
        "run",
        "--policy",
        "../../schemas/policy-v0.yaml",
        "--audit",
        &format!("{}/tc-exit-ok.jsonl", std::env::temp_dir().display()),
        "--",
        "/bin/true",
    ]);
    assert!(
        status.success(),
        "/bin/true must exit 0, got {:?}",
        status.code()
    );
}

#[test]
fn timeout_killed_run_exits_nonzero() {
    // The supervisor kills the child at the wall-clock deadline and returns
    // exit_code: None. The CLI must not map that to exit 0.
    let status = cli_run(&[
        "run",
        "--policy",
        "../../schemas/policy-v0.yaml",
        "--audit",
        &format!("{}/tc-exit-test.jsonl", std::env::temp_dir().display()),
        "--",
        "/bin/sleep",
        "300",
    ]);
    assert!(
        !status.success(),
        "timeout-killed run must not exit 0, got {:?}",
        status.code()
    );
}
