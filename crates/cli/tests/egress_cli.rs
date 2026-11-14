//! CLI egress limit tests — verifies egress budget enforcement at the CLI level.

use std::process::Command;

fn cli_run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .status()
        .expect("cli binary runs")
}

#[test]
fn egress_excessive_policy_rejected() {
    // Create a temp policy with excessive egress_bytes
    let dir = std::env::temp_dir().join("tc-egress-cli");
    std::fs::create_dir_all(&dir).unwrap();
    let policy_path = dir.join("policy.yaml");
    std::fs::write(&policy_path, r#"
tool: test
limits:
  egress_bytes: 2000000000000
  egress_requests: 0
"#).unwrap();
    let audit = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&audit);

    let status = cli_run(&[
        "run",
        "--policy",
        policy_path.to_str().unwrap(),
        "--audit",
        audit.to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert!(!status.success(), "excessive egress_bytes policy must be rejected");

    let _ = std::fs::remove_dir_all(&dir);
}
