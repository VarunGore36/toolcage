//! Tests for run_command argv validation in MCP.

use std::fs;
use std::path::PathBuf;

fn cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_toolcage-cli"));
    cmd.current_dir(std::env::temp_dir());
    cmd
}

fn setup_test_dir(base_name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tc-{}-{}", base_name, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let workspace = dir.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let policy = dir.join("policy.yaml");
    let audit = dir.join("audit.jsonl");
    fs::write(
        &policy,
        r#"
tool: test
version: 0
min_isolation: tier0
fs:
  mounts:
    - path: /workspace
      mode: rw
      source: session-copy
net:
  mode: allowlist
  hosts:
    - host: example.com
      methods: [GET]
credentials:
  - name: test_token
    use_with: example.com
limits:
  cpu_seconds: 300
  memory_mb: 1024
  egress_bytes: 1000000
"#,
    )
    .unwrap();
    fs::write(&audit, "").unwrap();
    (policy, audit, workspace)
}

#[test]
fn mcp_call_run_command_missing_argv_fails() {
    let (policy, audit, workspace) = setup_test_dir("run-cmd-missing-argv");

    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--name",
            "run_command",
            "--args-json",
            "{}",
            "--unsafe-no-isolation",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[args:argv required]"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn mcp_call_run_command_empty_argv_fails() {
    let (policy, audit, workspace) = setup_test_dir("run-cmd-empty-argv");

    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--name",
            "run_command",
            "--args-json",
            r#"{"argv":[]}"#,
            "--unsafe-no-isolation",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[args:argv cannot be empty]"),
        "stderr was: {}",
        stderr
    );
}

#[test]
fn mcp_call_run_command_valid_argv_succeeds_with_unsafe_no_isolation() {
    let (policy, audit, workspace) = setup_test_dir("run-cmd-valid-argv");

    // With --unsafe-no-isolation, the command runs unconfined and should succeed
    // The argv validation should pass (no "argv required" or "argv cannot be empty" errors)
    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--name",
            "run_command",
            "--args-json",
            r#"{"argv":["/bin/true"]}"#,
            "--unsafe-no-isolation",
        ])
        .output()
        .unwrap();

    // With --unsafe-no-isolation, the command runs and /bin/true succeeds
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("argv required"));
    assert!(!stderr.contains("argv cannot be empty"));
    // The command should succeed (exit 0)
    assert!(
        out.status.success(),
        "expected success with --unsafe-no-isolation, stderr: {}",
        stderr
    );
}
