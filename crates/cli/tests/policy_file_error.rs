//! Tests for policy file error messages.

use std::fs;
use std::path::PathBuf;

fn cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_toolcage-cli"));
    cmd.current_dir(std::env::temp_dir());
    cmd
}

fn write_audit(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("audit.jsonl");
    fs::write(&p, "").unwrap();
    p
}

#[test]
fn mcp_call_missing_policy_file_shows_path_in_error() {
    let dir = std::env::temp_dir().join(format!("tc-policy-missing-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let audit = write_audit(&dir);
    let missing_policy = dir.join("nonexistent.yaml");

    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            missing_policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--name",
            "run_command",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Error should mention the missing file path
    assert!(stderr.contains("read policy from") || stderr.contains("policy"));
    assert!(stderr.contains("nonexistent.yaml") || stderr.contains("No such file"));
}

#[test]
fn fetch_missing_policy_file_shows_path_in_error() {
    let dir = std::env::temp_dir().join(format!("tc-fetch-policy-missing-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let audit = write_audit(&dir);
    let missing_policy = dir.join("nonexistent.yaml");

    let out = cli()
        .args([
            "fetch",
            "--policy",
            missing_policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--host",
            "example.com",
            "--method",
            "GET",
            "--path",
            "/",
            "--cred",
            "test",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Error should mention the missing file path
    assert!(stderr.contains("read policy from") || stderr.contains("policy"));
    assert!(stderr.contains("nonexistent.yaml") || stderr.contains("No such file"));
}

#[test]
fn run_missing_policy_file_shows_path_in_error() {
    let dir = std::env::temp_dir().join(format!("tc-run-policy-missing-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let audit = write_audit(&dir);
    let missing_policy = dir.join("nonexistent.yaml");

    let out = cli()
        .args([
            "run",
            "--policy",
            missing_policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Error should mention the missing file path
    assert!(stderr.contains("read policy from") || stderr.contains("policy"));
    assert!(stderr.contains("nonexistent.yaml") || stderr.contains("No such file"));
}

#[test]
fn check_net_missing_policy_file_shows_path_in_error() {
    let dir = std::env::temp_dir().join(format!("tc-check-net-policy-missing-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let missing_policy = dir.join("nonexistent.yaml");

    let out = cli()
        .args([
            "check-net",
            "--policy",
            missing_policy.to_str().unwrap(),
            "--host",
            "example.com",
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Error should mention the missing file path
    assert!(stderr.contains("read policy from") || stderr.contains("policy"));
    assert!(stderr.contains("nonexistent.yaml") || stderr.contains("No such file"));
}