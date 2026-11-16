//! Tests for dual-auth validation: --token and --key-hex must be used together.

use std::fs;
use std::path::PathBuf;

fn cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_toolcage-cli"));
    cmd.current_dir(std::env::temp_dir());
    cmd
}

fn write_policy(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("policy.yaml");
    fs::write(
        &p,
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
    p
}

fn write_audit(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("audit.jsonl");
    fs::write(&p, "").unwrap();
    p
}

fn write_token(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("token.json");
    // Minimal valid token structure (won't verify without key, but tests the arg parsing)
    fs::write(
        &p,
        r#"{
  "rev_id": "test",
  "parent": null,
  "ancestors": [],
  "rights": {
    "fs_prefixes": ["/workspace"],
    "net_hosts": ["example.com"],
    "methods": ["GET"],
    "cred_use": [],
    "budget_bytes": 1000,
    "expires_at": 9999999999
  },
  "tag": "deadbeef"
}"#,
    )
    .unwrap();
    p
}

fn write_key(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("key.hex");
    fs::write(
        &p,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    p
}

#[test]
fn fetch_token_without_key_fails() {
    let dir = std::env::temp_dir().join(format!("tc-dual-auth-token-only-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let token = write_token(&dir);

    let out = cli()
        .args([
            "fetch",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--host",
            "example.com",
            "--method",
            "GET",
            "--path",
            "/",
            "--cred",
            "test_token",
            "--token",
            token.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dual-auth") || stderr.contains("both"));
}

#[test]
fn fetch_key_without_token_fails() {
    let dir = std::env::temp_dir().join(format!("tc-dual-auth-key-only-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let key = write_key(&dir);

    let out = cli()
        .args([
            "fetch",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--host",
            "example.com",
            "--method",
            "GET",
            "--path",
            "/",
            "--cred",
            "test_token",
            "--key-hex",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // With key but no token, it should work (policy-only mode)
    // But with key and no token, the cap_key is set but no token is provided
    // This should fail with "token:missing"
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("token:missing") || stderr.contains("dual-auth"));
}

#[test]
fn mcp_serve_token_without_key_fails() {
    let dir = std::env::temp_dir().join(format!(
        "tc-dual-auth-mcp-token-only-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let token = write_token(&dir);

    let out = cli()
        .args([
            "mcp",
            "serve",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--token",
            token.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dual-auth") || stderr.contains("both"));
}

#[test]
fn mcp_serve_key_without_token_fails() {
    let dir =
        std::env::temp_dir().join(format!("tc-dual-auth-mcp-key-only-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let key = write_key(&dir);

    let out = cli()
        .args([
            "mcp",
            "serve",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--key-hex",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dual-auth") || stderr.contains("both"));
}

#[test]
fn mcp_call_token_without_key_fails() {
    let dir = std::env::temp_dir().join(format!(
        "tc-dual-auth-mcp-call-token-only-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let token = write_token(&dir);

    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--name",
            "http_fetch",
            "--args-json",
            r#"{"host":"example.com","method":"GET","path":"/"}"#,
            "--token",
            token.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dual-auth") || stderr.contains("both"));
}

#[test]
fn mcp_call_key_without_token_fails() {
    let dir = std::env::temp_dir().join(format!(
        "tc-dual-auth-mcp-call-key-only-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let policy = write_policy(&dir);
    let audit = write_audit(&dir);
    let key = write_key(&dir);

    let out = cli()
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--name",
            "http_fetch",
            "--args-json",
            r#"{"host":"example.com","method":"GET","path":"/"}"#,
            "--key-hex",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dual-auth") || stderr.contains("both"));
}
