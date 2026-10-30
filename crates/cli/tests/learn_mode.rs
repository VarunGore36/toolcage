//! Learn mode records denials and prints a proposed allowlist addition for
//! operator review. Proposals are NEVER auto-applied — an injected agent must
//! not be able to grow its own allowlist.

use std::process::Command;

fn run(extra: &[&str]) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("tc-learn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let policy =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/policy-v0.yaml");
    let audit = dir.join("a.jsonl");
    let mut args = vec![
        "mcp",
        "call",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        audit.to_str().unwrap(),
        "--name",
        "read_file",
        "--args-json",
        r#"{"path":"/etc/passwd"}"#,
    ];
    args.extend_from_slice(extra);
    let out = Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .args(&args)
        .output()
        .expect("cli runs");
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn learn_mode_proposes_on_denial_and_never_applies() {
    // /etc/passwd is outside the policy's mounts -> denied -> propose.
    let out = run(&["--learn"]);
    assert!(!out.status.success(), "reading /etc/passwd must be denied");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("learn: proposed allowlist addition"),
        "learn mode must propose on a denial: {err}"
    );
    assert!(
        err.contains("/etc/passwd"),
        "the proposal must name the denied path: {err}"
    );
    assert!(
        err.contains("REVIEW") && err.contains("never auto-applied"),
        "the proposal must demand operator review and disclaim auto-apply: {err}"
    );
    // The proposal is advisory: the call was still denied.
    assert!(err.contains("denied"), "the denial itself still happens: {err}");
}

#[test]
fn without_learn_there_is_no_proposal() {
    let out = run(&[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("learn:"),
        "no proposal without --learn: {err}"
    );
}
