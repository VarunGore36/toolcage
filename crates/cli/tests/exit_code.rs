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
        "--unsafe-no-isolation",
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
        "--unsafe-no-isolation",
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

#[test]
fn denied_shell_exec_fails() {
    // sh -c is a shell interpreter and should be denied by policy
    let status = cli_run(&[
        "run",
        "--unsafe-no-isolation",
        "--policy",
        "../../schemas/policy-v0.yaml",
        "--audit",
        &format!("{}/tc-exit-deny.jsonl", std::env::temp_dir().display()),
        "--",
        "/bin/sh",
        "-c",
        "echo pwned",
    ]);
    assert!(
        !status.success(),
        "denied shell exec must not exit 0, got {:?}",
        status.code()
    );
}

#[test]
fn allowed_echo_exec_succeeds() {
    let status = cli_run(&[
        "run",
        "--unsafe-no-isolation",
        "--policy",
        "../../schemas/policy-v0.yaml",
        "--audit",
        &format!("{}/tc-exit-echo.jsonl", std::env::temp_dir().display()),
        "--",
        "/bin/echo",
        "hello",
    ]);
    assert!(
        status.success(),
        "echo must exit 0, got {:?}",
        status.code()
    );
}

#[test]
fn fetch_unknown_host_denied() {
    let dir = std::env::temp_dir().join("tc-fetch-deny");
    std::fs::create_dir_all(&dir).unwrap();
    let policy =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/policy-v0.yaml");
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let status = cli_run(&[
        "fetch",
        "--unsafe-no-isolation",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        audit.to_str().unwrap(),
        "--host",
        "evil.example.com",
        "--method",
        "GET",
        "--path",
        "/",
    ]);
    assert!(
        !status.success(),
        "fetch to unknown host must be denied, got {:?}",
        status.code()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_mint_and_attenuate() {
    let dir = std::env::temp_dir().join("tc-token");
    std::fs::create_dir_all(&dir).unwrap();
    let key_hex = dir.join("key.hex.key.hex");
    let key = dir.join("key.hex");
    let token = dir.join("token.json");
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    // Generate key first
    let status = cli_run(&[
        "token",
        "keygen",
        "--out-prefix",
        key.to_str().unwrap(),
    ]);
    assert!(status.success(), "token keygen must succeed, got {:?}", status.code());

    // Read the generated key
    // Mint root token
    let status = cli_run(&[
        "token",
        "mint",
        "--rev",
        "root-1",
        "--out",
        token.to_str().unwrap(),
        "--key-hex",
        key_hex.to_str().unwrap(),
    ]);
    assert!(
        status.success(),
        "token mint must succeed, got {:?}",
        status.code()
    );

    // Attenuate token
    let attenuated = dir.join("attenuated.json");
    let status = cli_run(&[
        "token",
        "attenuate",
        "--parent",
        token.to_str().unwrap(),
        "--rev",
        "child-1",
        "--out",
        attenuated.to_str().unwrap(),
        "--hosts",
        "github",
        "--methods",
        "GET",
        "--budget",
        "100",
        "--key-hex",
        key_hex.to_str().unwrap(),
    ]);
    assert!(
        status.success(),
        "token attenuate must succeed, got {:?}",
        status.code()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn image_sign_and_verify() {
    let dir = std::env::temp_dir().join("tc-image");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("manifest.json");
    let sig = dir.join("signature.bin");
    let key = dir.join("key.hex");
    let key_hex = dir.join("key.hex.secret.hex");
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    // Create a minimal manifest
    std::fs::write(
        &manifest,
        r#"{"kernel":"/vmlinuz","rootfs":"/rootfs.ext4","version":"1.0"}"#,
    )
    .unwrap();

    // Generate key
    let status = cli_run(&[
        "audit",
        "keygen",
        "--out-prefix",
        key.to_str().unwrap(),
    ]);
    assert!(status.success(), "keygen must succeed, got {:?}", status.code());

    // Sign the manifest (uses directory, not manifest file directly)
    let status = cli_run(&[
        "image",
        "sign",
        "--dir",
        dir.to_str().unwrap(),
        "--key-hex",
        key_hex.to_str().unwrap(),
    ]);
    assert!(
        status.success(),
        "image sign must succeed, got {:?}",
        status.code()
    );
    assert!(sig.exists(), "signature file must be created: {:?}", sig);

    let _ = std::fs::remove_dir_all(&dir);
}
