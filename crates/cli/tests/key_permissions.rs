//! Secret material (keys / tokens / credentials) must be written mode 0600,
//! not the 0644 that `fs::write` defaults to. On a multi-user host a
//! world-readable capability HMAC key or Ed25519 signing key is directly
//! usable by other local users.

use std::process::Command;

fn cli_run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .status()
        .expect("cli binary runs")
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
#[test]
fn secret_files_are_mode_0600() {
    let dir = std::env::temp_dir().join(format!(
        "tc-keymode-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // token keygen -> key.hex must be 0600.
    let key = dir.join("key");
    let status = cli_run(&["token", "keygen", "--out-prefix", key.to_str().unwrap()]);
    assert!(status.success(), "keygen must succeed");
    assert_eq!(mode(&key.with_extension("key.hex")), 0o600, "key.hex must be 0600");

    // token mint -> token file must be 0600.
    let token = dir.join("token.json");
    let status = cli_run(&[
        "token",
        "mint",
        "--rev",
        "root-1",
        "--out",
        token.to_str().unwrap(),
        "--key-hex",
        key.with_extension("key.hex").to_str().unwrap(),
    ]);
    assert!(status.success(), "mint must succeed");
    assert_eq!(mode(&token), 0o600, "minted token must be 0600");

    // audit keygen -> secret.hex must be 0600, pub.hex must NOT be 0600 (public).
    let ak = dir.join("auditkey");
    let status = cli_run(&["audit", "keygen", "--out-prefix", ak.to_str().unwrap()]);
    assert!(status.success(), "audit keygen must succeed");
    assert_eq!(
        mode(&ak.with_extension("secret.hex")),
        0o600,
        "secret.hex must be 0600"
    );
    let pub_mode = mode(&ak.with_extension("pub.hex"));
    assert_ne!(
        pub_mode,
        0o600,
        "pub.hex is public and must not be restricted to 0600"
    );
}
