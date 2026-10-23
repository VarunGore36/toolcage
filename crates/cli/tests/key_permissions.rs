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

#[cfg(unix)]
#[test]
fn keygen_out_prefix_is_not_extension_replaced() {
    // --out-prefix out/a.v1 must produce out/a.v1.key.hex, not out/a.key.hex.
    // with_extension replaces the existing extension, so out/a.v1 and out/a.v2
    // would both collapse to out/a.key.hex and clobber each other.
    let dir = std::env::temp_dir().join(format!(
        "tc-keyclob-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let base = dir.join("out/a");
    std::fs::create_dir_all(base.parent().unwrap()).unwrap();

    let s1 = cli_run(&["token", "keygen", "--out-prefix", base.with_extension("v1").to_str().unwrap()]);
    assert!(s1.success(), "keygen v1 must succeed");
    assert!(
        base.with_extension("v1.key.hex").exists(),
        "out/a.v1.key.hex must exist"
    );
    assert!(
        !base.with_extension("key.hex").exists(),
        "old buggy name out/a.key.hex must not be created"
    );

    let s2 = cli_run(&["token", "keygen", "--out-prefix", base.with_extension("v2").to_str().unwrap()]);
    assert!(s2.success(), "keygen v2 must succeed");
    assert!(
        base.with_extension("v2.key.hex").exists(),
        "out/a.v2.key.hex must exist"
    );
    assert!(
        base.with_extension("v1.key.hex").exists(),
        "out/a.v1.key.hex must not be clobbered by v2"
    );
}

#[cfg(unix)]
#[test]
fn checkpoint_file_uses_log_name() {
    // --log audit.log must produce audit.log.checkpoint.N (not
    // audit.jsonl.checkpoint.N), otherwise verify_with_pubkey scans the wrong
    // name and reports "no checkpoint files found".
    let dir = std::env::temp_dir().join(format!(
        "tc-ckptname-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("key");
    let s = cli_run(&["token", "keygen", "--out-prefix", key.to_str().unwrap()]);
    assert!(s.success(), "keygen must succeed");

    // Generate a valid audit log via a real run (Tier0).
    let log = dir.join("audit.log"); // NOTE: .log, not .jsonl
    let policy = std::env::current_dir().unwrap().join("../../schemas/policy-v0.yaml");
    let s = cli_run(&[
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--audit",
        log.to_str().unwrap(),
        "--",
        "/bin/true",
    ]);
    assert!(s.success(), "run must succeed to seed the audit log");

    let s = cli_run(&[
        "audit",
        "checkpoint",
        "--log",
        log.to_str().unwrap(),
        "--key-hex",
        key.with_extension("key.hex").to_str().unwrap(),
    ]);
    assert!(s.success(), "audit checkpoint must succeed");

    assert!(
        dir.join("audit.log.checkpoint.2").exists(),
        "audit.log.checkpoint.2 must exist"
    );
    assert!(
        !dir.join("audit.jsonl.checkpoint.2").exists(),
        "audit.jsonl.checkpoint.2 (old buggy name) must not be created"
    );
}

