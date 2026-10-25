//! `fetch` secret handling. `--secret-value` puts the credential on the
//! command line, where every local user can read it from `ps` /
//! `/proc/*/cmdline` (and it lands in shell history). `--secret-file` is the
//! safe path: the value is read host-side and never reaches argv.

use std::process::Command;

fn fetch_with(extra: &[&str]) -> String {
    let dir = std::env::temp_dir().join(format!(
        "tc-secret-arg-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.yaml");
    std::fs::write(
        &policy,
        "tool: t\nversion: 0\nmin_isolation: tier0\nnet:\n  mode: allowlist\n  hosts: []\n",
    )
    .unwrap();
    let mut args: Vec<String> = vec![
        "fetch".into(),
        "--policy".into(),
        policy.to_str().unwrap().into(),
        "--audit".into(),
        dir.join("a.jsonl").to_str().unwrap().into(),
        "--host".into(),
        "github".into(),
        "--method".into(),
        "GET".into(),
        "--path".into(),
        "/x".into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let out = Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(&args)
        .output()
        .expect("cli runs");
    let _ = std::fs::remove_dir_all(&dir);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn secret_file_is_the_safe_path() {
    // --secret-file reads the value host-side: no warning, because argv never
    // carries the credential.
    let dir = std::env::temp_dir().join(format!(
        "tc-secret-file-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("secret.txt");
    std::fs::write(&f, "s3cret-from-file").unwrap();
    let out = fetch_with(&["--secret-file", f.to_str().unwrap()]);
    assert!(
        !out.contains("--secret-value"),
        "--secret-file must not warn about argv exposure: {out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn secret_value_warns_about_argv_exposure() {
    // --secret-value keeps working but must warn: the credential is on argv.
    let out = fetch_with(&["--secret-value", "s3cret-in-argv"]);
    assert!(
        out.contains("--secret-file"),
        "--secret-value must warn to prefer --secret-file: {out}"
    );
    assert!(
        out.to_lowercase().contains("ps") || out.to_lowercase().contains("command line"),
        "the warning must name the exposure: {out}"
    );
}
