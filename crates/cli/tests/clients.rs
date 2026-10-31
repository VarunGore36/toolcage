//! Smoke tests for the shipped clients (M5: "Python and TypeScript
//! clients"). They wrap `toolcage-cli mcp call`, so the contract checked here
//! is the one users get: a clean call returns its JSON, a denied call raises
//! with the denial in the message.
//!
//! These use read_file (policy-checked, no sandbox needed) so they run on any
//! host — including CI runners where the Tier 0 cage is unavailable. Each
//! skips loudly if its runtime is missing.

use std::process::Command;

fn cli() -> &'static str {
    env!("CARGO_BIN_EXE_toolcage-cli")
}
fn policy() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/policy-v0.yaml")
        .display()
        .to_string()
}

#[test]
fn python_client_allows_and_denies() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skip: python3 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tc-client-py-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let audit = dir.join("a.jsonl");
    let client =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../clients/python/toolcage.py");
    let driver = format!(
        r#"
import sys
sys.path.insert(0, {client_dir:?})
from toolcage import Toolcage
tc = Toolcage({policy:?}, {audit:?}, {bin:?})
out = tc.call("read_file", {{"path": "/workspace/x"}})
assert out["path"] == "/workspace/x", out
assert out["checked"], out
try:
    tc.call("read_file", {{"path": "/etc/passwd"}})
except PermissionError as e:
    assert "denied" in str(e).lower(), e
else:
    raise AssertionError("reading /etc/passwd must raise PermissionError")
print("ok")
"#,
        client_dir = client.parent().unwrap().display().to_string(),
        policy = policy(),
        audit = audit.display().to_string(),
        bin = cli(),
    );
    let out = Command::new("python3")
        .args(["-c", &driver])
        .output()
        .expect("python runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("ok"),
        "python client smoke failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ts_client_allows_and_denies() {
    // Node >= 22.6 runs .ts via type stripping; deno also works. Skip if
    // neither is present.
    let runner: Vec<String> = if Command::new("node").arg("--version").output().is_ok() {
        vec!["node".into()]
    } else if Command::new("deno").arg("--version").output().is_ok() {
        vec![
            "deno".into(),
            "run".into(),
            "--allow-run".into(),
            "--allow-read".into(),
        ]
    } else {
        eprintln!("skip: neither node nor deno installed");
        return;
    };
    let dir = std::env::temp_dir().join(format!("tc-client-ts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let audit = dir.join("a.jsonl");
    let client =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../clients/ts/toolcage.ts");
    let driver = dir.join("driver.mts");
    std::fs::write(
        &driver,
        format!(
            r#"
import {{ Toolcage }} from "{client}";
const tc = new Toolcage({policy:?}, {audit:?}, {bin:?});
const out = tc.call("read_file", {{ path: "/workspace/x" }}) as {{ path: string; checked: string[] }};
if (out.path !== "/workspace/x" || !out.checked) throw new Error(JSON.stringify(out));
let denied = false;
try {{ tc.call("read_file", {{ path: "/etc/passwd" }}); }} catch (e) {{ denied = true; }}
if (!denied) throw new Error("reading /etc/passwd must throw");
console.log("ok");
"#,
            client = client.display().to_string(),
            policy = policy(),
            audit = audit.display().to_string(),
            bin = cli(),
        ),
    )
    .unwrap();
    let out = Command::new(&runner[0])
        .args(&runner[1..])
        .arg(&driver)
        .output()
        .expect("ts runner runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("ok"),
        "ts client smoke failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
