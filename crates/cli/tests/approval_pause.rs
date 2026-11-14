//! The approval pause contract: `fetch` and `mcp call` both exit **3** with a
//! "paused" message when a gate fires — distinguishable from a policy
//! denial's exit 2 — so operator scripts can tell "needs a human" from
//! "refused". `mcp call` used to collapse the pause into exit 2 with a
//! "denied:" prefix, making the two indistinguishable.

use std::process::Command;

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn mcp_call(name: &str, args_json: &str) -> Run {
    let dir = std::env::temp_dir().join(format!(
        "tc-approval-pause-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // No credentials section: nothing to bind, so the request reaches the
    // approval gate cleanly.
    let policy = dir.join("policy.yaml");
    std::fs::write(
        &policy,
        "tool: t\nversion: 0\nmin_isolation: tier0\nnet:\n  mode: allowlist\n  hosts:\n    - host: github\n      methods: [POST]\napproval:\n  require_for:\n    - http.request: { methods: [POST], hosts: [github] }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_toolcage-cli"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "mcp",
            "call",
            "--policy",
            policy.to_str().unwrap(),
            "--audit",
            dir.join("a.jsonl").to_str().unwrap(),
            "--name",
            name,
            "--args-json",
            args_json,
        ])
        .output()
        .expect("cli runs");
    let run = Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    run
}

#[test]
fn gated_request_pauses_with_exit_3() {
    let r = mcp_call(
        "http_fetch",
        r#"{"host":"github","method":"POST","path":"/repos/acme/app/issues/1"}"#,
    );
    assert_eq!(
        r.code,
        Some(3),
        "pause must exit 3: {}{}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("paused"),
        "pause must say 'paused': {}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("denied"),
        "pause must not be reported as a denial: {}",
        r.stderr
    );
}

#[test]
fn ungated_denial_still_exits_2() {
    // GET is not gated (known-wrong against the POST gate) and is denied by
    // the net allowlist — a denial, not a pause: exit 2, "denied" message.
    let r = mcp_call(
        "http_fetch",
        r#"{"host":"github","method":"GET","path":"/x"}"#,
    );
    assert_eq!(
        r.code,
        Some(2),
        "denial must exit 2: {}{}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("denied"),
        "denial says 'denied': {}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("paused"),
        "denial must not say 'paused': {}",
        r.stderr
    );
}

#[test]
fn unknown_host_denied_not_paused() {
    // A host not in the allowlist is denied (exit 2), not paused (exit 3),
    // even when approval would otherwise apply.
    let r = mcp_call(
        "http_fetch",
        r#"{"host":"evil.example.com","method":"POST","path":"/x"}"#,
    );
    assert_eq!(
        r.code,
        Some(2),
        "unknown host must be denied, not paused: {}{}",
        r.stdout,
        r.stderr
    );
    assert!(
        r.stderr.contains("denied"),
        "unknown host denial says 'denied': {}",
        r.stderr
    );
}
