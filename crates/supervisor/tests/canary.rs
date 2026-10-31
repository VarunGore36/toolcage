//! Canary tests for I2 (no secrets reach the guest) and I7 (cross-session isolation).
//! Replaces the vacuous skeleton that only asserted a string literal starts with
//! "secret:". These exercise real backend-ns isolation and broker scrubbing.
use toolcage_backend::{Backend, SessionSpec, Tier};
use toolcage_backend_ns::NsBackend;
use toolcage_broker::Broker;

fn ws_spec(id: &str, dir: &std::path::Path) -> SessionSpec {
    SessionSpec {
        id: id.into(),
        tier: Tier::Tier0,
        mem_mb: 0,
        workspace_mb: 0,
        workspace: dir.display().to_string(),
    }
}

fn ns_available() -> bool {
    NsBackend::probe().namespaces
}

#[test]
fn canary_secret_not_in_guest_environment() {
    // I2: env_clear must prevent host secrets from reaching the guest.
    // Plant a secret in THIS process's env, then exec /usr/bin/env inside a
    // namespaced session — the secret must not appear in the child's env.
    if !ns_available() {
        eprintln!("skip: unprivileged user namespaces unavailable");
        return;
    }
    std::env::set_var("TC_CANARY_SECRET", "hunter2-canary-do-not-leak");
    let dir = std::env::temp_dir().join(format!("tc-canary-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let spec = ws_spec("env-canary", &dir);
    let mut b = NsBackend::new();
    b.create(&spec).unwrap();
    let r = b
        .exec("env-canary", &["/usr/bin/env".into()], 30, 1024 * 1024)
        .unwrap();
    let output = String::from_utf8_lossy(&r.stdout);
    assert_eq!(r.exit_code, Some(0), "env exec failed: {output}");
    assert!(
        !output.contains("hunter2-canary-do-not-leak"),
        "secret leaked to guest env:\n{output}"
    );
    assert!(
        output.lines().any(|l| l.starts_with("PATH=")),
        "PATH must be present:\n{output}"
    );
    b.destroy("env-canary").unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("TC_CANARY_SECRET");
}

#[test]
fn canary_broker_scrub_redacts_secret() {
    // I2: broker.scrub() must remove known secret values from response bodies
    // before the guest sees them.
    let mut b = Broker::new();
    let canary = b.plant_canary("scrub_test");
    let body = format!("token={canary} and more {canary}");
    let scrubbed = b.scrub(&body);
    assert!(
        !scrubbed.contains(&canary),
        "canary not scrubbed: {scrubbed}"
    );
    assert!(scrubbed.contains("[REDACTED]"));
    // inject() must fail-closed for a mismatched destination: the secret never
    // goes to a host it isn't bound to.
    assert_eq!(
        b.inject(&canary, "evil.example.com", "GET", "/"),
        None,
        "inject allowed mismatched destination for canary secret"
    );
}

#[test]
fn canary_cross_session_isolation_after_teardown() {
    // I7: after session teardown (destroy), session state is unreachable.
    // Exec succeeds before destroy; fails after destroy.
    if !ns_available() {
        eprintln!("skip: unprivileged user namespaces unavailable");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tc-canary-session-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let spec = ws_spec("session-canary", &dir);
    let mut b = NsBackend::new();
    b.create(&spec).unwrap();
    // Session exists: exec works.
    let r1 = b
        .exec(
            "session-canary",
            &["/bin/echo".into(), "hello".into()],
            30,
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(r1.exit_code, Some(0), "pre-teardown exec failed");
    // Teardown.
    b.destroy("session-canary").unwrap();
    // After teardown: exec fails (session not created).
    let r2 = b.exec(
        "session-canary",
        &["/bin/echo".into(), "hello".into()],
        30,
        1024 * 1024,
    );
    assert!(r2.is_err(), "exec after destroy should fail, got {r2:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
