//! Escape suite v1 (I1/I6): every exfil path must be denied + audited at Tier0.
//! Real KVM tests run nightly; these run every commit without privs.
use toolcage_policy as policy;

fn sample() -> policy::Policy {
    policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
}

fn net(host: &str) -> policy::Request {
    policy::Request { action: "http.request".into(), host: Some(host.into()), method: Some("GET".into()), path: Some("/".into()), fs_path: None, argv: None }
}

#[test]
fn raw_exfil_paths_blocked() {
    let p = sample();
    // Raw/packet/DNS/ICMP/IPv6/metadata have no proxy path -> default deny.
    for h in [
        "169.254.169.254",
        "metadata.google.internal",
        "instance-data",
        "evil.example.com",
        "dns-tunnel.example.com",
    ] {
        let d = policy::decide(&p, &net(h));
        assert!(!d.allow, "{h} must be denied");
    }
}

#[test]
fn proxy_alias_cannot_smuggle_host() {
    // Guest asking for alias "github" with evil path must still be path-checked.
    let p = sample();
    let d = policy::decide(
        &p,
        &policy::Request { action: "http.request".into(), host: Some("github".into()), method: Some("POST".into()), path: Some("/repos/evil/x".into()), fs_path: None, argv: None },
    );
    assert!(!d.allow);
}

#[test]
fn shell_escape_blocked() {
    let p = sample();
    for argv in [
        vec!["sh".to_string(), "-c".to_string(), "id".to_string()],
        vec!["/bin/bash".to_string(), "-lc".to_string(), "id".to_string()],
    ] {
        let d = policy::decide(
            &p,
            &policy::Request { action: "proc.exec".into(), host: None, method: None, path: None, fs_path: None, argv: Some(argv) },
        );
        assert!(!d.allow);
    }
}
