//! Fuzz v0: hostile bytes must never panic, only deny/Err (runs every commit).
//! Continuous cargo-fuzz campaigns run nightly on real corpus.

#[test]
fn policy_never_panics_on_garbage() {
    for s in [
        "",
        "\0",
        "../..",
        "http://[::1",
        "A".repeat(8192).as_str(),
        "github\0evil",
    ] {
        let p = toolcage_policy::Policy {
            tool: "fuzz".into(),
            min_isolation: "tier0".into(),
            fs: Default::default(),
            net: Default::default(),
            credentials: vec![],
            approval: Default::default(),
            limits: Default::default(),
        };
        let _ = toolcage_policy::decide(
            &p,
            &toolcage_policy::Request {
                action: s.into(),
                host: Some(s.into()),
                method: Some(s.into()),
                path: Some(s.into()),
                fs_path: Some(s.into()),
                argv: None,
            },
        );
        let _ = toolcage_policy::canonical_path(s);
    }
}

#[test]
fn guest_protocol_never_panics() {
    for raw in ["", "{", "{\"op\":", "null", &"A".repeat(100000)] {
        let r: Result<toolcage_guest_agent::GuestMsg, _> = serde_json::from_str(raw);
        if let Ok(m) = r {
            let _ = toolcage_guest_agent::validate(&m);
        }
    }
}

#[test]
fn audit_verify_rejects_random_bytes() {
    let dir = std::env::temp_dir().join("tc-fuzz-audit");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("fuzz.jsonl");
    std::fs::write(&p, b"\x00\xffnot-json\n{\"seq\":999}\n").unwrap();
    assert!(toolcage_audit::verify(&p).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn proxy_never_allows_garbage() {
    let p = toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap();
    for h in [
        "",
        "\n",
        "..",
        "169.254.169.254.evil.com",
        &"x".repeat(5000),
    ] {
        let d = toolcage_proxy::decide(&p, h, "GET\x00", h);
        // Either deny, or allow only for exact allowlist match (never for garbage).
        if d.allow {
            assert!(
                h.eq_ignore_ascii_case("registry.npmjs.org")
                    || h.eq_ignore_ascii_case("github")
                    || h.to_ascii_lowercase().starts_with("github")
            );
        }
    }
}
