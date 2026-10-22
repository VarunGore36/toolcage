//! Destination identity: credential binding and approval gates must compare
//! *destinations*, not the guest's spelling of a hostname.
//!
//! Two regressions guarded here:
//! - the credential matched any host *starting with* "github", so
//!   `github.evil.com` carried the GitHub token;
//! - the approval gate was checked against the raw guest string while policy
//!   resolved aliases first, so a POST to `github.internal` (policy host:
//!   `github`) slipped past a gate written as `hosts: [github]`.
//!
//! Every case is network-free. The policy below sets `egress_bytes: 1`, so all
//! requests are denied at the pre-charge before any dial — and the pre-charge
//! audit event records the request-size estimate, which includes the
//! `Authorization` header exactly when a credential was attached. That is the
//! oracle for "did the secret travel?".

use toolcage_broker::{Broker, Credential};
use toolcage_supervisor::Supervisor;

/// Allows both the `github` alias and a look-alike host, gates POST to github,
/// and bounds egress to 1 byte so nothing is ever dialed.
const POLICY: &str = r#"
tool: destination-test
version: 0
min_isolation: tier0
fs:
  mounts:
    - path: /workspace
      mode: rw
      source: session-copy
net:
  mode: allowlist
  hosts:
    - alias: github
      methods: [GET, POST]
      paths: ["/**"]
    - host: github.evil.com
      methods: [GET, POST]
      paths: ["/**"]
credentials:
  - name: github_token
    use_with: github
limits:
  egress_bytes: 1
approval:
  require_for:
    - http.request: { methods: [POST], hosts: [github] }
"#;

const SECRET: &str = "s3cr3t-value-12345";

fn sup_at(audit: &std::path::Path) -> Supervisor {
    Supervisor {
        policy: toolcage_policy::load_yaml(POLICY).unwrap(),
        audit_path: audit.to_path_buf(),
        session: "dest".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
    }
}

fn broker() -> Broker {
    let mut b = Broker::new();
    b.insert(Credential {
        name: "github_token".into(),
        value: SECRET.into(),
        use_with: "github".into(),
        methods: vec![],
        paths: vec![],
        expires_at: None,
        encrypted_value: None,
    });
    b
}

/// `bytes` recorded by the most recent audit event (the pre-charge denial).
fn last_bytes(audit: &std::path::Path) -> u64 {
    let text = std::fs::read_to_string(audit).unwrap();
    let last = text.lines().last().expect("audit event");
    let v: serde_json::Value = serde_json::from_str(last).unwrap();
    v["bytes"].as_u64().unwrap()
}

#[test]
fn credential_follows_destination_not_prefix() {
    let dir = std::env::temp_dir().join(format!("tc-dest-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let s = sup_at(&audit);
    let b = broker();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    let rl = toolcage_capability::RevocationList::default();

    // Same method and path for both calls below, so the request-size estimate
    // differs by exactly the auth header when the credential is attached.
    let (method, path) = ("GET", "/repos/acme/app/x");

    // `github.internal` is an alias of the same destination as `github`
    // (one upstream): the credential travels.
    let o = s
        .fetch_via_proxy(
            &b, &mut budgets, &mut proxy, "github.internal", method, path, None, &rl, true,
        )
        .unwrap();
    assert!(!o.allowed, "1-byte budget must deny: {o:?}");
    assert_eq!(o.rule_ids, vec!["budget:exceeded".to_string()]);
    let with_cred = last_bytes(&audit);

    // `github.evil.com` is a different destination that merely looks similar.
    // Policy allows it, so this reaches credential binding — and must get
    // nothing.
    let o = s
        .fetch_via_proxy(
            &b, &mut budgets, &mut proxy, "github.evil.com", method, path, None, &rl, true,
        )
        .unwrap();
    assert!(!o.allowed, "1-byte budget must deny: {o:?}");
    assert_eq!(o.rule_ids, vec!["budget:exceeded".to_string()]);
    let without_cred = last_bytes(&audit);

    let header_len =
        ("Authorization".len() + 2 + format!("Bearer {SECRET}").len() + 2) as u64;
    assert_eq!(
        with_cred - without_cred,
        header_len,
        "the look-alike host must not carry the credential \
         (estimates: with={with_cred} without={without_cred})"
    );

    // And the plain alias behaves like its own alias spelling.
    let o = s
        .fetch_via_proxy(&b, &mut budgets, &mut proxy, "github", method, path, None, &rl, true)
        .unwrap();
    assert!(!o.allowed);
    assert_eq!(last_bytes(&audit), with_cred, "aliases share the binding");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn approval_gate_matches_destination_aliases() {
    let dir = std::env::temp_dir().join(format!("tc-dest-appr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let s = sup_at(&audit);
    let b = broker();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    let rl = toolcage_capability::RevocationList::default();

    // POST to the gated destination, spelled as the operator wrote it.
    let o = s
        .fetch_via_proxy(
            &b, &mut budgets, &mut proxy, "github", "POST", "/x", None, &rl, false,
        )
        .unwrap();
    assert!(o.need_approval, "POST to github must pause for approval: {o:?}");
    assert!(!o.allowed);

    // The same destination under its alias spelling must hit the same gate.
    let o = s
        .fetch_via_proxy(
            &b, &mut budgets, &mut proxy, "github.internal", "POST", "/x", None, &rl, false,
        )
        .unwrap();
    assert!(
        o.need_approval,
        "POST to github.internal is POST to github: must pause for approval: {o:?}"
    );
    assert!(!o.allowed);

    // Once approved it proceeds past the gate (and is stopped at the budget,
    // still without dialing).
    let o = s
        .fetch_via_proxy(
            &b, &mut budgets, &mut proxy, "github.internal", "POST", "/x", None, &rl, true,
        )
        .unwrap();
    assert!(!o.need_approval, "an approved call must not pause again: {o:?}");
    assert_eq!(o.rule_ids, vec!["budget:exceeded".to_string()]);

    // GET is not gated under either spelling: it reaches the budget check
    // (which denies it) rather than the approval gate.
    for host in ["github", "github.internal"] {
        let o = s
            .fetch_via_proxy(&b, &mut budgets, &mut proxy, host, "GET", "/x", None, &rl, false)
            .unwrap();
        assert!(!o.need_approval, "GET to {host} is not gated: {o:?}");
        assert_eq!(o.rule_ids, vec!["budget:exceeded".to_string()]);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
