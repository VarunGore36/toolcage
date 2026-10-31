//! Capability token gate in Supervisor::fetch_via_proxy.
//!
//! Bug: the whole token check (rights + revocation) lived inside
//! `if let Some(t) = token`, so a call with `token: None` ran with policy-only
//! rights even when `cap_key` was armed — and skipped revocation entirely. A
//! caller could drop the token to escape attenuation. The MCP front door had
//! this fixed; the supervisor's own enforcement point did not.
//!
//! These tests use `egress_bytes: 1` so any request that gets *past* the token
//! gate is denied at the budget pre-charge instead of dialing the network —
//! the rule id is the oracle for "which gate rejected it".

use toolcage_supervisor::Supervisor;

const POLICY: &str = r#"
tool: token-gate-test
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
limits:
  egress_bytes: 1
"#;

fn sup_at(audit: &std::path::Path, cap_key: Option<toolcage_capability::Key>) -> Supervisor {
    Supervisor {
        policy: toolcage_policy::load_yaml(POLICY).unwrap(),
        audit_path: audit.to_path_buf(),
        session: "tokgate".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key,
    }
}

fn key() -> toolcage_capability::Key {
    toolcage_capability::Key::from_hex(&"ab".repeat(32)).unwrap()
}

fn fetch(
    sup: &mut Supervisor,
    token: Option<&toolcage_capability::Token>,
    rl: &toolcage_capability::RevocationList,
) -> toolcage_supervisor::FetchOutcome {
    let b = toolcage_broker::Broker::new();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    sup.fetch_via_proxy(
        &b,
        &mut budgets,
        &mut proxy,
        "github",
        "GET",
        "/x",
        token,
        rl,
        false,
    )
    .unwrap()
}

#[test]
fn missing_token_denied_when_cap_key_armed() {
    // Dual-auth: with a capability key armed, dropping the token must NOT fall
    // back to policy-only rights (that would make attenuation advisory).
    let dir = std::env::temp_dir().join(format!(
        "tc-tokgate-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let mut sup = sup_at(&audit, Some(key()));
    let rl = toolcage_capability::RevocationList::default();
    let o = fetch(&mut sup, None, &rl);
    assert!(!o.allowed, "no token with a key armed must be denied");
    assert_eq!(
        o.rule_ids,
        vec!["token:missing".to_string()],
        "must be denied by the token gate, not some later gate: {:?}",
        o.rule_ids
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_token_passes_the_gate_when_cap_key_armed() {
    // A valid, allowed token must get past the token gate (it is then stopped
    // at the 1-byte egress budget — proving the gate did not block it).
    let dir = std::env::temp_dir().join(format!(
        "tc-tokgate-ok-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let k = key();
    let tok = toolcage_capability::Token::root(
        &k,
        "root-1",
        toolcage_capability::Rights {
            fs_prefixes: vec![],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 0,
            expires_at: 0,
        },
    )
    .unwrap();
    let mut sup = sup_at(&audit, Some(k.clone()));
    let rl = toolcage_capability::RevocationList::default();
    let o = fetch(&mut sup, Some(&tok), &rl);
    assert_eq!(
        o.rule_ids,
        vec!["budget:exceeded".to_string()],
        "a valid token must clear the token gate and reach the budget check: {:?}",
        o.rule_ids
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_identity_recorded_in_audit_events() {
    // The proxy-intent / proxy-error / allow events hardcoded
    // token_rev_id: "root", so the audit log could not attribute an *allowed*
    // request to the token that authorized it (the deny paths recorded it
    // correctly). Exactly the forensics revocation needs.
    let dir = std::env::temp_dir().join(format!(
        "tc-tokgate-rev-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let k = key();
    let tok = toolcage_capability::Token::root(
        &k,
        "root-42",
        toolcage_capability::Rights {
            fs_prefixes: vec![],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 0,
            expires_at: 0,
        },
    )
    .unwrap();
    let mut sup = sup_at(&audit, Some(k));
    let rl = toolcage_capability::RevocationList::default();
    let _ = fetch(&mut sup, Some(&tok), &rl);
    let text = std::fs::read_to_string(&audit).unwrap();
    let events: Vec<serde_json::Value> = text.lines().filter_map(|l| l.parse().ok()).collect();
    // The proxy-intent event (written before the action) must name the token.
    let intent = events
        .iter()
        .find(|v| v["result"] == "proxy-intent")
        .expect("a proxy-intent event is written");
    assert_eq!(
        intent["token_rev_id"], "root-42",
        "the intent event must attribute the request to the token"
    );
    // And no event may carry the old hardcoded "root" placeholder.
    assert!(
        !events.iter().any(|v| v["token_rev_id"] == "root"),
        "no event may hardcode token_rev_id root: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_only_when_no_cap_key_armed() {
    // No capability key = no capability system to enforce; policy is the only
    // gate and tokenless calls work (back-compat).
    let dir = std::env::temp_dir().join(format!(
        "tc-tokgate-pure-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let mut sup = sup_at(&audit, None);
    let rl = toolcage_capability::RevocationList::default();
    let o = fetch(&mut sup, None, &rl);
    assert_eq!(
        o.rule_ids,
        vec!["budget:exceeded".to_string()],
        "with no key armed a tokenless call must reach the budget check: {:?}",
        o.rule_ids
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same as POLICY but binds a credential to the `github` destination, so the
/// request would carry `Authorization: Bearer ...` upstream.
const POLICY_WITH_CRED: &str = r#"
tool: token-gate-cred-test
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
credentials:
  - name: github_token
    use_with: github
limits:
  egress_bytes: 1
"#;

fn fetch_cred(
    sup: &mut Supervisor,
    token: Option<&toolcage_capability::Token>,
    rl: &toolcage_capability::RevocationList,
) -> toolcage_supervisor::FetchOutcome {
    let b = toolcage_broker::Broker::new();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    sup.fetch_via_proxy(
        &b,
        &mut budgets,
        &mut proxy,
        "github",
        "GET",
        "/x",
        token,
        rl,
        false,
    )
    .unwrap()
}

#[test]
fn cred_use_axis_is_enforced_on_credential_attachment() {
    // Bug: the token check passed `cred` as None, so the `cred_use` rights
    // axis was never consulted — a token attenuated to `cred_use: []` ("must
    // not use any credential") still got `github_token` attached upstream.
    // The axis must gate the attachment: a request that would carry a
    // credential the token may not use is denied.
    let dir = std::env::temp_dir().join(format!(
        "tc-tokgate-cred-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("audit.jsonl");
    let k = key();
    let rl = toolcage_capability::RevocationList::default();

    // Token narrowed to use NO credentials -> the credential-bearing request
    // must be denied at the token gate.
    let none_allowed = toolcage_capability::Token::root(
        &k,
        "root-cred-none",
        toolcage_capability::Rights {
            fs_prefixes: vec![],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 0,
            expires_at: 0,
        },
    )
    .unwrap();
    let mut sup = Supervisor {
        policy: toolcage_policy::load_yaml(POLICY_WITH_CRED).unwrap(),
        audit_path: audit.clone(),
        session: "tokgate-cred".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: Some(k.clone()),
    };
    let o = fetch_cred(&mut sup, Some(&none_allowed), &rl);
    assert_eq!(
        o.rule_ids,
        vec!["token:deny".to_string()],
        "cred_use: [] must forbid the github_token credential: {:?}",
        o.rule_ids
    );

    // Token narrowed to use exactly that credential -> passes the gate and
    // reaches the budget check.
    let ok_tok = toolcage_capability::Token::root(
        &k,
        "root-cred-ok",
        toolcage_capability::Rights {
            fs_prefixes: vec![],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec!["github_token".into()],
            budget_bytes: 0,
            expires_at: 0,
        },
    )
    .unwrap();
    let mut sup = Supervisor {
        policy: toolcage_policy::load_yaml(POLICY_WITH_CRED).unwrap(),
        audit_path: audit.clone(),
        session: "tokgate-cred2".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: Some(k.clone()),
    };
    let o = fetch_cred(&mut sup, Some(&ok_tok), &rl);
    assert_eq!(
        o.rule_ids,
        vec!["budget:exceeded".to_string()],
        "cred_use permitting github_token must clear the gate: {:?}",
        o.rule_ids
    );

    let _ = std::fs::remove_dir_all(&dir);
}
