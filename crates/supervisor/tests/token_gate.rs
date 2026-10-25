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
    );
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
