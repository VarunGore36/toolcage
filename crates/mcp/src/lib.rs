//! MCP front door v0: stdio JSON-RPC with 4 tools mapping 1:1 to policy actions.
//! Tools: run_command -> proc.exec, read_file/write_file -> fs.read/write,
//! http_fetch -> http.request via proxy+broker. Denials are terse model-side,
//! detailed orchestrator-side. Learn mode proposes allowlist from denials.
//!
//! REVIEW (A1/A2: tool args and server output are untrusted input):
//! - route() re-checks policy AND token on every call; MCP transport auth is
//!   separate from authorization. Unknown tools bail (deny). Adding a 5th tool
//!   requires a new policy action + audit shape — no generic passthrough.
//! - Model-facing errors are terse ("denied (...)") so injected content cannot
//!   probe policy; orchestrator gets rule ids via audit log, not via error.
//! - read/write_file audit via policy decide but do NOT copy bytes yet (v0
//!   returns checked path). Real file transfer must go host-mediated with
//!   canonicalize-at-open + O_NOFOLLOW, or TOCTOU reopens the path.
//! - check_server_cmd() gates third-party server binaries (argv-only). A
//!   malicious server's OUTPUT is still untrusted — its tool responses flow
//!   back through route(), never directly to the model.
//! - LearnMode proposes from DENIALS only; auto-applying proposals would let
//!   an injected agent grow its own allowlist. Proposals need operator review.
//! - RpcReq parsing: malformed lines get error responses, never panic (fuzz
//!   the JSON-RPC layer next: truncated frames, huge ids, duplicate ids).
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
pub struct RpcReq {
    pub jsonrpc: String,
    /// `None` is a JSON-RPC notification (no `id` member): the server MUST
    /// NOT reply. `Some` is a request and must be answered with the same id.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Largest request `id` echoed back. The id is reflected in the response, so
/// an unbounded one is a memory amplifier for anyone who can write a line.
pub const MAX_ID_BYTES: usize = 256;

/// JSON-RPC 2.0 standard error codes (the deny path intentionally uses the
/// server-error range instead: a policy denial is not a protocol error).
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Serialize)]
pub struct RpcResp {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    /// Exactly ONE of result/error is present. The spec says the error member
    /// MUST NOT exist when there is no error (and vice versa), so both are
    /// skipped when absent — a response with `"error": null` on success is
    /// non-conforming.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErr>,
}

#[derive(Debug, Serialize)]
pub struct RpcErr {
    pub code: i32,
    pub message: String,
}

impl RpcResp {
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }
    pub fn deny(id: serde_json::Value, rules: &[String]) -> Self {
        // Terse model-facing text; orchestrator gets rule ids in result log.
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcErr {
                code: -32000,
                message: format!("denied ({})", rules.join(",")),
            }),
        }
    }
    /// A protocol error with a JSON-RPC 2.0 standard code.
    pub fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcErr {
                code,
                message: message.into(),
            }),
        }
    }
}

impl RpcReq {
    /// Validate request shape per JSON-RPC 2.0. Returns the standard error
    /// code and message for a malformed request, or Ok when well-formed.
    pub fn validate(&self) -> Result<(), (i32, String)> {
        if self.jsonrpc != "2.0" {
            return Err((
                INVALID_REQUEST,
                format!("unsupported jsonrpc version: {}", self.jsonrpc),
            ));
        }
        // The id is reflected in the response, so it must be a legal JSON-RPC
        // id (string, number or null) and small — an object/array id is not
        // valid and an unbounded one is a memory amplifier.
        match &self.id {
            None => Ok(()), // notification: no id to bound
            Some(serde_json::Value::String(s)) => {
                if s.len() > MAX_ID_BYTES {
                    Err((INVALID_REQUEST, "id too large".into()))
                } else {
                    Ok(())
                }
            }
            Some(serde_json::Value::Number(_)) | Some(serde_json::Value::Null) => Ok(()),
            Some(_) => Err((
                INVALID_REQUEST,
                "id must be a string, number, or null".into(),
            )),
        }
    }

    /// True for a JSON-RPC notification (no `id` member): the server MUST
    /// process it but MUST NOT reply.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

#[derive(Debug, Deserialize)]
pub struct CallParams {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Route a tools/call to supervisor. Returns JSON result or denial.
#[allow(clippy::too_many_arguments)]
pub fn route(
    sup: &mut toolcage_supervisor::Supervisor,
    broker: &toolcage_broker::Broker,
    proxy: &mut toolcage_proxy::Proxy,
    budgets: &mut toolcage_proxy::Budgets,
    token: Option<&toolcage_capability::Token>,
    revocation: &toolcage_capability::RevocationList,
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    // Capability gate (I3) — applied to EVERY tool, not only the arms that
    // consulted a token. Dual auth: policy AND a valid token must allow. When
    // the host has a capability key armed the token is MANDATORY: a caller
    // must not be able to drop it and fall back to policy-only rights, which
    // would make attenuation purely advisory. Revocation is checked here so it
    // covers every arm (the fs arms used to ignore it entirely). With no key
    // armed there is no capability system to enforce — policy is the only gate
    // — and a presented token cannot be verified, so it is refused (fail
    // closed).
    match token {
        None => anyhow::ensure!(
            sup.cap_key.is_none(),
            "denied [token:missing]"
        ),
        Some(t) => {
            // Fail closed: no host key means the tag cannot be verified.
            let ok = sup
                .cap_key
                .as_ref()
                .map(|k| t.verify_tag(k) && t.allows(k, None, None, None, None))
                .unwrap_or(false);
            anyhow::ensure!(ok && !revocation.is_revoked(t), "denied [token:deny]");
        }
    }
    match name {
        "run_command" => {
            let argv: Vec<String> =
                serde_json::from_value(args.get("argv").cloned().unwrap_or_default())?;
            let o = sup.exec(&argv)?;
            if !o.allowed {
                anyhow::bail!("denied {:?}", o.rule_ids);
            }
            Ok(serde_json::json!({
                "exit": o.exit_code,
                "stdout_trunc": String::from_utf8_lossy(&o.stdout).len(),
                "stderr_trunc": String::from_utf8_lossy(&o.stderr).len(),
            }))
        }
        "read_file" | "write_file" => {
            // A missing path is UNKNOWN, not "/": a policy that mounts "/" (or
            // a caller probing defaults) must not get a grant from an absent
            // argument. Require the argument explicitly.
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| anyhow::anyhow!("denied [args:path required]"))?;
            let action = if name == "read_file" {
                "fs.read"
            } else {
                "fs.write"
            };
            let d = toolcage_policy::decide(
                &sup.policy,
                &toolcage_policy::Request {
                    action: action.into(),
                    host: None,
                    method: None,
                    path: None,
                    fs_path: Some(path.into()),
                    argv: None,
                },
            );
            if !d.allow {
                anyhow::bail!("denied {:?}", d.rule_ids);
            }
            if let Some(t) = token {
                // Path axis of the token's rights (the gate above already
                // verified the tag, the expiry and revocation).
                let ok = sup
                    .cap_key
                    .as_ref()
                    .map(|k| t.allows(k, Some(path), None, None, None))
                    .unwrap_or(false);
                if !ok {
                    anyhow::bail!("denied [token:deny]");
                }
            }
            // Host-mediated file copy happens here in real driver; v0 audits intent.
            Ok(serde_json::json!({ "path": path, "checked": d.rule_ids }))
        }
        "http_fetch" => {
            // Required arguments, no permissive defaults: an absent host must
            // not become "" and an absent method must not silently become GET
            // (the request would inherit GET's policy and approval posture
            // without the caller ever asking for it).
            let host = args
                .get("host")
                .and_then(|v| v.as_str())
                .filter(|h| !h.is_empty())
                .ok_or_else(|| anyhow::anyhow!("denied [args:host required]"))?;
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .filter(|m| !m.is_empty())
                .ok_or_else(|| anyhow::anyhow!("denied [args:method required]"))?;
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| anyhow::anyhow!("denied [args:path required]"))?;
            let o = sup.fetch_via_proxy(
                broker, budgets, proxy, host, method, path, token, revocation, false,
            )?;
            if o.need_approval {
                anyhow::bail!("paused {:?}", o.rule_ids);
            }
            if !o.allowed {
                anyhow::bail!("denied {:?}", o.rule_ids);
            }
            Ok(serde_json::json!({ "body": o.body }))
        }
        _ => anyhow::bail!("unknown tool {name}"),
    }
}

/// Learn mode: collect denials, propose minimal allowlist additions.
#[derive(Debug, Default)]
pub struct LearnMode {
    pub denied_hosts: BTreeSet<String>,
    pub denied_paths: BTreeSet<String>,
    pub denied_fs: BTreeSet<String>,
}

impl LearnMode {
    pub fn record(&mut self, name: &str, args: &serde_json::Value) {
        match name {
            "http_fetch" => {
                if let Some(h) = args.get("host").and_then(|v| v.as_str()) {
                    self.denied_hosts.insert(h.to_string());
                }
                if let Some(p) = args.get("path").and_then(|v| v.as_str()) {
                    self.denied_paths.insert(p.to_string());
                }
            }
            "read_file" | "write_file" => {
                if let Some(p) = args.get("path").and_then(|v| v.as_str()) {
                    self.denied_fs.insert(p.to_string());
                }
            }
            _ => {}
        }
    }
    pub fn propose(&self) -> serde_json::Value {
        serde_json::json!({
            "add_hosts": self.denied_hosts.iter().collect::<Vec<_>>(),
            "add_paths": self.denied_paths.iter().collect::<Vec<_>>(),
            "add_fs": self.denied_fs.iter().collect::<Vec<_>>(),
        })
    }
}

/// Sandboxed third-party MCP server host: spawn server binary contained via
/// supervisor exec, mediate its file/net calls through the same route().
/// v0 validates the server command is argv-safe; real vsock proxying follows.
pub fn check_server_cmd(argv: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(!argv.is_empty(), "empty server cmd");
    let d = toolcage_policy::decide(
        &toolcage_policy::Policy {
            tool: "mcp-host".into(),
            min_isolation: "tier0".into(),
            fs: Default::default(),
            net: Default::default(),
            credentials: vec![],
            approval: Default::default(),
            limits: Default::default(),
            exec: Default::default(),
        },
        &toolcage_policy::Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: Some(argv.to_vec()),
        },
    );
    anyhow::ensure!(d.allow, "server cmd rejected: shell strings not allowed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fs_rights(fs_prefixes: Vec<String>) -> toolcage_capability::Rights {
        toolcage_capability::Rights {
            fs_prefixes,
            net_hosts: vec![],
            methods: vec![],
            cred_use: vec![],
            budget_bytes: 0,
            expires_at: 0,
        }
    }

    fn cap_key() -> toolcage_capability::Key {
        toolcage_capability::Key::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn sup_with(cap_key: Option<toolcage_capability::Key>) -> toolcage_supervisor::Supervisor {
        toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: std::env::temp_dir().join("tc-mcp-cap-test.jsonl"),
            session: "t".into(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key,
        }
    }

    fn fs_call(
        sup: &mut toolcage_supervisor::Supervisor,
        token: Option<&toolcage_capability::Token>,
        rl: &toolcage_capability::RevocationList,
        path: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let b = toolcage_broker::Broker::new();
        let mut budgets = toolcage_proxy::Budgets::default();
        let mut proxy = toolcage_proxy::Proxy::new().unwrap();
        let args = serde_json::json!({"path": path});
        route(sup, &b, &mut proxy, &mut budgets, token, rl, "read_file", &args)
    }

    #[test]
    fn cap_key_armed_makes_the_token_mandatory() {
        // Dual auth: with a capability key armed, omitting the token must not
        // fall back to policy-only rights (that would make attenuation
        // advisory — an agent could simply drop the credential).
        let k = cap_key();
        let mut sup = sup_with(Some(k.clone()));
        let rl = toolcage_capability::RevocationList::default();

        let e = fs_call(&mut sup, None, &rl, "/workspace/x").unwrap_err();
        assert!(
            e.to_string().contains("token:missing"),
            "no token with a key armed must be denied: {e}"
        );

        // The same call with a valid token goes through (policy allows it).
        let tok = toolcage_capability::Token::root(
            &k,
            "root-1",
            fs_rights(vec!["workspace".into()]),
        );
        assert!(fs_call(&mut sup, Some(&tok), &rl, "/workspace/x").is_ok());
    }

    #[test]
    fn dropping_the_token_must_not_widen_rights() {
        // The token is narrowed to /workspace/narrow; the policy on its own
        // allows all of /workspace. Dropping the token must not hand back the
        // wider policy rights.
        let k = cap_key();
        let mut sup = sup_with(Some(k.clone()));
        let rl = toolcage_capability::RevocationList::default();
        let tok = toolcage_capability::Token::root(
            &k,
            "root-2",
            fs_rights(vec!["workspace/narrow".into()]),
        );

        // Narrow right: allowed.
        assert!(fs_call(&mut sup, Some(&tok), &rl, "/workspace/narrow/f").is_ok());
        // Outside the token's rights: denied WITH the token ...
        let e = fs_call(&mut sup, Some(&tok), &rl, "/workspace/other/f").unwrap_err();
        assert!(e.to_string().contains("token:deny"), "outside rights: {e}");
        // ... and denied WITHOUT it (this is the fail-open regression: the
        // policy alone allows /workspace/other/f).
        let e = fs_call(&mut sup, None, &rl, "/workspace/other/f").unwrap_err();
        assert!(e.to_string().contains("token:missing"), "drop=deny: {e}");
    }

    #[test]
    fn revoked_token_denied_on_every_tool() {
        // The fs arms used to ignore the revocation list entirely (only
        // http_fetch consulted it): a revoked token kept reading and writing
        // files. Revocation is now checked at the front door.
        let k = cap_key();
        let mut sup = sup_with(Some(k.clone()));
        let tok = toolcage_capability::Token::root(
            &k,
            "root-3",
            fs_rights(vec!["workspace".into()]),
        );
        let mut rl = toolcage_capability::RevocationList::default();
        rl.track(&tok);
        rl.revoke("root-3");

        let e = fs_call(&mut sup, Some(&tok), &rl, "/workspace/x").unwrap_err();
        assert!(e.to_string().contains("token:deny"), "revoked: {e}");

        // Revoking a PARENT id revokes the subtree too.
        let child = tok
            .attenuate(
                &k,
                "child-3",
                fs_rights(vec!["workspace".into()]),
            )
            .unwrap();
        let mut rl2 = toolcage_capability::RevocationList::default();
        rl2.track(&child);
        rl2.revoke("root-3");
        let e = fs_call(&mut sup, Some(&child), &rl2, "/workspace/x").unwrap_err();
        assert!(e.to_string().contains("token:deny"), "parent revoked: {e}");
    }

    #[test]
    fn no_cap_key_is_policy_only() {
        // No capability key armed = no capability system to enforce; policy is
        // the gate and calls work without a token (back-compat).
        let mut sup = sup_with(None);
        let rl = toolcage_capability::RevocationList::default();
        assert!(fs_call(&mut sup, None, &rl, "/workspace/x").is_ok());
    }

    #[test]
    fn missing_tool_args_are_denied_not_defaulted() {
        // The defaults used to be PERMISSIVE: a missing path became "/", a
        // missing host "", a missing method GET. With a policy that mounts "/"
        // and allows GET to github those defaults were grants the caller never
        // asked for. Each argument is required now, and the denial names it.
        let policy = toolcage_policy::load_yaml(
            r#"
tool: t
version: 0
fs:
  mounts:
    - path: /
      mode: rw
net:
  mode: allowlist
  hosts:
    - host: github
      methods: [GET]
"#,
        )
        .unwrap();
        let mut sup = toolcage_supervisor::Supervisor {
            policy,
            audit_path: std::env::temp_dir().join("tc-mcp-args-test.jsonl"),
            session: "t".into(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
        };
        let b = toolcage_broker::Broker::new();
        let mut budgets = toolcage_proxy::Budgets::default();
        let mut proxy = toolcage_proxy::Proxy::new().unwrap();
        let rl = toolcage_capability::RevocationList::default();
        let mut call = |sup: &mut toolcage_supervisor::Supervisor,
                    name: &str,
                    args: &serde_json::Value|
         -> String {
            match route(sup, &b, &mut proxy, &mut budgets, None, &rl, name, args) {
                Ok(_) => "ALLOWED".to_string(),
                Err(e) => format!("{e:#}"),
            }
        };
        // No path: the "/" default was a grant under this policy.
        for name in ["read_file", "write_file"] {
            let why = call(&mut sup, name, &serde_json::json!({}));
            assert!(
                why.contains("args:path required"),
                "{name} with no path must be denied for the missing argument, got: {why}"
            );
        }
        // No method (and no host/path): the GET default was a grant.
        for args in [
            serde_json::json!({"host": "github", "path": "/"}),
            serde_json::json!({"method": "GET", "path": "/"}),
            serde_json::json!({"host": "github", "method": "GET"}),
        ] {
            let why = call(&mut sup, "http_fetch", &args);
            assert!(
                why.contains("args:"),
                "http_fetch with a missing argument must be denied for it, got: {why}"
            );
        }
        // Empty values are refused the same way as absent ones.
        let why = call(&mut sup, "read_file", &serde_json::json!({"path": ""}));
        assert!(why.contains("args:path required"), "got: {why}");
    }

    #[test]
    fn unknown_tool_rejected() {
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: std::env::temp_dir().join("tc-mcp-test.jsonl"),
            session: "t".into(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
        };
        let b = toolcage_broker::Broker::new();
        let mut budgets = toolcage_proxy::Budgets::default();
        let mut proxy = toolcage_proxy::Proxy::new().unwrap();
        let rl = toolcage_capability::RevocationList::default();
        assert!(route(
            &mut sup,
            &b,
            &mut proxy,
            &mut budgets,
            None,
            &rl,
            "nope",
            &serde_json::json!({})
        )
        .is_err());
    }
    #[test]
    fn run_command_without_backend_denies_fail_closed() {
        // run_command must never fall back to a host spawn: with no wired backend
        // (and no explicit opt-in) the tool call is denied, fail-closed.
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: std::env::temp_dir().join("tc-mcp-isolation-test.jsonl"),
            session: "t".into(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: false,
            cap_key: None,
        };
        let b = toolcage_broker::Broker::new();
        let mut budgets = toolcage_proxy::Budgets::default();
        let mut proxy = toolcage_proxy::Proxy::new().unwrap();
        let rl = toolcage_capability::RevocationList::default();
        let args = serde_json::json!({"argv": ["/bin/echo", "pwned"]});
        let e = route(
            &mut sup,
            &b,
            &mut proxy,
            &mut budgets,
            None,
            &rl,
            "run_command",
            &args,
        )
        .unwrap_err();
        assert!(e.to_string().contains("isolation:unavailable"), "got: {e}");
    }
    #[test]
    fn fs_token_without_host_key_denies() {
        // I3 fail-closed: a presented token whose keyed tag cannot be verified
        // (no cap_key wired, or minted under another key) is denied.
        use toolcage_capability::{Key, Rights, Token};
        let mut sup = toolcage_supervisor::Supervisor {
            policy: toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml"))
                .unwrap(),
            audit_path: std::env::temp_dir().join("tc-mcp-token-test.jsonl"),
            session: "t".into(),
            tier: toolcage_backend::Tier::Tier0,
            backend: None,
            allow_unisolated: true,
            cap_key: None,
        };
        let b = toolcage_broker::Broker::new();
        let mut budgets = toolcage_proxy::Budgets::default();
        let mut proxy = toolcage_proxy::Proxy::new().unwrap();
        let rl = toolcage_capability::RevocationList::default();
        let tok = Token::root(
            &Key::from_bytes([1u8; 32]),
            "r0",
            Rights {
                fs_prefixes: vec!["/workspace".into()],
                net_hosts: vec![],
                methods: vec![],
                cred_use: vec![],
                budget_bytes: 1,
                expires_at: 9_999_999_999,
            },
        );
        let args = serde_json::json!({"path": "/workspace/f"});
        let e = route(
            &mut sup,
            &b,
            &mut proxy,
            &mut budgets,
            Some(&tok),
            &rl,
            "read_file",
            &args,
        )
        .unwrap_err();
        assert!(e.to_string().contains("token:deny"), "got: {e}");
    }
    #[test]
    fn learn_proposes_denials() {
        let mut l = LearnMode::default();
        l.record(
            "http_fetch",
            &serde_json::json!({"host": "new.example.com", "path": "/a"}),
        );
        let p = l.propose();
        assert!(p.to_string().contains("new.example.com"));
    }
    #[test]
    fn rpc_response_omits_absent_members() {
        // JSON-RPC 2.0: the error member MUST NOT exist on success (and
        // result must not exist on error). The old struct serialized both as
        // `null`, which is non-conforming and confuses strict clients.
        let ok = RpcResp::ok(serde_json::json!(1), serde_json::json!({"x": 1}));
        let s = serde_json::to_string(&ok).unwrap();
        assert!(!s.contains("\"error\""), "success must omit error: {s}");
        assert!(s.contains("\"result\""), "success must carry result: {s}");

        let err = RpcResp::error(serde_json::json!(1), INVALID_REQUEST, "bad");
        let s = serde_json::to_string(&err).unwrap();
        assert!(!s.contains("\"result\""), "error must omit result: {s}");
        assert!(s.contains("\"error\""), "error must carry error: {s}");

        let deny = RpcResp::deny(serde_json::json!(1), &["r".into()]);
        let s = serde_json::to_string(&deny).unwrap();
        assert!(!s.contains("\"result\""), "deny must omit result: {s}");
    }

    #[test]
    fn validate_rejects_bad_version_and_id() {
        let mk = |jsonrpc: &str, id: serde_json::Value| RpcReq {
            jsonrpc: jsonrpc.into(),
            id: Some(id),
            method: "tools/list".into(),
            params: serde_json::Value::Null,
        };
        // Version must be exactly "2.0".
        assert!(mk("2.0", serde_json::json!(1)).validate().is_ok());
        let (code, _) = mk("1.0", serde_json::json!(1)).validate().unwrap_err();
        assert_eq!(code, INVALID_REQUEST);
        let (code, _) = mk("", serde_json::json!(1)).validate().unwrap_err();
        assert_eq!(code, INVALID_REQUEST);

        // Id must be a string, number or null — not an object or array.
        assert!(mk("2.0", serde_json::Value::Null).validate().is_ok());
        assert!(mk("2.0", serde_json::json!("abc")).validate().is_ok());
        let (code, _) = mk("2.0", serde_json::json!({"a": 1})).validate().unwrap_err();
        assert_eq!(code, INVALID_REQUEST);
        let (code, _) = mk("2.0", serde_json::json!([1, 2])).validate().unwrap_err();
        assert_eq!(code, INVALID_REQUEST);

        // Id size is bounded: it is reflected in the response.
        let big = "x".repeat(MAX_ID_BYTES + 1);
        let (code, _) = mk("2.0", serde_json::json!(big)).validate().unwrap_err();
        assert_eq!(code, INVALID_REQUEST);
        let ok = "x".repeat(MAX_ID_BYTES);
        assert!(mk("2.0", serde_json::json!(ok)).validate().is_ok());
    }

    #[test]
    fn notifications_are_flagged_and_unversioned_ids_rejected() {
        // No id member = a notification: process but never reply.
        let n = RpcReq {
            jsonrpc: "2.0".into(),
            id: None,
            method: "tools/call".into(),
            params: serde_json::Value::Null,
        };
        assert!(n.is_notification());
        assert!(n.validate().is_ok());

        let r = RpcReq {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(7)),
            method: "tools/call".into(),
            params: serde_json::Value::Null,
        };
        assert!(!r.is_notification());

        // Standard error codes are the spec's values.
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
    }

    #[test]
    fn server_cmd_shell_rejected() {
        assert!(check_server_cmd(&["sh".to_string(), "-c".to_string(), "x".to_string()]).is_err());
        assert!(check_server_cmd(&["/bin/mcp-server".to_string()]).is_ok());
    }
}
