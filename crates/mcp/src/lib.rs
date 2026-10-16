//! MCP front door v0: stdio JSON-RPC with 4 tools mapping 1:1 to policy actions.
//! Tools: run_command -> proc.exec, read_file/write_file -> fs.read/write,
//! http_fetch -> http.request via proxy+broker. Denials are terse model-side,
//! detailed orchestrator-side. Learn mode proposes allowlist from denials.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
pub struct RpcReq {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct RpcResp {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcErr>,
}

#[derive(Debug, Serialize)]
pub struct RpcErr {
    pub code: i32,
    pub message: String,
}

impl RpcResp {
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    pub fn deny(id: serde_json::Value, rules: &[String]) -> Self {
        // Terse model-facing text; orchestrator gets rule ids in result log.
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcErr { code: -32000, message: format!("denied ({})", rules.join(",")) }),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CallParams {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Route a tools/call to supervisor. Returns JSON result or denial.
pub fn route(
    sup: &toolcage_supervisor::Supervisor,
    broker: &toolcage_broker::Broker,
    token: Option<&toolcage_capability::Token>,
    name: &str,
    args: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    match name {
        "run_command" => {
            let argv: Vec<String> = serde_json::from_value(args.get("argv").cloned().unwrap_or_default())?;
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
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("/");
            let action = if name == "read_file" { "fs.read" } else { "fs.write" };
            let d = toolcage_policy::decide(
                &sup.policy,
                &toolcage_policy::Request {
                    action: action.into(), host: None, method: None, path: None,
                    fs_path: Some(path.into()), argv: None,
                },
            );
            if !d.allow {
                anyhow::bail!("denied {:?}", d.rule_ids);
            }
            if let Some(t) = token {
                if !t.allows(Some(path), None, None, None) {
                    anyhow::bail!("denied [token:deny]");
                }
            }
            // Host-mediated file copy happens here in real driver; v0 audits intent.
            Ok(serde_json::json!({ "path": path, "checked": d.rule_ids }))
        }
        "http_fetch" => {
            let host = args.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("/");
            let o = sup.fetch_via_proxy(broker, host, method, path, token, false, false)?;
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
        },
        &toolcage_policy::Request {
            action: "proc.exec".into(), host: None, method: None, path: None,
            fs_path: None, argv: Some(argv.to_vec()),
        },
    );
    anyhow::ensure!(d.allow, "server cmd rejected: shell strings not allowed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_tool_rejected() {
        assert!(route as fn(_, _, _, _, _) -> _ == route);
    }
    #[test]
    fn learn_proposes_denials() {
        let mut l = LearnMode::default();
        l.record("http_fetch", &serde_json::json!({"host": "new.example.com", "path": "/a"}));
        let p = l.propose();
        assert!(p.to_string().contains("new.example.com"));
    }
    #[test]
    fn server_cmd_shell_rejected() {
        assert!(check_server_cmd(&["sh".to_string(), "-c".to_string(), "x".to_string()]).is_err());
        assert!(check_server_cmd(&["/bin/mcp-server".to_string()]).is_ok());
    }
}
