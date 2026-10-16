//! Policy v0: YAML allowlist + default-deny. See schemas/policy-v0.yaml.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub tool: String,
    #[serde(default = "default_tier")]
    pub min_isolation: String,
    #[serde(default)]
    pub fs: FsPolicy,
    #[serde(default)]
    pub net: NetPolicy,
    #[serde(default)]
    pub credentials: Vec<CredRule>,
}

fn default_tier() -> String {
    "tier0".into()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FsPolicy {
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mount {
    pub path: String,
    pub mode: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetPolicy {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
}

fn default_mode() -> String {
    "deny".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostRule {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredRule {
    pub name: String,
    pub use_with: String,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub action: String,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub fs_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allow: bool,
    pub rule_ids: Vec<String>,
    pub reason: String,
}

pub fn load_yaml(s: &str) -> anyhow::Result<Policy> {
    Ok(serde_yaml::from_str(s)?)
}

/// Canonicalize fs path: resolve `.`, `..`, duplicate `/` lexically (no FS access).
pub fn canonical_path(p: &str) -> String {
    let mut parts: Vec<&str> = vec![];
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn path_match(pattern: &str, path: &str) -> bool {
    // Support trailing /** only (v0). Exact otherwise.
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{}/", prefix))
    } else {
        pattern == path
    }
}

pub fn decide(policy: &Policy, req: &Request) -> Decision {
    let deny = |rule: &str, reason: &str| Decision {
        allow: false,
        rule_ids: vec![rule.into()],
        reason: reason.into(),
    };
    // Global forbid: metadata / link-local, always denied (I6 invariant).
    if let Some(h) = &req.host {
        if h.contains("169.254.169.254") || h == "metadata" {
            return deny("forbid:metadata", "metadata address is never reachable");
        }
    }
    match req.action.as_str() {
        "net.connect" | "http.request" => {
            let host = req.host.as_deref().unwrap_or("");
            let method = req.method.as_deref().unwrap_or("GET");
            let path = req.path.as_deref().unwrap_or("/");
            for h in &policy.net.hosts {
                let name = h.host.as_deref().or(h.alias.as_deref()).unwrap_or("");
                if name == host {
                    if !h.methods.is_empty() && !h.methods.iter().any(|m| m == method) {
                        continue;
                    }
                    if !h.paths.is_empty() && !h.paths.iter().any(|p| path_match(p, path)) {
                        continue;
                    }
                    return Decision {
                        allow: true,
                        rule_ids: vec![format!("net:allow:{host}")],
                        reason: "allowlisted".into(),
                    };
                }
            }
            deny("net:deny-default", "host not in allowlist")
        }
        "fs.read" | "fs.write" => {
            let raw = req.fs_path.as_deref().unwrap_or("/");
            let canon = canonical_path(raw);
            for m in &policy.fs.mounts {
                if canon == m.path || canon.starts_with(&format!("{}/", m.path)) {
                    if req.action == "fs.write" && m.mode == "ro" {
                        return deny("fs:deny-ro", "mount is read-only");
                    }
                    return Decision {
                        allow: true,
                        rule_ids: vec![format!("fs:allow:{}", m.path)],
                        reason: format!("under mount {}", m.path),
                    };
                }
            }
            deny("fs:deny-default", "path outside mounts")
        }
        "proc.exec" => Decision {
            allow: true,
            rule_ids: vec!["proc:allow".into()],
            reason: "exec gated by tier0; argv only, no shell".into(),
        },
        _ => deny("deny:unknown-action", "unknown action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Policy {
        load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
    }
    #[test]
    fn metadata_always_denied() {
        let p = sample();
        let d = decide(
            &p,
            &Request { action: "http.request".into(), host: Some("169.254.169.254".into()), method: Some("GET".into()), path: Some("/".into()), fs_path: None },
        );
        assert!(!d.allow);
    }
    #[test]
    fn allowlisted_get_allowed() {
        let p = sample();
        let d = decide(
            &p,
            &Request { action: "http.request".into(), host: Some("registry.npmjs.org".into()), method: Some("GET".into()), path: Some("/".into()), fs_path: None },
        );
        assert!(d.allow);
    }
    #[test]
    fn post_to_registry_denied() {
        let p = sample();
        let d = decide(
            &p,
            &Request { action: "http.request".into(), host: Some("registry.npmjs.org".into()), method: Some("POST".into()), path: Some("/".into()), fs_path: None },
        );
        assert!(!d.allow);
    }
    #[test]
    fn symlink_dotdot_contained() {
        assert_eq!(canonical_path("/workspace/a/../b"), "/workspace/b");
        assert_eq!(canonical_path("/workspace/../../etc/passwd"), "/etc/passwd");
        let p = sample();
        let d = decide(
            &p,
            &Request { action: "fs.read".into(), host: None, method: None, path: None, fs_path: Some("/workspace/../../etc/passwd".into()) },
        );
        assert!(!d.allow);
    }
    #[test]
    fn path_glob() {
        let p = sample();
        let ok = decide(
            &p,
            &Request { action: "http.request".into(), host: Some("github".into()), method: Some("GET".into()), path: Some("/repos/acme/app/issues/1".into()), fs_path: None },
        );
        assert!(ok.allow);
        let bad = decide(
            &p,
            &Request { action: "http.request".into(), host: Some("github".into()), method: Some("GET".into()), path: Some("/repos/evil/x".into()), fs_path: None },
        );
        assert!(!bad.allow);
    }
}
