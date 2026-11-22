use crate::{Decision, Request};
use anyhow::{anyhow, Result};
use cedar_policy::{Authorizer, Context, Entities, PolicySet};
use serde::{Deserialize, Serialize};

/// Cedar policy configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CedarConfig {
    /// Path to the Cedar policy file(s).
    pub policy_files: Vec<String>,
    /// Path to the Cedar entities file.
    pub entities_file: Option<String>,
    /// Cedar schema (optional).
    pub schema_file: Option<String>,
}

/// Cedar policy engine for evaluating authorization requests.
pub struct CedarEngine {
    authorizer: Authorizer,
    policy_set: PolicySet,
    entities: Entities,
}

impl CedarEngine {
    /// Create a new Cedar engine from configuration.
    pub fn new(config: &CedarConfig) -> Result<Self> {
        let mut policy_set = PolicySet::new();

        // Load policies
        for policy_file in &config.policy_files {
            let policy_text = std::fs::read_to_string(policy_file)
                .map_err(|e| anyhow!("failed to read policy file {}: {}", policy_file, e))?;
            let policy = cedar_policy::Policy::parse(None, &policy_text)
                .map_err(|e| anyhow!("failed to parse policy file {}: {}", policy_file, e))?;
            policy_set
                .add(policy)
                .map_err(|e| anyhow!("failed to add policy: {}", e))?;
        }

        // Load entities if provided
        let entities = if let Some(entities_file) = &config.entities_file {
            let entities_text = std::fs::read_to_string(entities_file)
                .map_err(|e| anyhow!("failed to read entities file {}: {}", entities_file, e))?;
            Entities::from_json_str(&entities_text, None)
                .map_err(|e| anyhow!("failed to parse entities: {}", e))?
        } else {
            Entities::empty()
        };

        let authorizer = Authorizer::new();

        Ok(Self {
            authorizer,
            policy_set,
            entities,
        })
    }

    /// Evaluate an authorization request using Cedar policies.
    pub fn authorize(&self, request: &Request) -> Result<Decision> {
        // Convert our Request to a Cedar Request
        let cedar_request = self.convert_request(request)?;

        // Evaluate the request using Cedar's Authorizer
        let response =
            self.authorizer
                .is_authorized(&cedar_request, &self.policy_set, &self.entities);

        match response.decision() {
            cedar_policy::Decision::Allow => Ok(Decision {
                allow: true,
                rule_ids: vec!["cedar:allow".into()],
                reason: "Allowed by Cedar policy".into(),
            }),
            cedar_policy::Decision::Deny => Ok(Decision {
                allow: false,
                rule_ids: vec!["cedar:deny".into()],
                reason: "Denied by Cedar policy".into(),
            }),
        }
    }

    /// Convert our internal Request to a Cedar Request.
    fn convert_request(&self, request: &Request) -> Result<cedar_policy::Request> {
        // Map our internal request action to a Cedar action entity
        let action = format!("toolcage::{}", request.action);
        let action_uid = action
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid action: {}", e))?;

        // Map resource based on request type
        let resource_str = if let Some(fs_path) = &request.fs_path {
            format!("toolcage::Path::{}", fs_path)
        } else if let Some(host) = &request.host {
            format!("toolcage::Host::{}", host)
        } else if let Some(path) = &request.path {
            format!("toolcage::Path::{}", path)
        } else if let Some(argv) = &request.argv {
            if argv.is_empty() {
                return Err(anyhow!("empty argv"));
            }
            format!("toolcage::Binary::{}", argv[0])
        } else {
            return Err(anyhow!("no resource specified in request"));
        };

        let resource = resource_str
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid resource: {}", e))?;

        let principal = "toolcage::Session::default"
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid principal: {}", e))?;

        cedar_policy::Request::new(principal, action_uid, resource, Context::empty(), None)
            .map_err(|e| anyhow!("failed to create Cedar request: {}", e))
    }
}

/// Load Cedar policies from a directory.
pub fn load_cedar_policies<P: AsRef<std::path::Path>>(dir: P) -> Result<Vec<String>> {
    let mut policies = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("cedar") {
            let content = std::fs::read_to_string(&path)?;
            // Validate it's valid Cedar
            let _ = cedar_policy::Policy::parse(None, &content)
                .map_err(|e| anyhow!("invalid Cedar policy in {:?}: {}", path, e))?;
            policies.push(content);
        }
    }
    Ok(policies)
}

/// Convert our internal Policy to Cedar policies (for hybrid approach).
pub fn policy_to_cedar(policy: &crate::Policy) -> Result<Vec<String>> {
    let mut cedar_policies = Vec::new();

    // Convert network rules
    for host_rule in &policy.net.hosts {
        let mut conditions = Vec::new();
        if !host_rule.methods.is_empty() {
            let methods = host_rule
                .methods
                .iter()
                .map(|m| format!("\"{}\"", m))
                .collect::<Vec<_>>()
                .join(", ");
            conditions.push(format!("action.method in [{}]", methods));
        }
        if !host_rule.paths.is_empty() {
            let paths = host_rule
                .paths
                .iter()
                .map(|p| format!("\"{}\"", p))
                .collect::<Vec<_>>()
                .join(", ");
            conditions.push(format!("context.request.path in [{}]", paths));
        }

        let condition = if conditions.is_empty() {
            "true".to_string()
        } else {
            conditions.join(" && ")
        };

        let host_name = host_rule.host.as_deref().unwrap_or("");
        let policy = format!(
            "permit(\n    principal,\n    action == toolcage::Action::\"{}\",\n    resource == toolcage::Host::\"{}\"\n) when {{ {} }};",
            "http_request",
            host_name,
            condition
        );
        cedar_policies.push(policy);
    }

    // Convert filesystem rules
    for mount in &policy.fs.mounts {
        let mode = &mount.mode;
        let path = &mount.path;
        let action = if mode == "rw" { "fs_write" } else { "fs_read" };

        let policy = format!(
            "permit(\n    principal,\n    action == toolcage::Action::\"{}\",\n    resource == toolcage::Path::\"{}\"\n);",
            action, path
        );
        cedar_policies.push(policy);
    }

    // Convert exec allowlist
    for binary in &policy.exec.allowlist {
        let policy = format!(
            "permit(\n    principal,\n    action == toolcage::Action::\"proc_exec\",\n    resource == toolcage::Binary::\"{}\"\n);",
            binary
        );
        cedar_policies.push(policy);
    }

    Ok(cedar_policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cedar_config_default() {
        let config = CedarConfig::default();
        assert!(config.policy_files.is_empty());
        assert!(config.entities_file.is_none());
        assert!(config.schema_file.is_none());
    }
}
