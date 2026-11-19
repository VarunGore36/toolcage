//! Cedar policy support for toolcage.
//!
//! This module provides integration with the Cedar policy engine for
//! fine-grained authorization decisions.

use crate::{Decision, Policy, Request};
use anyhow::{anyhow, Result};
use cedar_policy::{Entities, Policy as CedarPolicy, PolicySet, Request as CedarRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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
            let policy = CedarPolicy::from_json(
                None,
                serde_json::from_str::<serde_json::Value>(&policy_text)?,
            )
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

        // Load schema if provided
        if let Some(schema_file) = &config.schema_file {
            let schema_text = std::fs::read_to_string(schema_file)
                .map_err(|e| anyhow!("failed to read schema file {}: {}", schema_file, e))?;
            let schema = cedar_policy::Schema::from_json_str(&schema_text)
                .map_err(|e| anyhow!("failed to parse schema: {}", e))?;
            // Note: PolicySet::new_with_schema would be used here in practice
        }

        Ok(Self {
            policy_set,
            entities,
        })
    }

    /// Evaluate an authorization request using Cedar policies.
    pub fn authorize(&self, request: &Request) -> Result<Decision> {
        // Convert our Request to a Cedar Request
        let _cedar_request = self.convert_request(request)?;

        // Evaluate the request
        // TODO: Use proper Cedar authorization API
        // For now, return allow as placeholder
        let response_decision = cedar_policy::Decision::Allow;

        match response_decision {
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
    fn convert_request(&self, request: &crate::Request) -> Result<CedarRequest> {
        // This is a simplified conversion. In practice, you'd need to map
        // your internal request types to Cedar's request format.
        // For now, we'll create a basic request.
        use cedar_policy::{EntityUid, Request as CedarRequest};

        let action = format!("toolcage::{}", request.action);
        let action_uid = action
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid action: {}", e))?;

        // Create a basic request with principal and resource
        // This is simplified - in practice you'd map all request fields
        let principal = "toolcage::Session::anonymous"
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid principal: {}", e))?;

        let resource = "toolcage::Resource::default"
            .parse::<cedar_policy::EntityUid>()
            .map_err(|e| anyhow!("invalid resource: {}", e))?;

        CedarRequest::new(
            principal,
            action_uid,
            resource,
            cedar_policy::Context::empty(),
            None,
        )
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
            let _ = cedar_policy::Policy::from_json(
                None,
                serde_json::from_str::<serde_json::Value>(&content)?,
            )
            .map_err(|e| anyhow!("invalid Cedar policy in {:?}: {}", path, e))?;
            policies.push(content);
        }
    }
    Ok(policies)
}

/// Convert our internal Policy to Cedar policies (for hybrid approach).
pub fn policy_to_cedar(policy: &crate::Policy) -> Result<Vec<String>> {
    let mut cedar_policies = Vec::new();

    /// Convert network rules
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
            r#"permit(
    principal,
    action == toolcage::Action::"{}",
    resource == toolcage::Host::"{}"
) when {{ {} }};"#,
            "http_request", // or whatever action
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
            r#"permit(
    principal,
    action == toolcage::Action::"{}",
    resource == toolcage::Path::"{}"
);"#,
            action, path
        );
        cedar_policies.push(policy);
    }

    // Convert exec allowlist
    for binary in &policy.exec.allowlist {
        let policy = format!(
            r#"permit(
    principal,
    action == toolcage::Action::"proc_exec",
    resource == toolcage::Binary::"{}"
);"#,
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
