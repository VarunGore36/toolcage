//! Fuzz target: proxy HTTP request/response handling.
//!
//! The proxy handles HTTP requests from the guest and forwards them upstream.
//! Malformed HTTP must be rejected cleanly, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_proxy::{Proxy, Budgets, decide};
use toolcage_policy::load_yaml;

fn field(data: &[u8], start: usize, len: usize) -> Option<String> {
    let end = (start + len).min(data.len());
    if start >= data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let _proxy = Proxy::new().unwrap();
    let mut budgets = Budgets::default();
    
    let host = field(data, 0, 16).unwrap_or_else(|| "example.com".into());
    let method = field(data, 16, 8).unwrap_or_else(|| "GET".into());
    let path = field(data, 24, 24).unwrap_or_else(|| "/".into());
    
    // Test proxy decision with a minimal policy
    let policy_text = r#"tool: fuzz
version: 0
net:
  mode: allowlist
  hosts:
    - host: example.com
      methods: [GET]
"#;
    let Ok(policy) = load_yaml(policy_text) else {
        return;
    };
    
    // Test proxy decision
    let _ = decide(&policy, &host, &method, &path);
    
    // Test budget operations
    let req_est = data.len() as u64 + 256;
    let _ = budgets.check(&host, req_est, u64::MAX, u64::MAX);
    let _ = budgets.check(&host, req_est, req_est, u64::MAX);
    let _ = budgets.used_bytes(&host);
});