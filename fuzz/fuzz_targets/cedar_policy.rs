//! Fuzz target: Cedar policy engine integration.
//!
//! Tests the Cedar policy conversion and authorization with arbitrary input.
//! The Cedar engine must handle malformed policies and requests gracefully.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_policy::{Policy, Request, load_yaml};

fn field(data: &[u8], start: usize, len: usize) -> Option<String> {
    let end = (start + len).min(data.len());
    if start >= data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Parse may fail on malformed YAML — must Err, never panic.
    let Ok(policy) = load_yaml(text) else {
        return;
    };
    if data.is_empty() {
        return;
    }
    // Test policy_to_cedar conversion
    #[cfg(feature = "cedar")]
    {
        let _ = toolcage_policy::policy_to_cedar(&policy);
    }
    // Test Cedar engine if available
    #[cfg(feature = "cedar")]
    {
        use toolcage_policy::{CedarConfig, CedarEngine};
        let config = CedarConfig {
            policy_files: vec![],
            entities_file: None,
            schema_file: None,
        };
        if let Ok(engine) = CedarEngine::new(&config) {
            let action = field(data, 0, 8).unwrap_or_else(|| "http.request".into());
            let host = field(data, 8, 16);
            let method = field(data, 24, 8);
            let path = field(data, 32, 24);
            let fs_path = field(data, 56, 24);
            let argv = if data.len() > 80 {
                Some(vec![field(data, 80, 16).unwrap_or_else(|| "/bin/sh".into())])
            } else {
                None
            };
            let req = Request {
                action,
                host,
                method,
                path,
                fs_path,
                argv,
            };
            let _ = engine.authorize(&req);
        }
    }
});