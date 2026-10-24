//! Fuzz target: policy YAML parsing + decision engine.
//! Policy files are operator-controlled but decisions must be deterministic
//! and never panic on malformed input. Every field of the decision Request
//! (host, method, path, fs_path, argv) is drawn from the fuzz input so
//! hostile values exercise the decision engine, not just hardcoded ones.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_policy::{decide, load_yaml, Request};

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
    let _ = decide(
        &policy,
        &Request {
            action,
            host,
            method,
            path,
            fs_path,
            argv,
        },
    );
});
