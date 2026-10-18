//! Fuzz target: policy YAML parsing + decision engine.
//! Policy files are operator-controlled but decisions must be deterministic
//! and never panic on malformed input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_policy::{load_yaml, decide, Request};

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Parse may fail on malformed YAML — must Err, never panic.
    let Ok(policy) = load_yaml(text) else { return };
    // Exercise decide() with a range of request shapes.
    let _ = decide(
        &policy,
        &Request {
            action: "http.request".into(),
            host: Some("example.com".into()),
            method: Some("GET".into()),
            path: Some("/".into()),
            fs_path: None,
            argv: None,
        },
    );
    let _ = decide(
        &policy,
        &Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: Some(vec!["/bin/sh".into(), "-c".into(), "echo".into()]),
        },
    );
    let _ = decide(
        &policy,
        &Request {
            action: "fs.read".into(),
            host: None,
            method: None,
            path: None,
            fs_path: Some("/workspace/../../etc/passwd".into()),
            argv: None,
        },
    );
});
