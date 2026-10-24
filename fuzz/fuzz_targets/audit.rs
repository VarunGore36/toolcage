//! Fuzz target: audit Event JSON deserialization + chain verification.
//! The audit writer re-verifies existing chains on open; corrupt entries
//! must be rejected, never panicked.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::from_slice;
use std::path::PathBuf;
use toolcage_audit::Event;

// Fixed Ed25519 pubkey (32 bytes) used to pin checkpoint verification in the
// fuzz target. Any 32 bytes work as a key; the point is to exercise the
// verification code path, not to validate a real signature.
const PUBKEY_HEX: &str = "001122334455666778899aabbccddeeff001122334455666778899aabbccddeeff";

fn temp_log_path() -> PathBuf {
    std::env::temp_dir().join(format!("tc-fuzz-audit-{}.jsonl", std::process::id()))
}

fuzz_target!(|data: &[u8]| {
    // 1. Event JSON deserialization: every line must parse or Err, never panic.
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let _ = from_slice::<Event>(line.as_bytes());
    }

    // 2. Chain verification: the raw bytes themselves are a candidate audit
    // log. verify_with_pubkey must reject or Err on any input, never panic.
    let path = temp_log_path();
    let _ = std::fs::write(&path, data);
    let _ = toolcage_audit::verify_with_pubkey(&path, Some(&hex_decode(PUBKEY_HEX)));
    let _ = std::fs::remove_file(&path);
});

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
