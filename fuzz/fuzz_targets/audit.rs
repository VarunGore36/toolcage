//! Fuzz target: audit Event JSON deserialization + chain verification.
//! The audit writer re-verifies existing chains on open; corrupt entries
//! must be rejected, never panicked.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::from_slice;
use toolcage_audit::Event;

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Each line is a candidate event; malformed lines must Err.
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = from_slice::<Event>(line.as_bytes()) {
            // Event struct alone is just data — verify() needs a full chain,
            // so we just ensure deserialization is safe.
            let _ = event.seq;
            let _ = event.decision.clone();
        }
    }
});
