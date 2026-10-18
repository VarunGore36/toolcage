//! Fuzz target: guest-agent protocol.
//! GuestMsg is deserialized from untrusted JSON then validated.
//! Any panic or incorrect accept here is a supervisor parser bug.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::from_slice;
use toolcage_guest_agent::{validate, GuestMsg};

fuzz_target!(|data: &[u8]| {
    // Deserialize is fallible by design — bad JSON must Err, never panic.
    if let Ok(msg) = from_slice::<GuestMsg>(data) {
        // validate() must reject anything hostile without panicking.
        let _ = validate(&msg);
    }
});
