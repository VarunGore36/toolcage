#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_capability::{Key, Token};

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let key = Key::from_bytes(data[..32].try_into().unwrap());
    if let Ok(token) = serde_json::from_slice::<Token>(&data[32..]) {
        let _ = token.verify_tag(&key);
    }
});
