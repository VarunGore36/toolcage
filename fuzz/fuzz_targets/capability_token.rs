//! Fuzz target: capability token parsing and verification.
//!
//! Tokens are untrusted guest input. Parsing, verification, and attenuation
//! must never panic on malformed input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_capability::{Key, Token, Rights, RevocationList};

fn field(data: &[u8], start: usize, len: usize) -> Option<String> {
    let end = (start + len).min(data.len());
    if start >= data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let key = Key::from_bytes(data[0..32].try_into().unwrap());
    let rl = RevocationList::default();
    
    // Try to parse a token from the rest of the data
    if data.len() > 32 {
        let token_data = &data[32..];
        if let Ok(token_json) = std::str::from_utf8(token_data) {
            if let Ok(token) = serde_json::from_str::<Token>(token_json) {
                // Test verification
                let _ = token.verify_tag(&key);
                let _ = token.allows(&key, None, None, None, None);
                
                // Test attenuation
                let rights = Rights {
                    fs_prefixes: vec!["/workspace".into()],
                    net_hosts: vec!["example.com".into()],
                    methods: vec!["GET".into()],
                    cred_use: vec![],
                    budget_bytes: 1024,
                    expires_at: 9999999999,
                };
                let _ = token.attenuate(&key, "child", rights);
                
                // Test revocation
                let mut rl = RevocationList::default();
                rl.track(&token);
                rl.revoke(&token.rev_id);
                let _ = rl.is_revoked(&token);
            }
        }
    }
});