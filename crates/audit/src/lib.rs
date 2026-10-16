//! Audit hash chain v0: hash = SHA256(prev_hash || canonical_json(event_without_hash)).
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub session: String,
    pub action: String,
    pub decision: String,
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
}

pub fn hash_event(prev_hash: &str, canonical: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(canonical);
    hex::encode(h.finalize())
}

// Minimal hex without extra dep
mod hex {
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{:02x}", x)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chain_changes_on_edit() {
        let h1 = hash_event("GENESIS", b"a");
        let h2 = hash_event("GENESIS", b"b");
        assert_ne!(h1, h2);
    }
}
