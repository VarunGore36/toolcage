//! Fuzz target: audit log event parsing and verification.
//!
//! Audit logs are append-only JSONL. Malformed lines must be rejected
//! without panicking, and hash chain verification must be deterministic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_audit::{Event, Writer, verify, hash_for, hash_event};

fn field(data: &[u8], start: usize, len: usize) -> Option<String> {
    let end = (start + len).min(data.len());
    if start >= data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

fn make_event(data: &[u8], seq: u64) -> Event {
    Event {
        seq,
        ts_wall: field(data, 0, 16).unwrap_or_else(|| "2026-01-01T00:00:00Z".into()),
        session: field(data, 16, 16).unwrap_or_else(|| "test".into()),
        actor: field(data, 32, 16).unwrap_or_else(|| "agent".into()),
        action: field(data, 48, 16).unwrap_or_else(|| "proc.exec".into()),
        request_hash: field(data, 64, 16).unwrap_or_else(|| "abc".into()),
        decision: field(data, 80, 8).unwrap_or_else(|| "allow".into()),
        rule_ids: vec![field(data, 88, 16).unwrap_or_else(|| "test".into())],
        token_rev_id: field(data, 104, 16).unwrap_or_else(|| "rev1".into()),
        result: field(data, 120, 16).unwrap_or_else(|| "ok".into()),
        bytes: data.len() as u64,
        claimed_by: "host".into(),
        prev_hash: String::new(),
        hash: String::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    
    // Test hash_event
    let event = make_event(data, 0);
    let _ = hash_event(&event);
    
    // Test hash_for
    let _ = hash_for("prev", &event);
    
    // Test Writer with in-memory buffer
    let dir = std::env::temp_dir().join(format!("tc-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&path);
    
    if let Ok(mut writer) = Writer::open(&path) {
        let mut event = make_event(data, 0);
        let _ = writer.append(event);
    }
    
    // Test verify (should handle malformed logs gracefully)
    let _ = verify(&path);
    
    let _ = std::fs::remove_dir_all(&dir);
});