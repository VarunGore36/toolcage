//! Fuzz target: supervisor decision logic.
//!
//! The supervisor makes exec/fetch decisions based on policy and tokens.
//! All inputs are untrusted; decisions must be deterministic and never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use toolcage_supervisor::Supervisor;
use toolcage_policy::{Policy, Request, load_yaml};
use toolcage_approval::{Queue, Verdict};

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
    
    let Ok(policy) = load_yaml(text) else {
        return;
    };
    
    // Test supervisor check with various requests
    let dir = std::env::temp_dir().join(format!("tc-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let audit_path = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&audit_path);
    
    let mut sup = Supervisor {
        policy,
        audit_path: audit_path.clone(),
        session: "fuzz".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        cap_key: None,
        token_rev_id: String::default(),
        #[cfg(feature = "cedar")]
        cedar_engine: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
    };
    
    // Test proc.exec check
    let action = field(data, 0, 16).unwrap_or_else(|| "proc.exec".into());
    let host = field(data, 16, 16);
    let method = field(data, 32, 8);
    let path = field(data, 40, 24);
    let fs_path = field(data, 64, 24);
    let argv = if data.len() > 88 {
        Some(vec![field(data, 88, 16).unwrap_or_else(|| "/bin/true".into())])
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
    
    let _ = sup.check(&req);
    
    // Test approval queue
    let _ = sup.approval_queue.request("http.request", Some("github"), Some("POST"));
    let _ = sup.approval_queue.resolve("appr-1");
    let _ = sup.approval_queue.decide("appr-1", Verdict::Approve);
    let _ = sup.approval_queue.sweep_expired(1000, 60);
    
    let _ = std::fs::remove_dir_all(&dir);
});