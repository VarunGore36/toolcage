//! Audit v0: JSONL hash chain + verify. hash = SHA256(prev_hash || canonical_json).
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts_wall: String,
    pub session: String,
    pub actor: String,
    pub action: String,
    pub request_hash: String,
    pub decision: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub token_rev_id: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default = "host_default")]
    pub claimed_by: String,
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
}

fn host_default() -> String {
    "host".into()
}

fn hex_encode(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{:02x}", x)).collect()
}

fn canonical(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

pub fn hash_for(prev_hash: &str, body: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(canonical(body));
    hex_encode(h.finalize())
}

fn event_body(e: &Event) -> serde_json::Value {
    serde_json::json!({
        "seq": e.seq, "ts_wall": e.ts_wall, "session": e.session,
        "actor": e.actor, "action": e.action, "request_hash": e.request_hash,
        "decision": e.decision, "rule_ids": e.rule_ids, "token_rev_id": e.token_rev_id,
        "result": e.result, "bytes": e.bytes, "claimed_by": e.claimed_by,
        "prev_hash": e.prev_hash,
    })
}

pub struct Writer {
    file: File,
    next_seq: u64,
    head: String,
}

impl Writer {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut next_seq = 0u64;
        let mut head = "GENESIS".to_string();
        if path.exists() {
            // Verify existing chain before appending: never extend a corrupt log.
            if std::fs::metadata(path)?.len() > 0 {
                let (n, h) = verify(path)?;
                next_seq = n;
                head = h;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, next_seq, head })
    }

    /// Write-ahead append: fsync before returning, so caller may act only after Ok.
    pub fn append(&mut self, mut e: Event) -> anyhow::Result<Event> {
        e.seq = self.next_seq;
        e.prev_hash = self.head.clone();
        let body = event_body(&e);
        e.hash = hash_for(&e.prev_hash, &body);
        let line = serde_json::to_string(&e)?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.next_seq += 1;
        self.head = e.hash.clone();
        Ok(e)
    }
}

pub fn verify(path: &Path) -> anyhow::Result<(u64, String)> {
    let f = File::open(path)?;
    let mut expect_prev = "GENESIS".to_string();
    let mut expect_seq = 0u64;
    let mut count = 0u64;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let e: Event = serde_json::from_str(&line)?;
        anyhow::ensure!(e.seq == expect_seq, "seq gap: got {} want {}", e.seq, expect_seq);
        anyhow::ensure!(e.prev_hash == expect_prev, "chain break at seq {}", e.seq);
        let recomputed = hash_for(&e.prev_hash, &event_body(&e));
        anyhow::ensure!(recomputed == e.hash, "hash mismatch at seq {}", e.seq);
        expect_prev = e.hash.clone();
        expect_seq += 1;
        count += 1;
    }
    Ok((count, expect_prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_mutation_detected() {
        let dir = std::env::temp_dir().join(format!("toolcage-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&p);
        let mut w = Writer::open(&p).unwrap();
        for i in 0..3 {
            w.append(Event {
                seq: 0, ts_wall: "2026-01-01T00:00:00Z".into(), session: "s1".into(),
                actor: "test".into(), action: format!("act{i}"), request_hash: "abc".into(),
                decision: "allow".into(), rule_ids: vec![], token_rev_id: "r".into(),
                result: "ok".into(), bytes: 0, claimed_by: "host".into(),
                prev_hash: String::new(), hash: String::new(),
            })
            .unwrap();
        }
        assert!(verify(&p).is_ok());
        // 1-byte mutation must fail
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.replace_range(10..11, "X");
        std::fs::write(&p, text).unwrap();
        assert!(verify(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
