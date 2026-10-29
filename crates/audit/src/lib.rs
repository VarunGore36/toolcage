//! Audit v0: JSONL hash chain + verify. hash = SHA256(prev_hash || canonical_json).
//!
//! REVIEW:
//! - Evidence, not debug: every decision/side-effect appends BEFORE the action
//!   (I4). If append fails, caller must NOT act. Writer opens with verify() so
//!   a corrupt log is never extended — a crash mid-write fails the next open.
//! - Chain: prev_hash links genesis->head; verify() re-hashes each body and
//!   checks seq continuity. Detects flip/delete/reorder/truncate. It does NOT
//!   detect deletion of the tail without an anchored checkpoint ( newest events
//!   have no successor yet) — external checkpoint anchoring closes that.
//! - No secrets: bodies hold hashes/ids (argv hash, cred: name), never values.
//!   Adding a field? Default to hash-or-id, never plaintext.
//! - fsync per append: slow (~hundreds/s) but crash-safe. Batch/group-commit
//!   only with a careful write-ahead protocol; never buffer intent in memory.
//! - Canonical JSON: serde_json field order follows the struct, so re-hash is
//!   deterministic today. Do not switch serializers without a schema version
//!   bump and migration test.
//! - Concurrency: one Writer per file. Multi-process appends interleave; use a
//!   single audit writer process + file lock before scaling writers.
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
        Ok(Self {
            file,
            next_seq,
            head,
        })
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
        anyhow::ensure!(
            e.seq == expect_seq,
            "seq gap: got {} want {}",
            e.seq,
            expect_seq
        );
        anyhow::ensure!(e.prev_hash == expect_prev, "chain break at seq {}", e.seq);
        let recomputed = hash_for(&e.prev_hash, &event_body(&e));
        anyhow::ensure!(recomputed == e.hash, "hash mismatch at seq {}", e.seq);
        expect_prev = e.hash.clone();
        expect_seq += 1;
        count += 1;
    }
    Ok((count, expect_prev))
}

// REVIEW: checkpoints bind (seq, head, time) with Ed25519. Key lives outside
// guest reach (OS keystore/HSM ideally). verify_with_pubkey() checks chain +
// every checkpoint sig; a valid chain with a BAD sig fails. Checkpoint files
// sit next to the log as `<log>.checkpoint.<seq>`; external anchoring (second
// machine / transparency log) closes tail-deletion. Secret key bytes are
// zeroized by callers after use; this module never persists keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub head_hash: String,
    pub time: String,
    pub sig_hex: String,
    pub pubkey_hex: String,
}

fn checkpoint_msg(seq: u64, head: &str, time: &str) -> Vec<u8> {
    format!("{seq}|{head}|{time}").into_bytes()
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let b = s.as_bytes();
    anyhow::ensure!(b.len().is_multiple_of(2), "odd hex");
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push((hex_val(b[i])? << 4) | hex_val(b[i + 1])?);
    }
    Ok(out)
}

/// Value of one ASCII hex digit. Operates on bytes, so multi-byte UTF-8
/// input (which the old &s[i..i+2] str slicing turned into a panic) is
/// rejected here with an error instead. A verification tool must refuse
/// bad input, never crash on it.
fn hex_val(c: u8) -> anyhow::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex digit"),
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Sign a checkpoint over the current head. sk_bytes must be 32 bytes.
pub fn sign_checkpoint(
    seq: u64,
    head: &str,
    time: &str,
    sk_bytes: &[u8],
) -> anyhow::Result<Checkpoint> {
    use ed25519_dalek::{Signer, SigningKey};
    anyhow::ensure!(sk_bytes.len() == 32, "sk must be 32 bytes");
    let sk = SigningKey::from_bytes(sk_bytes.try_into().unwrap());
    let msg = checkpoint_msg(seq, head, time);
    let sig = sk.sign(&msg);
    Ok(Checkpoint {
        seq,
        head_hash: head.into(),
        time: time.into(),
        sig_hex: hex_of(&sig.to_bytes()),
        pubkey_hex: hex_of(&sk.verifying_key().to_bytes()),
    })
}

/// Verify one checkpoint against a pinned pubkey (32 bytes).
pub fn verify_checkpoint(cp: &Checkpoint, pubkey: &[u8]) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    anyhow::ensure!(pubkey.len() == 32, "pubkey must be 32 bytes");
    let vk = VerifyingKey::from_bytes(pubkey.try_into().unwrap())?;
    let sig_bytes = hex_decode(&cp.sig_hex)?;
    let sig = Signature::from_slice(&sig_bytes)?;
    vk.verify(&checkpoint_msg(cp.seq, &cp.head_hash, &cp.time), &sig)?;
    anyhow::ensure!(
        cp.pubkey_hex == hex_of(pubkey),
        "checkpoint pubkey mismatch"
    );
    Ok(())
}

/// Verify chain + all sibling checkpoint files against pubkey (if given).
/// Without pubkey: chain only (back-compat). With pubkey: chain + every
/// `<log>.checkpoint.*` must verify AND its (seq, head) must match the chain
/// prefix at that seq. This binds old checkpoints: truncating the tail after
/// an old checkpoint fails because head(seq) != recorded head.
pub fn verify_with_pubkey(path: &Path, pubkey: Option<&[u8]>) -> anyhow::Result<(u64, String)> {
    let (n, head) = verify(path)?;
    if let Some(pk) = pubkey {
        // Replay chain to record head hash at each seq, so checkpoints bind.
        let mut heads: Vec<String> = Vec::new();
        {
            let f = File::open(path)?;
            let mut expect_prev = "GENESIS".to_string();
            for line in BufReader::new(f).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let e: Event = serde_json::from_str(&line)?;
                // verify() already checked continuity; recompute defensively.
                anyhow::ensure!(e.prev_hash == expect_prev, "chain break at seq {}", e.seq);
                expect_prev = e.hash.clone();
                heads.push(expect_prev.clone());
            }
        }
        let dir = match path.parent() {
            // parent() of a bare file name is Some(""), not None — that empty
            // component must be treated as the current directory, or
            // read_dir("") silently fails and every relative log path reports
            // "no checkpoint files found".
            Some(p) if p.as_os_str().is_empty() => Path::new("."),
            Some(p) => p,
            None => Path::new("."),
        };
        let stem = path.file_name().unwrap().to_string_lossy().to_string();
        let mut found = 0;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(&format!("{stem}.checkpoint.")) {
                    let cp: Checkpoint = serde_json::from_str(&std::fs::read_to_string(e.path())?)?;
                    verify_checkpoint(&cp, pk)?;
                    anyhow::ensure!(cp.seq <= n, "checkpoint seq beyond log");
                    // Bind (seq, head) to the actual chain prefix.
                    if cp.seq == 0 {
                        anyhow::ensure!(
                            cp.head_hash == "GENESIS",
                            "checkpoint head mismatch at seq 0"
                        );
                    } else {
                        let idx = (cp.seq - 1) as usize;
                        anyhow::ensure!(idx < heads.len(), "checkpoint seq beyond log");
                        anyhow::ensure!(
                            heads[idx] == cp.head_hash,
                            "checkpoint head mismatch at seq {}",
                            cp.seq
                        );
                    }
                    found += 1;
                }
            }
        }
        anyhow::ensure!(found > 0, "no checkpoint files found");
    }
    Ok((n, head))
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
                seq: 0,
                ts_wall: "2026-01-01T00:00:00Z".into(),
                session: "s1".into(),
                actor: "test".into(),
                action: format!("act{i}"),
                request_hash: "abc".into(),
                decision: "allow".into(),
                rule_ids: vec![],
                token_rev_id: "r".into(),
                result: "ok".into(),
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
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
    #[test]
    fn checkpoint_sign_verify_and_tamper_fails() {
        // REVIEW: deterministic test key (never production). Tampered sig/head
        // and wrong pubkey must all fail; valid chain + sig passes.
        let sk = [7u8; 32];
        let cp = sign_checkpoint(3, "abc123", "99", &sk).unwrap();
        let pk_hex = cp.pubkey_hex.clone();
        let mut pk = vec![0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&pk_hex[2 * i..2 * i + 2], 16).unwrap();
        }
        assert!(verify_checkpoint(&cp, &pk).is_ok());
        let mut bad = cp.clone();
        bad.head_hash = "zzz".into();
        assert!(verify_checkpoint(&bad, &pk).is_err());
        assert!(verify_checkpoint(&cp, &[9u8; 32]).is_err());
    }
    #[test]
    fn old_checkpoint_plus_truncated_tail_fails() {
        // I5: checkpoint at seq 2 must bind head(2). Truncate to 2 events after
        // checkpointing 3 -> old cp no longer matches -> verify_with_pubkey fails.
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("toolcage-audit-cp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&p);
        // Clean stale checkpoints for this log name.
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("audit.jsonl.checkpoint.") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let sk = [11u8; 32];
        let mut w = Writer::open(&p).unwrap();
        for i in 0..3 {
            w.append(Event {
                seq: 0,
                ts_wall: "2026-01-01T00:00:00Z".into(),
                session: "s1".into(),
                actor: "test".into(),
                action: format!("act{i}"),
                request_hash: "abc".into(),
                decision: "allow".into(),
                rule_ids: vec![],
                token_rev_id: "r".into(),
                result: "ok".into(),
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })
            .unwrap();
        }
        let (n, head) = verify(&p).unwrap();
        assert_eq!(n, 3);
        let cp = sign_checkpoint(n, &head, "99", &sk).unwrap();
        let pk = hex_decode(&cp.pubkey_hex).unwrap();
        let dest = dir.join(format!("audit.jsonl.checkpoint.{n}"));
        let mut f = std::fs::File::create(&dest).unwrap();
        f.write_all(serde_json::to_string(&cp).unwrap().as_bytes())
            .unwrap();
        assert!(verify_with_pubkey(&p, Some(&pk)).is_ok());
        // Attacker truncates last event but keeps old checkpoint file.
        let lines: Vec<String> = std::io::BufReader::new(std::fs::File::open(&p).unwrap())
            .lines()
            .map(|l| l.unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        // Chain alone looks valid (prefix), but pinned checkpoint head mismatches.
        assert!(verify(&p).is_ok());
        assert!(verify_with_pubkey(&p, Some(&pk)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn event_matches_schema_required_fields() {
        // Guard against schema/code drift: a serialized Event must contain every
        // field the schema marks required, and must NOT require ts_mono (nothing
        // emits it). Load the schema from the schemas/ directory.
        use serde_json::Value;
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/audit-event-v0.json"))
                .expect("audit-event-v0.json is valid JSON");
        let required = schema["required"]
            .as_array()
            .expect("schema has required array")
            .iter()
            .map(|v| v.as_str().expect("required entry is string").to_string())
            .collect::<Vec<_>>();
        // ts_mono is not emitted by any code path; it must not be required.
        assert!(
            !required.contains(&"ts_mono".to_string()),
            "ts_mono must not be required"
        );
        // deny-all is emitted by panic_freeze; it must be in the decision enum.
        let decision_enum = schema["properties"]["decision"]["enum"]
            .as_array()
            .expect("decision enum exists")
            .iter()
            .map(|v| v.as_str().expect("enum entry is string").to_string())
            .collect::<Vec<_>>();
        assert!(
            decision_enum.contains(&"deny-all".to_string()),
            "decision enum must include deny-all"
        );
        // Serialize a representative Event and check every required field present.
        let e = Event {
            seq: 0,
            ts_wall: "2026-01-01T00:00:00Z".into(),
            session: "s1".into(),
            actor: "test".into(),
            action: "act".into(),
            request_hash: "abc".into(),
            decision: "allow".into(),
            rule_ids: vec![],
            token_rev_id: "r".into(),
            result: "ok".into(),
            bytes: 0,
            claimed_by: "host".into(),
            prev_hash: "0".repeat(64),
            hash: "1".repeat(64),
        };
        let serialized = serde_json::to_value(&e).expect("event serializes");
        let obj = serialized.as_object().expect("event is object");
        for field in &required {
            assert!(
                obj.contains_key(field.as_str()),
                "serialized event missing required field: {field}"
            );
        }
    }

    #[test]
    fn garbage_hex_does_not_panic_verifier() {
        // hex_decode sliced &s[i..i+2] over a &str, which panics on multi-byte
        // UTF-8 input with an even byte length (e.g. an emoji). Decode now
        // operates on bytes and rejects anything that is not ASCII hex.
        assert!(hex_decode("😀").is_err()); // 4 bytes, even, slices mid-char
        assert!(hex_decode("zz").is_err()); // non-hex digits
        assert!(hex_decode("z").is_err());  // odd length
        assert_eq!(
            hex_decode("deadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        // A checkpoint sibling with garbage sig_hex must fail verification,
        // not crash: verify_with_pubkey parses every *.checkpoint.* file next
        // to the log. Plant one with a 4-byte emoji sig (even length -> the
        // old code panicked at &s[i..i+2]).
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("toolcage-audit-hex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&p);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("audit.jsonl.checkpoint.") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let sk = [7u8; 32];
        let cp = super::sign_checkpoint(3, "abc123", "99", &sk).unwrap();
        let pk_hex = cp.pubkey_hex.clone();
        let mut pk = vec![0u8; 32];
        for i in 0..32 {
            pk[i] = u8::from_str_radix(&pk_hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let mut bad = cp.clone();
        bad.sig_hex = "😀".into(); // valid length, not ASCII hex
        let mut f = std::fs::File::create(dir.join("audit.jsonl.checkpoint.3")).unwrap();
        f.write_all(serde_json::to_string(&bad).unwrap().as_bytes())
            .unwrap();
        // A valid three-event log (same shape as the other checkpoint tests),
        // so verification reaches the checkpoint scan.
        let mut w = super::Writer::open(&p).unwrap();
        for i in 0..3 {
            w.append(super::Event {
                seq: 0,
                ts_wall: "2026-01-01T00:00:00Z".into(),
                session: "s1".into(),
                actor: "test".into(),
                action: format!("act{i}"),
                request_hash: "abc".into(),
                decision: "allow".into(),
                rule_ids: vec![],
                token_rev_id: "r".into(),
                result: "ok".into(),
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })
            .unwrap();
        }
        assert!(verify(&p).is_ok());
        assert!(
            verify_with_pubkey(&p, Some(&pk)).is_err(),
            "garbage sig_hex must fail verification, not panic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_with_pubkey_works_for_relative_log_path() {
        // Bug: path.parent() of a bare file name is Some(""), not None, so
        // read_dir("") silently failed and every relative log path reported
        // "no checkpoint files found" even with valid checkpoints next to it.
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("toolcage-audit-rel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev_cwd = std::env::current_dir().unwrap();
        let _ = std::env::set_current_dir(&dir);
        let result = (|| -> anyhow::Result<()> {
            let p = Path::new("audit.jsonl");
            let _ = std::fs::remove_file(p);
            let sk = [11u8; 32];
            let mut w = super::Writer::open(p).unwrap();
            for i in 0..3 {
                w.append(super::Event {
                    seq: 0,
                    ts_wall: "2026-01-01T00:00:00Z".into(),
                    session: "s1".into(),
                    actor: "test".into(),
                    action: format!("act{i}"),
                    request_hash: "abc".into(),
                    decision: "allow".into(),
                    rule_ids: vec![],
                    token_rev_id: "r".into(),
                    result: "ok".into(),
                    bytes: 0,
                    claimed_by: "host".into(),
                    prev_hash: String::new(),
                    hash: String::new(),
                })
                .unwrap();
            }
            let (n, head) = super::verify(p).unwrap();
            assert_eq!(n, 3);
            let cp = super::sign_checkpoint(n, &head, "99", &sk).unwrap();
            let pk_hex = cp.pubkey_hex.clone();
            let mut pk = vec![0u8; 32];
            for i in 0..32 {
                pk[i] = u8::from_str_radix(&pk_hex[2 * i..2 * i + 2], 16).unwrap();
            }
            let dest = dir.join(format!("audit.jsonl.checkpoint.{n}"));
            let mut f = std::fs::File::create(&dest).unwrap();
            f.write_all(serde_json::to_string(&cp).unwrap().as_bytes())
                .unwrap();
            // Relative path: used to fail with "no checkpoint files found".
            super::verify_with_pubkey(p, Some(&pk))?;
            Ok(())
        })();
        let _ = std::env::set_current_dir(&prev_cwd);
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();
    }
}
