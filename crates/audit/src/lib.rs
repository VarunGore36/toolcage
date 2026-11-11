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
//! - Concurrency: every append takes flock(LOCK_EX), re-reads the chain tail
//!   if another process extended the file, then writes + fsyncs, so concurrent
//!   writers serialize instead of forking the chain. The lock is never held
//!   across the action itself.
//! - Freeze: a `deny-all` event (panic_freeze) is terminal. Writer::open and
//!   append refuse a log with a `.tainted` marker or a deny-all tail, and
//!   verify() fails if anything follows a deny-all.
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

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(b: impl AsRef<[u8]>) -> String {
    let bytes = b.as_ref();
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize]);
        out.push(HEX_LOWER[(byte & 0x0f) as usize]);
    }
    // SAFETY: `HEX_LOWER` contains only ASCII hex digits.
    unsafe { String::from_utf8_unchecked(out) }
}

// Borrowed view of Event with fields in BTreeMap key order so to_writer
// hashes the exact same bytes as event_body() without building a Value.
#[derive(Serialize)]
struct CanonicalEventBody<'a> {
    action: &'a str,
    actor: &'a str,
    bytes: u64,
    claimed_by: &'a str,
    decision: &'a str,
    prev_hash: &'a str,
    request_hash: &'a str,
    result: &'a str,
    rule_ids: &'a [String],
    seq: u64,
    session: &'a str,
    token_rev_id: &'a str,
    ts_wall: &'a str,
}

impl<'a> From<&'a Event> for CanonicalEventBody<'a> {
    #[inline]
    fn from(e: &'a Event) -> Self {
        Self {
            action: &e.action,
            actor: &e.actor,
            bytes: e.bytes,
            claimed_by: &e.claimed_by,
            decision: &e.decision,
            prev_hash: &e.prev_hash,
            request_hash: &e.request_hash,
            result: &e.result,
            rule_ids: &e.rule_ids,
            seq: e.seq,
            session: &e.session,
            token_rev_id: &e.token_rev_id,
            ts_wall: &e.ts_wall,
        }
    }
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl std::io::Write for Sha256Writer<'_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[inline]
fn hash_event(e: &Event) -> String {
    let mut h = Sha256::new();
    h.update(e.prev_hash.as_bytes());
    let body = CanonicalEventBody::from(e);
    serde_json::to_writer(Sha256Writer(&mut h), &body)
        .expect("infallible serialization into Sha256Writer");
    hex_encode(h.finalize())
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

#[cfg(test)]
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
    path: std::path::PathBuf,
    next_seq: u64,
    head: String,
    /// File length after our last verify/append. If another process appended
    /// in between, the length differs and the chain tail is re-read under the
    /// lock before we extend it.
    known_len: u64,
    /// File mtime after our last verify/append. A non-flocking tamperer can
    /// rewrite the tail to the SAME length (defeating the known_len check);
    /// a changed mtime with an unchanged length forces a full re-verify too.
    known_mtime: Option<std::time::SystemTime>,
}

/// Exclusive advisory lock on the audit file, released on drop. Held only for
/// the verify-then-append critical section — never across the action itself,
/// so a long exec cannot block another process (e.g. an operator `panic`).
struct FlockGuard(std::os::unix::io::RawFd);

impl FlockGuard {
    fn lock(file: &File, path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        loop {
            // SAFETY: flock on a valid fd owned by `file`, which outlives the guard.
            if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 {
                return Ok(Self(fd));
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                anyhow::bail!("flock audit log {}: {err}", path.display());
            }
        }
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: same fd the lock was taken on; still open (see lock()).
        unsafe { libc::flock(self.0, libc::LOCK_UN) };
    }
}

impl Writer {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        // A panic-frozen log (`<log>.tainted` present) accepts no new events.
        // Every supervisor action opens a Writer before acting (I4), so
        // refusing here stops every execution path fail-closed.
        ensure_not_tainted(path)?;
        let existed = path.exists();
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if !existed {
            // Deterministic and secure: the creation mode is umask-masked
            // (0666 & !umask), so a hardened umask left the log 0000 and the
            // later verify/checkpoint steps could not read it. An audit log
            // holds session/action metadata — 0600, like the key material.
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut w = Self {
            file,
            path: path.to_path_buf(),
            next_seq: 0,
            head: "GENESIS".to_string(),
            known_len: 0,
            known_mtime: None,
        };
        // Verify existing chain (under the lock) before appending: never
        // extend a corrupt log, and never extend one frozen by `panic`.
        let _g = FlockGuard::lock(&w.file, path)?;
        w.resync()?;
        Ok(w)
    }

    /// Re-read the chain tail (caller holds the lock). Fails on a corrupt or
    /// panic-frozen log.
    fn resync(&mut self) -> anyhow::Result<()> {
        let len = self.file.metadata()?.len();
        if len > 0 {
            let (n, h, frozen) = verify_chain(&self.path)?;
            anyhow::ensure!(
                !frozen,
                "audit log {} is frozen by a deny-all panic event",
                self.path.display()
            );
            self.next_seq = n;
            self.head = h;
        } else {
            self.next_seq = 0;
            self.head = "GENESIS".to_string();
        }
        self.known_len = len;
        self.known_mtime = self.file.metadata().ok().and_then(|m| m.modified().ok());
        Ok(())
    }

    /// True when the file changed since our last verify/append in a way the
    /// known_len check cannot see: a non-flocking tamperer can rewrite the
    /// tail to the SAME length. The stat is cheap; the full re-verify it
    /// triggers only runs on suspicion. An unreadable stat fails safe
    /// (re-verify).
    fn modified_since_known(&self) -> bool {
        let Ok(md) = self.file.metadata() else {
            return true;
        };
        if md.len() != self.known_len {
            return true;
        }
        match (md.modified(), self.known_mtime) {
            (Ok(m), Some(k)) => m != k,
            _ => true,
        }
    }

    /// Write-ahead append: fsync before returning, so caller may act only after Ok.
    ///
    /// Serialized across processes with flock: if another writer extended the
    /// log since our last append, the new tail is verified and chained onto
    /// (so concurrent sessions never fork the chain), and a freeze appended in
    /// the meantime by `panic` makes this append fail.
    pub fn append(&mut self, mut e: Event) -> anyhow::Result<Event> {
        ensure_not_tainted(&self.path)?;
        let _g = FlockGuard::lock(&self.file, &self.path)?;
        if self.modified_since_known() {
            self.resync()?;
        }
        e.seq = self.next_seq;
        e.prev_hash = self.head.clone();
        e.hash = hash_event(&e);
        let mut line = Vec::with_capacity(256);
        serde_json::to_writer(&mut line, &e)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.known_len += line.len() as u64;
        self.known_mtime = self.file.metadata().ok().and_then(|m| m.modified().ok());
        self.next_seq += 1;
        self.head = e.hash.clone();
        Ok(e)
    }

    /// Group-commit append: chains and writes a batch of events in one buffer
    /// with a single fdatasync (`sync_data`), preserving write-ahead order (I4).
    pub fn append_batch(&mut self, mut events: Vec<Event>) -> anyhow::Result<Vec<Event>> {
        if events.is_empty() {
            return Ok(events);
        }
        ensure_not_tainted(&self.path)?;
        let _g = FlockGuard::lock(&self.file, &self.path)?;
        if self.modified_since_known() {
            self.resync()?;
        }
        let mut buf = Vec::with_capacity(events.len() * 256);
        let mut seq = self.next_seq;
        let mut head = self.head.clone();
        let mut saw_freeze = false;
        for e in &mut events {
            anyhow::ensure!(
                !saw_freeze,
                "cannot append event after deny-all panic freeze in batch"
            );
            e.seq = seq;
            e.prev_hash = head;
            e.hash = hash_event(e);
            serde_json::to_writer(&mut buf, &*e)?;
            buf.push(b'\n');
            if e.decision == FREEZE_DECISION {
                saw_freeze = true;
            }
            seq += 1;
            head = e.hash.clone();
        }
        self.file.write_all(&buf)?;
        self.file.sync_data()?;
        self.known_len += buf.len() as u64;
        self.known_mtime = self.file.metadata().ok().and_then(|m| m.modified().ok());
        self.next_seq = seq;
        self.head = head;
        Ok(events)
    }
}

pub fn verify(path: &Path) -> anyhow::Result<(u64, String)> {
    let (count, head, _frozen) = verify_chain(path)?;
    Ok((count, head))
}

/// Decision recorded by `panic_freeze`. It must be the terminal event of a
/// log: anything appended after it means the freeze was bypassed.
pub const FREEZE_DECISION: &str = "deny-all";

/// `<log>.tainted` — appended suffix, matching `panic_freeze`'s naming.
pub fn tainted_marker(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".tainted");
    std::path::PathBuf::from(os)
}

fn ensure_not_tainted(path: &Path) -> anyhow::Result<()> {
    let taint = tainted_marker(path);
    anyhow::ensure!(
        !taint.exists(),
        "audit log {} is frozen ({} present)",
        path.display(),
        taint.display()
    );
    Ok(())
}

/// Verify the chain; also report whether it ends in a panic freeze.
fn verify_chain(path: &Path) -> anyhow::Result<(u64, String, bool)> {
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, f);
    let mut line = String::with_capacity(512);
    let mut expect_prev = "GENESIS".to_string();
    let mut expect_seq = 0u64;
    let mut count = 0u64;
    let mut frozen_at: Option<u64> = None;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(pseq) = frozen_at {
            anyhow::bail!("log extended after panic freeze at seq {pseq}");
        }
        let e: Event = serde_json::from_str(trimmed)?;
        anyhow::ensure!(
            e.seq == expect_seq,
            "seq gap: got {} want {}",
            e.seq,
            expect_seq
        );
        anyhow::ensure!(e.prev_hash == expect_prev, "chain break at seq {}", e.seq);
        let recomputed = hash_event(&e);
        anyhow::ensure!(recomputed == e.hash, "hash mismatch at seq {}", e.seq);
        if e.decision == FREEZE_DECISION {
            frozen_at = Some(e.seq);
        }
        expect_prev = e.hash;
        expect_seq += 1;
        count += 1;
    }
    Ok((count, expect_prev, frozen_at.is_some()))
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

/// Sign arbitrary bytes with an Ed25519 key (64-byte signature). Used for
/// golden-image manifests, whose loader verifies the signature over the
/// manifest hash; checkpoints use sign_checkpoint's shaped message.
pub fn sign_bytes(sk_bytes: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};
    anyhow::ensure!(sk_bytes.len() == 32, "sk must be 32 bytes");
    let sk = SigningKey::from_bytes(sk_bytes.try_into().unwrap());
    Ok(sk.sign(msg).to_bytes().to_vec())
}

/// The Ed25519 public key (32 bytes) for a secret key.
pub fn pubkey_of(sk_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ed25519_dalek::SigningKey;
    anyhow::ensure!(sk_bytes.len() == 32, "sk must be 32 bytes");
    let sk = SigningKey::from_bytes(sk_bytes.try_into().unwrap());
    Ok(sk.verifying_key().to_bytes().to_vec())
}

/// Verify an Ed25519 signature over arbitrary bytes against a pinned pubkey.
/// Used by `image verify` to check a golden-image manifest signature.
pub fn verify_bytes(sig: &[u8], msg: &[u8], pubkey: &[u8]) -> anyhow::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    anyhow::ensure!(pubkey.len() == 32, "pubkey must be 32 bytes");
    anyhow::ensure!(sig.len() == 64, "signature must be 64 bytes");
    let vk = VerifyingKey::from_bytes(pubkey.try_into().unwrap())?;
    let sig = Signature::from_slice(sig)?;
    vk.verify(msg, &sig)?;
    Ok(())
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
        // file_name() is None for "/", ".", and ".." — operator-supplied
        // paths, so a panic here is a verifier DoS. Fall back to the whole
        // path string: checkpoint lookups then simply find nothing, which
        // fails closed (missing checkpoints are rejected when a pubkey is
        // pinned).
        let stem = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string());
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

    fn ev(action: &str, decision: &str) -> Event {
        Event {
            seq: 0,
            ts_wall: "2026-01-01T00:00:00Z".into(),
            session: "s1".into(),
            actor: "test".into(),
            action: action.into(),
            request_hash: "abc".into(),
            decision: decision.into(),
            rule_ids: vec![],
            token_rev_id: "r".into(),
            result: "ok".into(),
            bytes: 0,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn append_batch_chains_properly_and_verifies() {
        let dir = std::env::temp_dir().join(format!("toolcage-audit-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("batch.jsonl");
        let mut w = Writer::open(&p).unwrap();

        let batch1 = vec![
            ev("act0", "allow"),
            ev("act1", "allow"),
            ev("act2", "allow"),
        ];
        let out1 = w.append_batch(batch1).unwrap();
        assert_eq!(out1.len(), 3);
        for (idx, item) in out1.iter().enumerate() {
            assert_eq!(item.seq, idx as u64);
            assert_eq!(item.hash, hash_for(&item.prev_hash, &event_body(item)));
        }
        assert_eq!(out1[1].prev_hash, out1[0].hash);
        assert_eq!(out1[2].prev_hash, out1[1].hash);

        let batch2 = vec![ev("act3", "allow"), ev("act4", "allow")];
        let out2 = w.append_batch(batch2).unwrap();
        assert_eq!(out2.len(), 2);
        assert_eq!(out2[0].seq, 3);
        assert_eq!(out2[1].seq, 4);
        assert_eq!(out2[0].prev_hash, out1[2].hash);
        assert_eq!(out2[1].prev_hash, out2[0].hash);

        let (count, head) = verify(&p).expect("batch appends must verify cleanly");
        assert_eq!(count, 5);
        assert_eq!(head, out2[1].hash);

        // Extending after a freeze inside a single batch must fail closed.
        assert!(w
            .append_batch(vec![ev("panic", FREEZE_DECISION), ev("act5", "allow")])
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interleaved_writers_never_fork_the_chain() {
        // Two writers on one log (as two concurrent processes would be) used to
        // each cache (next_seq, head) from open and write duplicate seqs. Each
        // append now re-reads the tail under flock and chains onto it.
        let dir = std::env::temp_dir().join(format!("toolcage-audit-ilv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.jsonl");
        let mut a = Writer::open(&p).unwrap();
        let mut b = Writer::open(&p).unwrap();
        for i in 0..4 {
            a.append(ev(&format!("a{i}"), "allow")).unwrap();
            b.append(ev(&format!("b{i}"), "allow")).unwrap();
        }
        let (n, _) = verify(&p).expect("interleaved appends must keep the chain valid");
        assert_eq!(n, 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_all_freeze_is_terminal() {
        // A panic freeze (deny-all) is the last event a log may hold: a writer
        // that was already open must not extend it, a new writer must refuse
        // to open it, and a log extended past it must fail verification.
        let dir = std::env::temp_dir().join(format!("toolcage-audit-frz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.jsonl");
        let mut running = Writer::open(&p).unwrap();
        running.append(ev("proc.exec", "allow")).unwrap();
        let mut op = Writer::open(&p).unwrap();
        op.append(ev("panic", FREEZE_DECISION)).unwrap();
        drop(op);
        verify(&p).expect("a frozen log still verifies");
        assert!(running.append(ev("proc.exec", "allow")).is_err());
        assert!(Writer::open(&p).is_err());
        // Forge an extension past the freeze by hand: verify must reject it.
        let text = std::fs::read_to_string(&p).unwrap();
        let last: Event = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        let mut forged = ev("proc.exec", "allow");
        forged.seq = last.seq + 1;
        forged.prev_hash = last.hash.clone();
        forged.hash = hash_for(&forged.prev_hash, &event_body(&forged));
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "{}", serde_json::to_string(&forged).unwrap()).unwrap();
        let err = verify(&p).unwrap_err().to_string();
        assert!(err.contains("after panic freeze"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tainted_marker_blocks_open() {
        let dir = std::env::temp_dir().join(format!("toolcage-audit-tnt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("a.jsonl");
        std::fs::write(tainted_marker(&p), "tainted\n").unwrap();
        assert!(Writer::open(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
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
        assert!(hex_decode("z").is_err()); // odd length
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
