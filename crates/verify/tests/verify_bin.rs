//! The standalone verifier is what an operator runs to check a log (I5) —
//! the one binary with no tests before this. Contract: a clean log verifies
//! (with and without checkpoints), a tampered one does not, and a bad
//! checkpoint signature fails even when the chain is intact.

use std::path::PathBuf;

fn verify_bin() -> &'static str {
    env!("CARGO_BIN_EXE_toolcage-verify")
}

fn mklog(dir: &std::path::Path) -> (PathBuf, String) {
    let log = dir.join("audit.jsonl");
    let mut w = toolcage_audit::Writer::open(&log).unwrap();
    for i in 0..3u64 {
        w.append(toolcage_audit::Event {
            seq: 0,
            ts_wall: format!("t{i}"),
            session: "s".into(),
            actor: "agent".into(),
            action: "proc.exec".into(),
            request_hash: "h".into(),
            decision: "allow".into(),
            rule_ids: vec![],
            token_rev_id: String::new(),
            result: "ok".into(),
            bytes: 0,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        })
        .unwrap();
    }
    drop(w);
    let (n, head) = toolcage_audit::verify(&log).unwrap();
    (log, format!("{n}:{head}"))
}

#[test]
fn clean_log_verifies_and_tampering_fails() {
    let dir = std::env::temp_dir().join(format!("tc-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (log, _) = mklog(&dir);

    let out = std::process::Command::new(verify_bin())
        .args(["--log", log.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a clean log must verify: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok:"));

    // Flip one byte of the middle event: verify must fail.
    let data = std::fs::read_to_string(&log).unwrap();
    let mut lines: Vec<String> = data.lines().map(|l| l.to_string()).collect();
    let mid = lines[1].replace("\"allow\"", "\"deny\"");
    lines[1] = mid;
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();
    let out = std::process::Command::new(verify_bin())
        .args(["--log", log.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a tampered log must not verify");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn checkpoints_are_verified_against_the_pinned_key() {
    let dir = std::env::temp_dir().join(format!("tc-verify-ckpt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (log, _) = mklog(&dir);
    let (n, head) = toolcage_audit::verify(&log).unwrap();

    // Sign a checkpoint at the chain head and pin its pubkey.
    let sk = [7u8; 32];
    let cp = toolcage_audit::sign_checkpoint(n, &head, "t", &sk).unwrap();
    std::fs::write(
        dir.join(format!("audit.jsonl.checkpoint.{n}")),
        serde_json::to_string_pretty(&cp).unwrap(),
    )
    .unwrap();
    let pubfile = dir.join("pub.hex");
    std::fs::write(&pubfile, &cp.pubkey_hex).unwrap();

    // Chain + checkpoints verify.
    let out = std::process::Command::new(verify_bin())
        .args([
            "--log",
            log.to_str().unwrap(),
            "--pubkey",
            pubfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a signed chain must verify: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A tampered checkpoint signature fails even though the chain is intact.
    let mut forged = cp.clone();
    forged.sig_hex = "00".repeat(64);
    std::fs::write(
        dir.join(format!("audit.jsonl.checkpoint.{n}")),
        serde_json::to_string_pretty(&forged).unwrap(),
    )
    .unwrap();
    let out = std::process::Command::new(verify_bin())
        .args([
            "--log",
            log.to_str().unwrap(),
            "--pubkey",
            pubfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a forged checkpoint signature must fail"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
