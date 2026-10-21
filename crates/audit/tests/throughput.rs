//! Audit append throughput benchmark. Target (plan §11): >= 10,000 appends/sec.
//! fsync-per-append caps this (~hundreds/s today); group commit is the next step.
//! Runs every commit; prints appends/sec. Asserts a CI-safe floor so a
//! regression is caught, while the real number is captured in docs/TEST_RESULTS.md.
use std::time::Instant;
use toolcage_audit::{Event, Writer};

#[test]
fn append_throughput_eps() {
    let dir = std::env::temp_dir().join(format!("toolcage-bench-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("bench.jsonl");
    let _ = std::fs::remove_file(&p);
    let mut w = Writer::open(&p).unwrap();
    let n = 5_000;
    let start = Instant::now();
    for i in 0..n {
        w.append(Event {
            seq: 0,
            ts_wall: "2026-10-17T00:00:00Z".into(),
            session: "bench".into(),
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
    let elapsed = start.elapsed();
    let eps = n as f64 / elapsed.as_secs_f64();
    println!("audit append: n={} elapsed={:?} eps={:.0}", n, elapsed, eps);
    // CI-safe floor: fsync-per-append on loaded runners can dip low; the
    // product target (10k/s) is tracked separately via group commit.
    assert!(
        eps > 200.0,
        "audit append throughput regressed: {:.0} eps",
        eps
    );
    assert!(toolcage_audit::verify(&p).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}
