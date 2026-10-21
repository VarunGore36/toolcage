//! Policy decision latency benchmark. Target (plan §11): p99 in-process < 5 ms.
//! Runs every commit; prints p50/p99 so regressions are visible. Asserts a
//! generous CI-safe ceiling (< 100 ms) so the suite never flakes on loaded
//! runners, while the real number is captured in docs/TEST_RESULTS.md.
use std::time::Instant;
use toolcage_policy::{decide, load_yaml, Request};

fn sample() -> toolcage_policy::Policy {
    load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
}

fn net_req(host: &str) -> Request {
    Request {
        action: "http.request".into(),
        host: Some(host.into()),
        method: Some("GET".into()),
        path: Some("/".into()),
        fs_path: None,
        argv: None,
    }
}

#[test]
fn decision_latency_p99_under_ceiling() {
    let p = sample();
    let mut latencies = Vec::with_capacity(10_000);
    let hosts = [
        "registry.npmjs.org",
        "github",
        "evil.example.com",
        "169.254.169.254",
    ];
    let mut i = 0;
    // Warmup.
    for _ in 0..100 {
        decide(&p, &net_req(hosts[i % hosts.len()]));
        i += 1;
    }
    for _ in 0..10_000 {
        let start = Instant::now();
        decide(&p, &net_req(hosts[i % hosts.len()]));
        latencies.push(start.elapsed());
        i += 1;
    }
    latencies.sort();
    let n = latencies.len();
    let p50 = latencies[n / 2];
    let p99 = latencies[(n as f64 * 0.99) as usize];
    let max = latencies[n - 1];
    println!(
        "policy decisions: n=10000 p50={:?} p99={:?} max={:?}",
        p50, p99, max
    );
    assert!(
        p99 < std::time::Duration::from_millis(100),
        "policy p99 too slow: {:?}",
        p99
    );
}
