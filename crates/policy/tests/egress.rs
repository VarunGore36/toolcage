//! Egress limit validation tests — verifies that excessive egress bounds
//! are rejected by the policy decide function.

use toolcage_policy::{decide, Policy, Request};

fn req_connect() -> Request {
    Request {
        action: "net.connect".into(),
        host: Some("example.com".into()),
        method: None,
        path: Some("/".into()),
        fs_path: None,
        argv: None,
    }
}

fn req_http() -> Request {
    Request {
        action: "http.request".into(),
        host: Some("example.com".into()),
        method: Some("GET".into()),
        path: Some("/".into()),
        fs_path: None,
        argv: None,
    }
}

#[test]
fn egress_bytes_excessive_is_denied() {
    let mut p = Policy::default();
    p.limits.egress_bytes = 2 * 1024 * 1024 * 1024 * 1024; // 2 TiB > 1 TiB
    let d = decide(&p, &req_connect());
    assert!(!d.allow, "excessive egress_bytes must be denied");
    assert!(d.rule_ids.iter().any(|r| r.contains("egress-bytes-excessive")));
}

#[test]
fn egress_requests_excessive_is_denied() {
    let mut p = Policy::default();
    p.limits.egress_requests = 2_000_000_000; // 2B > 1B
    let d = decide(&p, &req_http());
    assert!(!d.allow, "excessive egress_requests must be denied");
    assert!(d.rule_ids.iter().any(|r| r.contains("egress-requests-excessive")));
}

#[test]
fn egress_bytes_zero_is_unlimited() {
    let p = Policy::default();
    let d = decide(&p, &req_connect());
    assert!(!d.rule_ids.iter().any(|r| r.contains("egress-bytes-excessive")));
}

#[test]
fn egress_requests_zero_is_unlimited() {
    let p = Policy::default();
    let d = decide(&p, &req_http());
    assert!(!d.rule_ids.iter().any(|r| r.contains("egress-requests-excessive")));
}

#[test]
fn egress_bytes_at_limit_is_allowed() {
    let mut p = Policy::default();
    p.limits.egress_bytes = 1024 * 1024 * 1024 * 1024; // exactly 1 TiB
    let d = decide(&p, &req_connect());
    assert!(!d.rule_ids.iter().any(|r| r.contains("egress-bytes-excessive")));
}

#[test]
fn egress_requests_at_limit_is_allowed() {
    let mut p = Policy::default();
    p.limits.egress_requests = 1_000_000_000; // exactly 1B
    let d = decide(&p, &req_http());
    assert!(!d.rule_ids.iter().any(|r| r.contains("egress-requests-excessive")));
}
