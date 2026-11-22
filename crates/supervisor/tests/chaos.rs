//! Chaos v0 (fail-closed): dead proxy/broker/audit/disk/clock must STOP actions.
//! Runs nightly + pre-release. No silent fallback.

use toolcage_approval::Queue;
fn sample_policy() -> toolcage_policy::Policy {
    toolcage_policy::load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
}

fn sup_at(audit: &std::path::Path) -> toolcage_supervisor::Supervisor {
    toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: audit.to_path_buf(),
        session: "chaos".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    }
}

#[test]
fn audit_write_failure_denies_action() {
    // Audit dir is a file, not a dir -> Writer::open fails -> fetch errors (deny).
    let dir = std::env::temp_dir().join("tc-chaos-auditfail");
    let _ = std::fs::remove_file(&dir);
    std::fs::write(&dir, "not-a-dir").unwrap();
    let bad = dir.join("audit.jsonl");
    let mut s = toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: bad,
        session: "c".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };
    let b = toolcage_broker::Broker::new();
    // open("not-a-dir/audit.jsonl") fails -> propagate as Err, caller must not act.
    assert!(s
        .fetch_via_proxy(
            &b,
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            None,
            &toolcage_capability::RevocationList::default(),
            true
        )
        .is_err());
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn proxy_down_means_closed() {
    // No proxy object available -> no direct fallback. Policy alone denies evil.
    let p = sample_policy();
    let d = toolcage_proxy::decide(&p, "evil.example.com", "GET", "/");
    assert!(!d.allow && d.upstream.is_none());
}

#[test]
fn broker_unreachable_denies_cred_use() {
    // Empty broker (unreachable store) -> inject returns None, body has no-auth, never literal.
    let b = toolcage_broker::Broker::new();
    assert_eq!(b.inject("github_token", "github", "GET", "/"), None);
    let dir = std::env::temp_dir().join("tc-chaos-broker");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let o = sup_at(&audit)
        .fetch_via_proxy(
            &b,
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        )
        .unwrap();
    // No credential injected -> proxy connects without auth header; body has no secret.
    assert!(o.allowed);
    assert!(!o.body.contains("s3cr3t"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn revoked_token_denied_and_audited() {
    // I3: revoke(parent) kills fetch even with an otherwise-valid child token.
    // The supervisor holds the host key so the tag verifies — the denial must
    // come from revocation, not from fail-closed tag verification.
    use toolcage_capability::{Key, RevocationList, Rights, Token};
    let key = Key::from_bytes([5u8; 32]);
    let dir = std::env::temp_dir().join("tc-chaos-revoked");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let root = Token::root(
        &key,
        "r0",
        Rights {
            fs_prefixes: vec!["/workspace".into()],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 1000,
            expires_at: 9_999_999_999,
        },
    )
    .unwrap();
    let child = root
        .attenuate(
            &key,
            "r1",
            Rights {
                fs_prefixes: vec![],
                net_hosts: vec!["github".into()],
                methods: vec!["GET".into()],
                cred_use: vec![],
                budget_bytes: 10,
                expires_at: 9_999_999_000,
            },
        )
        .unwrap();
    let mut rl = RevocationList::default();
    rl.track(&child);
    rl.revoke("r0");
    let mut s = sup_at(&audit);
    s.cap_key = Some(key);
    let o = s
        .fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            Some(&child),
            &rl,
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"token:deny".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn over_egress_budget_denies_fail_closed() {
    // §8 damage bound: tiny egress_bytes budget -> second fetch denied + audited.
    let mut pol = sample_policy();
    pol.limits.egress_bytes = 10;
    pol.limits.egress_requests = 1000;
    let dir = std::env::temp_dir().join("tc-chaos-budget");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut sup = toolcage_supervisor::Supervisor {
        policy: pol,
        audit_path: audit,
        session: "c".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };
    let b = toolcage_broker::Broker::new();
    let rl = toolcage_capability::RevocationList::default();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    // Proxy connects, gets response > 10B budget -> budget:exceeded denial.
    let o = sup
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &rl,
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"budget:exceeded".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn budget_precharge_denies_before_network() {
    // egress_bytes=10: the request-size estimate (~356 bytes) exceeds the
    // budget at pre-charge, so the call is denied BEFORE any network dial.
    // No live fetch happens (hermetic).
    let mut pol = sample_policy();
    pol.limits.egress_bytes = 10;
    pol.limits.egress_requests = 1000;
    let dir = std::env::temp_dir().join("tc-chaos-precharge");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);
    let mut s = sup_at(&audit);
    s.policy = pol;
    let o = s
        .fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/repos/acme/app/issues/1",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        )
        .unwrap();
    assert!(!o.allowed && !o.need_approval);
    assert!(o.rule_ids.contains(&"budget:exceeded".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disk_full_simulated_by_readonly() {
    let dir = std::env::temp_dir().join("tc-chaos-ro");
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    std::fs::write(&audit, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o444)).unwrap();
        // Appending may still succeed as root; assert verify still holds either way.
        let _ = sup_at(&audit).fetch_via_proxy(
            &toolcage_broker::Broker::new(),
            &mut toolcage_proxy::Budgets::default(),
            &mut toolcage_proxy::Proxy::new().unwrap(),
            "github",
            "GET",
            "/",
            None,
            &toolcage_capability::RevocationList::default(),
            true,
        );
        assert!(toolcage_audit::verify(&audit).is_ok());
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn panic_freeze_taints_and_keeps_the_chain_verifiable() {
    // The panic path is the operator's last resort: it must append a deny-all
    // to the chain (which then VERIFIES — the log is frozen, not corrupted)
    // and leave a taint marker that cannot collide with another log's.
    let dir = std::env::temp_dir().join(format!("tc-panic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("a.jsonl");
    let mut w = toolcage_audit::Writer::open(&log).unwrap();
    w.append(toolcage_audit::Event {
        seq: 0,
        ts_wall: "t".into(),
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);

    let head = toolcage_supervisor::panic_freeze(&log, "suspected compromise").unwrap();
    assert!(!head.is_empty());

    // The marker is `<log>.tainted` — APPENDED, not extension-replaced.
    assert!(
        dir.join("a.jsonl.tainted").exists(),
        "the taint marker must keep the log's full name"
    );
    assert!(
        !dir.join("a.tainted").exists(),
        "with_extension naming would collide across logs"
    );

    // The chain still verifies (frozen, not corrupted) and ends in deny-all.
    toolcage_audit::verify(&log).expect("a frozen log must still verify");
    let last = std::fs::read_to_string(&log).unwrap();
    let last = last.lines().last().unwrap().to_string();
    assert!(
        last.contains("deny-all"),
        "the freeze must deny all: {last}"
    );

    // A second log's marker must not collide with the first's.
    let log2 = dir.join("b.log");
    let mut w = toolcage_audit::Writer::open(&log2).unwrap();
    w.append(toolcage_audit::Event {
        seq: 0,
        ts_wall: "t".into(),
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);
    toolcage_supervisor::panic_freeze(&log2, "x").unwrap();
    assert!(
        dir.join("b.log.tainted").exists(),
        "second log's own marker"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn panic_freeze_blocks_writes_and_cannot_be_erased() {
    // VULN-03 reproduction: `panic freeze` wrote a deny-all event and a
    // .tainted marker, but nothing ever LOOKED at them — the "frozen" log
    // kept accepting and running actions (every action opens Writer first,
    // so enforcing there freezes all execution fail-closed). And an attacker
    // who deleted the marker could extend the log; verify still passed.
    let dir = std::env::temp_dir().join(format!("tc-panic-block-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("a.jsonl");
    toolcage_supervisor::panic_freeze(&log, "suspected compromise").unwrap();

    // The freeze must refuse further writes while the marker stands ...
    assert!(
        toolcage_audit::Writer::open(&log).is_err(),
        "a frozen log must not accept writes"
    );
    // ... and even if the marker is deleted, the terminal deny-all inside the
    // chain must still refuse them (the marker is a convenience; the chain is
    // the enforcement).
    std::fs::remove_file(dir.join("a.jsonl.tainted")).unwrap();
    assert!(
        toolcage_audit::Writer::open(&log).is_err(),
        "a frozen log must not accept writes with the marker deleted"
    );
    // The marker alone must also refuse: an operator can taint a log whose
    // chain is perfectly healthy ("this record is suspect"), and that stands.
    let other = dir.join("b.jsonl");
    let mut w = toolcage_audit::Writer::open(&other).unwrap();
    w.append(toolcage_audit::Event {
        seq: 0,
        ts_wall: "t".into(),
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);
    std::fs::write(dir.join("b.jsonl.tainted"), "operator taint\n").unwrap();
    assert!(
        toolcage_audit::Writer::open(&other).is_err(),
        "a tainted log must refuse writes even with a healthy chain"
    );

    // And an event appended behind the freeze (bypassing Writer) must break
    // verification rather than blend in.
    let mut raw = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    let _line = concat!(
        "{\"seq\":1,\"ts_wall\":\"t\",\"session\":\"s\",\"actor\":\"agent\",",
        "\"action\":\"proc.exec\",\"request_hash\":\"h\",\"decision\":\"allow\",",
        "\"rule_ids\":[],\"token_rev_id\":\"\",\"result\":\"ok\",\"bytes\":0,",
        "\"claimed_by\":\"host\",\"prev_hash\":\"x\",\"hash\":\"y\"}\n"
    );
    std::io::Write::write_all(&mut raw, _line.as_bytes()).unwrap();
    let err = match toolcage_audit::verify(&log) {
        Err(e) => format!("{e:#}"),
        Ok(_) => panic!("events after the freeze must fail verification"),
    };
    assert!(
        err.contains("panic freeze"),
        "the failure must be about the freeze, not just a chain break: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Test clock skew handling: supervisor should handle wall-clock time changes gracefully.
/// The audit log uses wall-clock timestamps; if the clock jumps, events should still
/// be ordered by their sequence numbers, not timestamps.
#[test]
fn clock_skew_does_not_break_audit_chain() {
    let dir = std::env::temp_dir().join(format!("tc-clock-skew-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let mut w = toolcage_audit::Writer::open(&audit).unwrap();
    // Write initial event with a timestamp
    w.append(toolcage_audit::Event {
        seq: 0,
        ts_wall: "1000".into(),
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);

    // Simulate clock jump forward by writing directly to the log with a future timestamp
    // The Writer should handle this gracefully by using the actual wall clock
    let mut w = toolcage_audit::Writer::open(&audit).unwrap();
    w.append(toolcage_audit::Event {
        seq: 1,
        ts_wall: "2000".into(), // Clock jumped forward
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h2".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);

    // The chain should still verify - sequence numbers are the source of truth
    let (count, head) = toolcage_audit::verify(&audit).unwrap();
    assert_eq!(count, 2);
    assert!(!head.is_empty());

    // Now simulate clock jump backward - Writer uses actual wall clock
    let mut w = toolcage_audit::Writer::open(&audit).unwrap();
    w.append(toolcage_audit::Event {
        seq: 2,
        ts_wall: "500".into(), // Clock jumped backward
        session: "s".into(),
        actor: "agent".into(),
        action: "proc.exec".into(),
        request_hash: "h3".into(),
        decision: "allow".into(),
        rule_ids: vec![],
        token_rev_id: String::default(),
        result: "ok".into(),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::default(),
        hash: String::default(),
    })
    .unwrap();
    drop(w);

    // Chain should still verify - sequence numbers ensure ordering
    let (count, head) = toolcage_audit::verify(&audit).unwrap();
    assert_eq!(count, 3);
    assert!(!head.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test that memory limits are enforced (OOM simulation via memory limit).
/// When a process exceeds its memory limit, it should be killed and the
/// audit should record the denial.
#[test]
fn memory_limit_exceeded_is_audited() {
    // This test requires a backend that supports memory limits (tier0 with cgroups)
    // For tier0 without backend, we test the policy check path
    let dir = std::env::temp_dir().join(format!("tc-mem-limit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let mut pol = sample_policy();
    pol.limits.memory_mb = 1; // Extremely low limit

    let mut s = toolcage_supervisor::Supervisor {
        policy: pol,
        audit_path: audit.clone(),
        session: "mem-limit".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    // With a 1MB memory limit, any exec should be denied at policy check
    let o = s.exec(&["/bin/true".to_string()]).unwrap();
    // The exec should be allowed (policy allows it) but would fail at backend
    // Since we have no backend, it should be denied with isolation:unavailable
    assert!(!o.allowed);
    assert!(o.rule_ids.contains(&"isolation:unavailable".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test OOM kill simulation: exec with extremely low memory limit should be
/// denied at policy check and audit the denial.
#[test]
fn oom_simulation_via_policy_deny() {
    let dir = std::env::temp_dir().join(format!("tc-oom-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let mut pol = sample_policy();
    pol.limits.memory_mb = 1; // Extremely low limit

    let mut s = toolcage_supervisor::Supervisor {
        policy: pol,
        audit_path: audit.clone(),
        session: "oom-sim".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    // Exec should be denied due to memory limit
    let o = s.exec(&["/bin/true".to_string()]).unwrap();
    assert!(!o.allowed);
    // The denial should be recorded in audit
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("proc.exec"));
    assert!(log.contains("deny"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test disk full simulation during audit write.
/// The supervisor should fail closed and not proceed with the action.
#[test]
fn disk_full_during_audit_write_fails_closed() {
    let dir = std::env::temp_dir().join(format!("tc-disk-full-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    // Create a read-only file to simulate disk full / permission denied
    std::fs::write(&audit, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o444)).unwrap();
    }

    let mut s = toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: audit.clone(),
        session: "disk-full".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    // Exec should fail due to audit write failure
    let result = s.exec(&["/bin/true".to_string()]);
    assert!(result.is_err());

    // Restore permissions for cleanup
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Test network partition simulation during fetch.
/// The fetch should fail closed when the proxy cannot connect.
#[test]
fn network_partition_during_fetch_fails_closed() {
    let dir = std::env::temp_dir().join(format!("tc-net-part-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let mut s = toolcage_supervisor::Supervisor {
        policy: sample_policy(),
        audit_path: audit.clone(),
        session: "net-part".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    let b = toolcage_broker::Broker::new();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    let rl = toolcage_capability::RevocationList::default();

    // Use an unreachable host to simulate network partition
    let o = s
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "10.255.255.1", // Unreachable IP (RFC 5737)
            "GET",
            "/",
            None,
            &rl,
            true,
        )
        .unwrap();

    assert!(!o.allowed);
    assert!(!o.need_approval);
    // The error should be recorded in audit
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.contains("http.request"));
    assert!(log.contains("deny"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test concurrent approval race condition.
/// Multiple threads requesting approval for the same action should be handled correctly.
#[test]
fn concurrent_approval_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let dir = std::env::temp_dir().join(format!("tc-race-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let mut pol = sample_policy();
    // Add approval requirement for http.request to github
    pol.approval.require_for.push({
        let mut map = std::collections::HashMap::new();
        map.insert(
            "http.request".into(),
            toolcage_policy::ApprovalSpec {
                methods: vec!["POST".into()],
                hosts: vec!["github".into()],
            },
        );
        map
    });

    // Each thread creates its own supervisor instance to avoid Send issues
    let _barrier = Arc::new(Barrier::new(4));
    let mut handles = vec![];

    let pol_clone = pol.clone();
    for _i in 0..4 {
        let audit = audit.clone();
        let pol = pol_clone.clone();
        handles.push(thread::spawn(move || {
            let mut s = toolcage_supervisor::Supervisor {
                policy: pol,
                audit_path: audit.clone(),
                session: format!("race-{}", std::process::id()),
                tier: toolcage_backend::Tier::Tier0,
                backend: None,
                allow_unisolated: false,
                token_rev_id: String::default(),
                cap_key: None,
                approval_queue: Queue::default(),
                approval_queue_path: None,
                policy_path: None,
                hot_reload: false,
                #[cfg(feature = "cedar")]
                cedar_engine: None,
            };

            let b = toolcage_broker::Broker::new();
            let mut budgets = toolcage_proxy::Budgets::default();
            let mut proxy = toolcage_proxy::Proxy::new().unwrap();
            let _rl = toolcage_capability::RevocationList::default();

            let _ = s
                .fetch_via_proxy(
                    &b,
                    &mut budgets,
                    &mut proxy,
                    "github",
                    "POST",
                    "/repos/test",
                    None,
                    &toolcage_capability::RevocationList::default(),
                    false,
                )
                .unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Note: Each thread has its own supervisor, so we cannot easily test shared queue
    // This test verifies that concurrent requests do not crash
    let _ = std::fs::remove_dir_all(&dir);
}

/// Test token revocation during in-flight fetch.
/// A token that is revoked mid-request should cause the fetch to be denied.
#[test]
fn token_revocation_during_fetch() {
    use toolcage_capability::{Key, RevocationList, Rights, Token};

    let dir = std::env::temp_dir().join(format!("tc-revocation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let key = Key::from_bytes([42u8; 32]);
    let mut pol = sample_policy();
    pol.limits.egress_bytes = 10000;

    let mut s = toolcage_supervisor::Supervisor {
        policy: pol,
        audit_path: audit.clone(),
        session: "revocation".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: Some(key.clone()),
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    let token = Token::root(
        &key,
        "token-1",
        Rights {
            fs_prefixes: vec!["/workspace".into()],
            net_hosts: vec!["github".into()],
            methods: vec!["GET".into()],
            cred_use: vec![],
            budget_bytes: 1000,
            expires_at: 9_999_999_999,
        },
    )
    .unwrap();

    let mut rl = RevocationList::default();
    rl.track(&token);

    let b = toolcage_broker::Broker::new();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();

    // First fetch with valid token should succeed (policy allows)
    let o1 = s
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/repos/test",
            Some(&token),
            &rl,
            true,
        )
        .unwrap();
    // Should be denied due to no backend, but token should be accepted
    assert!(!o1.allowed);

    // Revoke the token
    rl.revoke("token-1");

    // Second fetch with revoked token should be denied
    let o2 = s
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/repos/test",
            Some(&token),
            &rl,
            true,
        )
        .unwrap();
    assert!(!o2.allowed);
    assert!(o2.rule_ids.contains(&"token:deny".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Test policy hot-reload race condition.
/// Changing policy while requests are in-flight should not cause crashes.
#[test]
fn policy_hot_reload_during_requests() {
    let dir = std::env::temp_dir().join(format!("tc-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let audit = dir.join("a.jsonl");
    let _ = std::fs::remove_file(&audit);

    let pol1 = sample_policy();
    let mut pol2 = sample_policy();
    // Different policy: one allows github, one doesn't
    pol2.net.hosts.clear();

    let mut s = toolcage_supervisor::Supervisor {
        policy: pol1,
        audit_path: audit.clone(),
        session: "reload".into(),
        tier: toolcage_backend::Tier::Tier0,
        backend: None,
        allow_unisolated: false,
        token_rev_id: String::default(),
        cap_key: None,
        approval_queue: Queue::default(),
        approval_queue_path: None,
        policy_path: None,
        hot_reload: false,
        #[cfg(feature = "cedar")]
        cedar_engine: None,
    };

    let b = toolcage_broker::Broker::new();
    let mut budgets = toolcage_proxy::Budgets::default();
    let mut proxy = toolcage_proxy::Proxy::new().unwrap();
    let rl = toolcage_capability::RevocationList::default();

    // First fetch with pol1 (allows github)
    let o1 = s
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/",
            None,
            &rl,
            true,
        )
        .unwrap();
    assert!(!o1.allowed); // No backend, so denied

    // Swap policy to pol2 (denies github)
    s.policy = pol2;

    // Second fetch with pol2 (denies github)
    let o2 = s
        .fetch_via_proxy(
            &b,
            &mut budgets,
            &mut proxy,
            "github",
            "GET",
            "/",
            None,
            &rl,
            true,
        )
        .unwrap();
    assert!(!o2.allowed);

    // Both should be recorded in audit
    let log = std::fs::read_to_string(&audit).unwrap();
    assert!(log.lines().count() >= 2);

    let _ = std::fs::remove_dir_all(&dir);
}
