//! Supervisor v0: policy check -> audit intent -> exec argv -> audit outcome.
//!
//! REVIEW:
//! - Order is the security property: check (policy AND token) -> append intent
//!   -> spawn -> append outcome. Reordering (spawn before intent log) breaks I4.
//! - env_clear: child gets PATH only. Any new .env() passthrough must be
//!   allowlisted and reviewed — secrets in parent env must never reach guest (I2).
//! - argv hashed (SHA256 with length prefixes), never logged raw: argv can
//!   carry secrets and prompt-injected strings. Length-prefix avoids
//!   concatenation ambiguity ("ab"+"c" vs "a"+"bc").
//! - Output cap 1 MiB post-hoc: Command::output() buffers unbounded BEFORE
//!   truncate, so a fork-bomb writer can OOM the supervisor. Next step is
//!   streaming with take(CAP) + kill on overrun; truncation flag already logged.
//! - No timeout/cgroup yet: exec blocks indefinitely and inherits no limits.
//!   Add wall-clock kill (whole process group) + cgroup v2 caps before
//!   untrusted workloads; enforce in supervisor, never trust guest rlimits.
//! - fetch_via_proxy: token deny and approval pause are audited as their own
//!   events (token:deny / approval:required). approved=false + gated policy
//!   returns need_approval (CLI exit 3), never proceeds. Timeout = deny.
//! - panic_freeze: appends deny-all + writes .tainted sibling. Caller must stop
//!   sessions and close proxy first; taint clears only out-of-band.
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use toolcage_audit::{Event, Writer};
use toolcage_backend::{Backend, Tier};
use toolcage_policy::{Decision, Policy, Request};

pub struct Supervisor {
    pub policy: Policy,
    pub audit_path: PathBuf,
    pub session: String,
    pub tier: Tier,
    pub backend: Option<Box<dyn Backend>>,
}

pub struct ExecOutcome {
    pub allowed: bool,
    pub rule_ids: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn now_wall() -> String {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("{t}")
}

fn hash_argv(argv: &[String]) -> String {
    let mut h = Sha256::new();
    for a in argv {
        h.update([a.len() as u8]);
        h.update(a.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|x| format!("{:02x}", x)).collect()
}

impl Supervisor {
    pub fn check(&self, req: &Request) -> Decision {
        toolcage_policy::decide(&self.policy, req)
    }

    /// Run argv array (no shell). Logs intent before spawn (I4) and outcome after.
    /// Streaming 1 MiB cap per stream + 30 s wall-clock kill (whole child).
    pub fn exec(&mut self, argv: &[String]) -> anyhow::Result<ExecOutcome> {
        self.exec_limits(argv, 30, 1024 * 1024)
    }

    /// Bounded exec: timeout_secs wall clock, cap_bytes per stream.
    /// Kill on timeout (fail-closed); truncation flagged in audit outcome.
    pub fn exec_limits(&mut self, argv: &[String], timeout_secs: u64, cap: usize) -> anyhow::Result<ExecOutcome> {
        anyhow::ensure!(!argv.is_empty(), "empty argv");
        let req = Request {
            action: "proc.exec".into(),
            host: None,
            method: None,
            path: None,
            fs_path: None,
            argv: Some(argv.to_vec()),
        };
        let d = self.check(&req);
        let mut w = Writer::open(&self.audit_path)?;
        let argv_hash = hash_argv(argv);
        // Write-ahead intent: store argv hash, never raw argv (secrets stay out of log).
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "agent".into(), action: "proc.exec".into(),
            request_hash: argv_hash.clone(), decision: if d.allow { "allow" } else { "deny" }.into(),
            rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
            result: "intent".into(), bytes: 0, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        if !d.allow {
            return Ok(ExecOutcome { allowed: false, rule_ids: d.rule_ids, exit_code: None, stdout: vec![], stderr: vec![] });
        }
        // Tier 0 runs inside a real namespace + Landlock + seccomp cage (I1),
        // Tier 1 runs inside runsc (gVisor). Both go through the wired backend;
        // otherwise fall back to direct spawn (tests that exercise supervisor-level
        // limits only).
        if self.tier == Tier::Tier0 || self.tier == Tier::Tier1 {
            if let Some(backend) = self.backend.as_mut() {
                let cr = backend.exec(&self.session, argv)?;
                w.append(Event {
                    seq: 0, ts_wall: now_wall(), session: self.session.clone(),
                    actor: "supervisor".into(), action: "proc.exec".into(),
                    request_hash: hash_argv(argv), decision: "allow".into(),
                    rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
                    result: format!("exit={:?} truncated={}", cr.exit_code, cr.truncated),
                    bytes: (cr.stdout.len() + cr.stderr.len()) as u64, claimed_by: "host".into(),
                    prev_hash: String::new(), hash: String::new(),
                })?;
                return Ok(ExecOutcome { allowed: true, rule_ids: d.rule_ids, exit_code: cr.exit_code, stdout: cr.stdout, stderr: cr.stderr });
            }
        }
        // env_clear: child never inherits host secrets (I2). Keep only minimal PATH.
        // Streaming cap: read at most cap+1 bytes per stream so a fork-bomb
        // writer cannot OOM the supervisor; overrun sets truncated=true.
        use std::io::Read;
        use std::process::Stdio;
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (tx_out, rx_out) = channel();
        let (tx_err, rx_err) = channel();
        let mut co = child.stdout.take();
        let mut ce = child.stderr.take();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(f) = co.take() {
                let _ = f.take((cap + 1) as u64).read_to_end(&mut buf);
            }
            let _ = tx_out.send(buf);
        });
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(f) = ce.take() {
                let _ = f.take((cap + 1) as u64).read_to_end(&mut buf);
            }
            let _ = tx_err.send(buf);
        });
        // Wall-clock timeout: poll, kill whole child on expiry (fail-closed).
        let mut timed_out = false;
        let code = {
            let mut waited = Duration::from_secs(0);
            let step = Duration::from_millis(50);
            let mut done = None;
            while waited.as_secs() < timeout_secs {
                match child.try_wait()? {
                    Some(st) => {
                        done = Some(st.code());
                        break;
                    }
                    None => {
                        std::thread::sleep(step);
                        waited += step;
                    }
                }
            }
            match done {
                Some(c) => c,
                None => {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    None
                }
            }
        };
        let mut stdout = rx_out.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        let mut stderr = rx_err.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        let mut truncated = timed_out;
        if stdout.len() > cap {
            stdout.truncate(cap);
            truncated = true;
        }
        if stderr.len() > cap {
            stderr.truncate(cap);
            truncated = true;
        }
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "supervisor".into(), action: "proc.exec".into(),
            request_hash: argv_hash, decision: "allow".into(),
            rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
            result: format!("exit={:?} truncated={} timeout={}", code, truncated, timed_out),
            bytes: (stdout.len() + stderr.len()) as u64, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        // Ensure caller stream flush ordering is deterministic.
        let _ = std::io::stdout().flush();
        Ok(ExecOutcome { allowed: true, rule_ids: d.rule_ids, exit_code: code, stdout, stderr })
    }

    /// Fetch via egress proxy + broker (M2). Guest never dials or holds secrets.
    /// Dual-auth: policy AND token must allow. Approval gate pauses when required.
    /// Returns guest-safe (scrubbed) body — secret values never included.
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_via_proxy(
        &self,
        broker: &toolcage_broker::Broker,
        budgets: &mut toolcage_proxy::Budgets,
        proxy: &mut toolcage_proxy::Proxy,
        alias_or_host: &str,
        method: &str,
        path: &str,
        token: Option<&toolcage_capability::Token>,
        revocation: &toolcage_capability::RevocationList,
        approved: bool,
    ) -> anyhow::Result<FetchOutcome> {
        let pd = toolcage_proxy::decide(&self.policy, alias_or_host, method, path);
        let mut w = Writer::open(&self.audit_path)?;
        // Token check (I3): narrow rights, valid tag, unexpired, not revoked.
        if let Some(t) = token {
            if revocation.is_revoked(t) || !t.verify_tag() || !t.allows(None, Some(alias_or_host), Some(method), None) {
                w.append(Event {
                    seq: 0, ts_wall: now_wall(), session: self.session.clone(),
                    actor: "agent".into(), action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(), decision: "deny".into(),
                    rule_ids: vec!["token:deny".into()], token_rev_id: t.rev_id.clone(),
                    result: "token-denied".into(), bytes: 0, claimed_by: "host".into(),
                    prev_hash: String::new(), hash: String::new(),
                })?;
                return Ok(FetchOutcome { allowed: false, need_approval: false, rule_ids: vec!["token:deny".into()], body: String::new() });
            }
        }
        // Approval gate: pause for out-of-band decision, timeout = deny.
        if pd.allow && self.policy.needs_approval("http.request", Some(method), Some(alias_or_host)) && !approved {
            w.append(Event {
                seq: 0, ts_wall: now_wall(), session: self.session.clone(),
                actor: "agent".into(), action: format!("http.request {method} {alias_or_host}{path}"),
                request_hash: "net".into(), decision: "need_approval".into(),
                rule_ids: vec!["approval:required".into()], token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                result: "paused-for-approval".into(), bytes: 0, claimed_by: "host".into(),
                prev_hash: String::new(), hash: String::new(),
            })?;
            return Ok(FetchOutcome { allowed: false, need_approval: true, rule_ids: vec!["approval:required".into()], body: String::new() });
        }
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "agent".into(), action: format!("http.request {method} {alias_or_host}{path}"),
            request_hash: "net".into(),
            decision: if pd.allow { "allow" } else { "deny" }.into(),
            rule_ids: pd.rule_ids.clone(), token_rev_id: "root".into(),
            result: "proxy-intent".into(), bytes: 0, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        if !pd.allow {
            return Ok(FetchOutcome { allowed: false, need_approval: false, rule_ids: pd.rule_ids, body: String::new() });
        }
        // Broker attaches credential upstream (host-side only). Guest sees placeholder.
        let cred_name = self
            .policy
            .credentials
            .iter()
            .find(|c| c.use_with.eq_ignore_ascii_case(alias_or_host)
                || (alias_or_host.to_ascii_lowercase().starts_with("github")
                    && c.use_with.eq_ignore_ascii_case("github")))
            .map(|c| c.name.clone());
        let upstream = pd.upstream.clone().unwrap_or_default();
        // Build auth header from broker-injected credential (never goes to guest).
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(cn) = &cred_name {
            if let Some(secret) = broker.inject(cn, &cred_name_alias(alias_or_host), method, path) {
                headers.push(("Authorization".to_string(), format!("Bearer {secret}")));
            }
        }
        // Real dial: proxy resolves DNS, connects (TLS if https), sends request.
        let resp = match proxy.fetch(&upstream, method, path, &headers) {
            Ok(r) => r,
            Err(e) => {
                w.append(Event {
                    seq: 0, ts_wall: now_wall(), session: self.session.clone(),
                    actor: "proxy".into(), action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(), decision: "deny".into(),
                    rule_ids: vec!["proxy-error".into()], token_rev_id: "root".into(),
                    result: format!("proxy-error: {e}").into(), bytes: 0, claimed_by: "host".into(),
                    prev_hash: String::new(), hash: String::new(),
                })?;
                return Ok(FetchOutcome { allowed: false, need_approval: false, rule_ids: vec!["proxy-error".into()], body: String::new() });
            }
        };
        let safe_body = broker.scrub(&String::from_utf8_lossy(&resp.body));
        // Egress damage bound (§8): per-destination byte + request budgets.
        // Zero limit = unbounded (back-compat); over-budget denies fail-closed.
        {
            let max_bytes = if self.policy.limits.egress_bytes == 0 { u64::MAX } else { self.policy.limits.egress_bytes };
            let max_req = if self.policy.limits.egress_requests == 0 { u64::MAX } else { self.policy.limits.egress_requests };
            if !budgets.check(alias_or_host, safe_body.len() as u64, max_bytes, max_req) {
                w.append(Event {
                    seq: 0, ts_wall: now_wall(), session: self.session.clone(),
                    actor: "proxy".into(), action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(), decision: "deny".into(),
                    rule_ids: vec!["budget:exceeded".into()], token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                    result: "over-egress-budget".into(), bytes: safe_body.len() as u64, claimed_by: "host".into(),
                    prev_hash: String::new(), hash: String::new(),
                })?;
                return Ok(FetchOutcome { allowed: false, need_approval: false, rule_ids: vec!["budget:exceeded".into()], body: String::new() });
            }
        }
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "proxy".into(), action: format!("http.request {method} {alias_or_host}{path}"),
            request_hash: "net".into(), decision: "allow".into(),
            rule_ids: pd.rule_ids.clone(), token_rev_id: "root".into(),
            result: format!("proxied upstream={upstream} status={} cred={}", resp.status, cred_name.as_deref().map(toolcage_broker::Broker::log_id).unwrap_or_else(|| "none".into())),
            bytes: safe_body.len() as u64, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        Ok(FetchOutcome { allowed: true, need_approval: false, rule_ids: pd.rule_ids, body: safe_body })
    }
}

fn cred_name_alias(alias_or_host: &str) -> String {
    let k = alias_or_host.to_ascii_lowercase();
    if k.starts_with("github") {
        "github".to_string()
    } else {
        k
    }
}

#[derive(Debug)]
pub struct FetchOutcome {
    pub allowed: bool,
    pub need_approval: bool,
    pub rule_ids: Vec<String>,
    pub body: String,
}

/// Panic path: freeze audit with final checkpoint event, mark host tainted.
/// Operator clears taint out-of-band. Sessions must be stopped by caller.
pub fn panic_freeze(audit_path: &std::path::Path, reason: &str) -> anyhow::Result<String> {
    let mut w = Writer::open(audit_path)?;
    let e = w.append(Event {
        seq: 0, ts_wall: now_wall(), session: "supervisor".into(),
        actor: "operator".into(), action: "panic".into(),
        request_hash: "panic".into(), decision: "deny-all".into(),
        rule_ids: vec!["panic:freeze".into()], token_rev_id: String::new(),
        result: format!("frozen: {reason}"),
        bytes: 0, claimed_by: "host".into(),
        prev_hash: String::new(), hash: String::new(),
    })?;
    let taint = audit_path.with_extension("tainted");
    std::fs::write(&taint, format!("tainted at {} head {}\n", e.ts_wall, e.hash))?;
    Ok(e.hash)
}
