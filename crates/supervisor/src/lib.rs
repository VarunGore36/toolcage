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
//! - Fail-closed exec: every tier runs through the wired backend. A missing
//!   backend is a DENIAL (rule `isolation:unavailable`), never a silent host
//!   spawn — Tier2 must not quietly degrade to zero isolation. The only
//!   unconfined path is the explicit `allow_unisolated` operator opt-in, and it
//!   is marked `isolation:unisolated` in the audit outcome so the log never
//!   shows an unconfined run as a sandboxed one.
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
    /// Explicit operator opt-in to run unconfined (CLI `--unsafe-no-isolation`).
    /// The ONLY route to a host spawn: with `backend: None` and this flag false,
    /// `exec` denies (`isolation:unavailable`) instead of falling back.
    pub allow_unisolated: bool,
    /// Host key for capability-token tags (I3). Tokens presented without a
    /// verifiable key are denied — fail closed, never "unverified but allowed".
    pub cap_key: Option<toolcage_capability::Key>,
}

pub struct ExecOutcome {
    pub allowed: bool,
    pub rule_ids: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn now_wall() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{t}")
}

fn hash_argv(argv: &[String]) -> String {
    let mut h = Sha256::new();
    for a in argv {
        // Length prefix as u64 (big-endian) so distinct argv can't collide by
        // wrapping mod 256 (the old as u8 did). The trailing NUL still
        // disambiguates for NUL-free args, and the prefix is the only
        // discriminator when args contain NUL.
        h.update(&(a.len() as u64).to_be_bytes());
        h.update(a.as_bytes());
        h.update([0u8]);
    }
    h.finalize().iter().map(|x| format!("{:02x}", x)).collect()
}

/// Upper-bound estimate of the HTTP request bytes we are about to send to the
/// upstream. Over-estimates on purpose (fail-closed): better to deny a valid
/// request than to let a credential-bearing request leave when over budget.
fn request_size_estimate(method: &str, path: &str, headers: &[(String, String)]) -> u64 {
    let mut n = method.len() + path.len() + 96; // request line + CRLFs + framing
    for (k, v) in headers {
        n += k.len() + 2 + v.len() + 2; // "k: v\r\n"
    }
    (n + 256) as u64 // safety margin
}

/// SIGKILL a workload's whole process group and reap the direct child.
///
/// The unconfined spawn is process_group(0)'d, so the child leads a group
/// that every process it forks shares: killing the group is what makes the
/// timeout a bound on the WORKLOAD, not just on the direct child (a forked
/// grandchild used to outlive the timeout and keep running on the host).
fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    unsafe { libc::killpg(pid, libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
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
    pub fn exec_limits(
        &mut self,
        argv: &[String],
        timeout_secs: u64,
        cap: usize,
    ) -> anyhow::Result<ExecOutcome> {
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
            seq: 0,
            ts_wall: now_wall(),
            session: self.session.clone(),
            actor: "agent".into(),
            action: "proc.exec".into(),
            request_hash: argv_hash.clone(),
            decision: if d.allow { "allow" } else { "deny" }.into(),
            rule_ids: d.rule_ids.clone(),
            token_rev_id: "root".into(),
            result: "intent".into(),
            bytes: 0,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        })?;
        if !d.allow {
            return Ok(ExecOutcome {
                allowed: false,
                rule_ids: d.rule_ids,
                exit_code: None,
                stdout: vec![],
                stderr: vec![],
            });
        }
        // Isolation is mandatory (I1/I6): every tier runs through the wired
        // backend — Tier 0 = namespaces + Landlock + seccomp, Tier 1 = runsc
        // (gVisor), Tier 2 = Firecracker. No tier is special-cased here: Tier 2
        // must never quietly degrade to a host spawn.
        if let Some(backend) = self.backend.as_mut() {
            let cr = backend.exec(&self.session, argv, timeout_secs, cap)?;
            w.append(Event {
                seq: 0,
                ts_wall: now_wall(),
                session: self.session.clone(),
                actor: "supervisor".into(),
                action: "proc.exec".into(),
                request_hash: hash_argv(argv),
                decision: "allow".into(),
                rule_ids: d.rule_ids.clone(),
                token_rev_id: "root".into(),
                result: format!("exit={:?} truncated={}", cr.exit_code, cr.truncated),
                bytes: (cr.stdout.len() + cr.stderr.len()) as u64,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })?;
            return Ok(ExecOutcome {
                allowed: true,
                rule_ids: d.rule_ids,
                exit_code: cr.exit_code,
                stdout: cr.stdout,
                stderr: cr.stderr,
            });
        }
        // No wired backend: fail closed and audit the denial. This is the whole
        // point of the change — a missing cage is a denial, not a fallback. The
        // `allow_unisolated` escape hatch is honored only for Tier0: Tier1/2
        // demand a real cage, and refusing beats downgrading.
        let refusal: Option<(&str, String)> = if !self.allow_unisolated {
            Some((
                "isolation:unavailable",
                "denied: no isolation backend".into(),
            ))
        } else if self.tier != Tier::Tier0 {
            Some((
                "isolation:downgrade-refused",
                format!("denied: {:?} never runs unisolated", self.tier),
            ))
        } else {
            None
        };
        if let Some((rule, why)) = refusal {
            w.append(Event {
                seq: 0,
                ts_wall: now_wall(),
                session: self.session.clone(),
                actor: "supervisor".into(),
                action: "proc.exec".into(),
                request_hash: argv_hash,
                decision: "deny".into(),
                rule_ids: vec![rule.into()],
                token_rev_id: "root".into(),
                result: why,
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })?;
            return Ok(ExecOutcome {
                allowed: false,
                rule_ids: vec![rule.into()],
                exit_code: None,
                stdout: vec![],
                stderr: vec![],
            });
        }
        // Explicit --unsafe-no-isolation opt-in: unconfined host spawn. Marked in
        // rule_ids AND the audit outcome so the log never shows this as sandboxed.
        let mut rule_ids = d.rule_ids.clone();
        rule_ids.push("isolation:unisolated".to_string());
        // env_clear: child never inherits host secrets (I2). Keep only minimal PATH.
        // Streaming cap: read at most cap+1 bytes per stream so a fork-bomb
        // writer cannot OOM the supervisor; overrun sets truncated=true.
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own process group: the timeout kill below must reach
            // everything the workload forks, not just the direct child.
            .process_group(0)
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
        // Wall-clock timeout: poll, kill the whole process group on expiry
        // (fail-closed). `child.kill()` alone SIGKILLs only the direct child —
        // everything it forked kept running on the host past the timeout.
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
                    kill_process_group(&mut child);
                    None
                }
            }
        };
        let mut stdout = rx_out
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        let mut stderr = rx_err
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
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
            seq: 0,
            ts_wall: now_wall(),
            session: self.session.clone(),
            actor: "supervisor".into(),
            action: "proc.exec".into(),
            request_hash: argv_hash,
            decision: "allow".into(),
            rule_ids: rule_ids.clone(),
            token_rev_id: "root".into(),
            result: format!(
                "exit={:?} truncated={} timeout={}",
                code, truncated, timed_out
            ),
            bytes: (stdout.len() + stderr.len()) as u64,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        })?;
        // Ensure caller stream flush ordering is deterministic.
        let _ = std::io::stdout().flush();
        Ok(ExecOutcome {
            allowed: true,
            rule_ids,
            exit_code: code,
            stdout,
            stderr,
        })
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
        // Destination identity (not spelling) for everything below: policy
        // already resolved the guest's alias to the operator's name, and the
        // approval gate, the credential binding and the egress budgets must
        // all key on the same thing. Otherwise `github.internal` passes policy
        // as `github` while slipping past a gate or budget written for `github`.
        let dest = toolcage_proxy::policy_host(&self.policy, alias_or_host);
        let dest_names = toolcage_proxy::destination_names(&self.policy, alias_or_host);
        // Credential bound to this destination, computed up front so the token
        // gate can enforce the `cred_use` axis at the point it matters: the
        // broker attaches this credential upstream, so the token must be
        // allowed to use it. Passing `None` here (the old code) skipped the
        // axis entirely, making `cred_use` attenuation advisory.
        let bound_cred = self
            .policy
            .credentials
            .iter()
            .find(|c| dest_names.iter().any(|n| n.eq_ignore_ascii_case(&c.use_with)));
        let mut w = Writer::open(&self.audit_path)?;
        // Token check (I3): valid keyed tag, narrow rights, unexpired, not
        // revoked. Fail closed: with no host key the tag cannot be verified,
        // so a presented token is denied, never waved through.
        //
        // Capability gate (I3): dual auth — policy AND a valid token must
        // allow. When a capability key is armed the token is MANDATORY: a
        // caller must not be able to drop it and fall back to policy-only
        // rights, which would make attenuation purely advisory. With no key
        // armed there is no capability system to enforce (policy is the only
        // gate) and a presented token cannot be verified, so it is refused
        // (fail closed). Revocation is checked for every presented token.
        let deny_rule: Option<&str> = match token {
            None => {
                if self.cap_key.is_some() {
                    Some("token:missing")
                } else {
                    None
                }
            }
            Some(t) => {
                let authorized = self
                    .cap_key
                    .as_ref()
                    .map(|k| {
                        t.verify_tag(k)
                            && t.allows(
                                k,
                                None,
                                Some(alias_or_host),
                                Some(method),
                                bound_cred.map(|c| c.name.as_str()),
                            )
                    })
                    .unwrap_or(false);
                if !authorized || revocation.is_revoked(t) {
                    Some("token:deny")
                } else {
                    None
                }
            }
        };
        if let Some(rule) = deny_rule {
            w.append(Event {
                seq: 0,
                ts_wall: now_wall(),
                session: self.session.clone(),
                actor: "agent".into(),
                action: format!("http.request {method} {alias_or_host}{path}"),
                request_hash: "net".into(),
                decision: "deny".into(),
                rule_ids: vec![rule.into()],
                token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                result: "token-denied".into(),
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })?;
            return Ok(FetchOutcome {
                allowed: false,
                need_approval: false,
                rule_ids: vec![rule.into()],
                body: String::new(),
            });
        }
        // Approval gate: pause for out-of-band decision, timeout = deny.
        // Matched over every spelling of the destination, so a request for
        // `github.internal` cannot dodge a gate written as `hosts: [github]`
        // (and vice versa) — policy already treats the two as one destination.
        let needs_ok = dest_names.iter().any(|n| {
            self.policy
                .needs_approval("http.request", Some(method), Some(n))
        });
        if pd.allow && needs_ok && !approved {
            w.append(Event {
                seq: 0,
                ts_wall: now_wall(),
                session: self.session.clone(),
                actor: "agent".into(),
                action: format!("http.request {method} {alias_or_host}{path}"),
                request_hash: "net".into(),
                decision: "need_approval".into(),
                rule_ids: vec!["approval:required".into()],
                token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                result: "paused-for-approval".into(),
                bytes: 0,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })?;
            return Ok(FetchOutcome {
                allowed: false,
                need_approval: true,
                rule_ids: vec!["approval:required".into()],
                body: String::new(),
            });
        }
        w.append(Event {
            seq: 0,
            ts_wall: now_wall(),
            session: self.session.clone(),
            actor: "agent".into(),
            action: format!("http.request {method} {alias_or_host}{path}"),
            request_hash: "net".into(),
            decision: if pd.allow { "allow" } else { "deny" }.into(),
            rule_ids: pd.rule_ids.clone(),
            token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
            result: "proxy-intent".into(),
            bytes: 0,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        })?;
        if !pd.allow {
            return Ok(FetchOutcome {
                allowed: false,
                need_approval: false,
                rule_ids: pd.rule_ids,
                body: String::new(),
            });
        }
        // Broker attaches credential upstream (host-side only). Guest sees placeholder.
        //
        // Destination binding (README: "not attached to requests for any other
        // host"): `use_with` names a destination, so it is matched against
        // every spelling of the request's destination — `github` and
        // `github.internal` are one upstream and share the credential, while a
        // look-alike such as `github.evil.com` is a different destination and
        // gets nothing. The broker re-checks the binding exactly with the
        // credential's own use_with string (defence in depth).
        let upstream = pd.upstream.clone().unwrap_or_default();
        // Build auth header from broker-injected credential (never goes to guest).
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(c) = bound_cred {
            if let Some(secret) = broker.inject(&c.name, &c.use_with, method, path) {
                headers.push(("Authorization".to_string(), format!("Bearer {secret}")));
            }
        }
        // Egress damage bound (§8): reserve budget for the outgoing request BEFORE
        // dialing, so a credential-bearing request never leaves the supervisor when
        // over budget. Zero limit = unbounded (back-compat).
        let max_bytes = if self.policy.limits.egress_bytes == 0 {
            u64::MAX
        } else {
            self.policy.limits.egress_bytes
        };
        let max_req = if self.policy.limits.egress_requests == 0 {
            u64::MAX
        } else {
            self.policy.limits.egress_requests
        };
        let req_est = request_size_estimate(method, path, &headers);
        // Budgets are keyed on the canonical destination so every spelling of
        // one upstream draws from one bucket (alias variants must not multiply
        // the damage bound).
        match budgets.check(&dest, req_est, max_bytes, max_req) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                w.append(Event {
                    seq: 0,
                    ts_wall: now_wall(),
                    session: self.session.clone(),
                    actor: "proxy".into(),
                    action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(),
                    decision: "deny".into(),
                    rule_ids: vec!["budget:exceeded".into()],
                    token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                    result: "over-egress-budget(precharge)".into(),
                    bytes: req_est,
                    claimed_by: "host".into(),
                    prev_hash: String::new(),
                    hash: String::new(),
                })?;
                return Ok(FetchOutcome {
                    allowed: false,
                    need_approval: false,
                    rule_ids: vec!["budget:exceeded".into()],
                    body: String::new(),
                });
            }
        }
        // Real dial: proxy resolves DNS, connects (TLS if https), sends request.
        // The response is read under the REMAINING egress budget: the damage
        // bound must bite during the transfer, not be charged after it (the
        // old flow buffered the whole response and only then discovered it was
        // over budget).
        let resp_cap = max_bytes.saturating_sub(budgets.used_bytes(&dest));
        let resp = match proxy.fetch(&upstream, method, path, &headers, resp_cap) {
            Ok(r) => r,
            Err(toolcage_proxy::ProxyError::Budget(e)) => {
                // The read stopped at the cap: no more than resp_cap bytes
                // were ever buffered, and nothing extra is charged.
                w.append(Event {
                    seq: 0,
                    ts_wall: now_wall(),
                    session: self.session.clone(),
                    actor: "proxy".into(),
                    action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(),
                    decision: "deny".into(),
                    rule_ids: vec!["budget:exceeded".into()],
                    token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                    result: format!("over-egress-budget(response): {e}"),
                    bytes: budgets.used_bytes(&dest),
                    claimed_by: "host".into(),
                    prev_hash: String::new(),
                    hash: String::new(),
                })?;
                return Ok(FetchOutcome {
                    allowed: false,
                    need_approval: false,
                    rule_ids: vec!["budget:exceeded".into()],
                    body: String::new(),
                });
            }
            Err(e) => {
                w.append(Event {
                    seq: 0,
                    ts_wall: now_wall(),
                    session: self.session.clone(),
                    actor: "proxy".into(),
                    action: format!("http.request {method} {alias_or_host}{path}"),
                    request_hash: "net".into(),
                    decision: "deny".into(),
                    rule_ids: vec!["proxy-error".into()],
                    token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                    result: format!("proxy-error: {e}"),
                    bytes: 0,
                    claimed_by: "host".into(),
                    prev_hash: String::new(),
                    hash: String::new(),
                })?;
                return Ok(FetchOutcome {
                    allowed: false,
                    need_approval: false,
                    rule_ids: vec!["proxy-error".into()],
                    body: String::new(),
                });
            }
        };
        let safe_body = broker.scrub(&String::from_utf8_lossy(&resp.body));
        // Egress damage bound (§8): the request was pre-charged before dialing;
        // charge the response now too. Note this counts resp.body (the real
        // bytes on the wire), not the scrubbed view — scrubbing shrinks the
        // body (secrets become "[REDACTED]"), and the damage bound must count
        // real volume. The pre-charged request estimate is not refunded, so
        // the total is a deliberate over-count (fail-closed).
        let max_bytes = if self.policy.limits.egress_bytes == 0 {
            u64::MAX
        } else {
            self.policy.limits.egress_bytes
        };
        if !budgets.charge_bytes(&dest, resp.body.len() as u64, max_bytes)? {
            w.append(Event {
                seq: 0,
                ts_wall: now_wall(),
                session: self.session.clone(),
                actor: "proxy".into(),
                action: format!("http.request {method} {alias_or_host}{path}"),
                request_hash: "net".into(),
                decision: "deny".into(),
                rule_ids: vec!["budget:exceeded".into()],
                token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
                result: "over-egress-budget(true-up)".into(),
                // What was charged (resp.body), not the scrubbed view the guest
                // sees — the audit must match the budget state.
                bytes: resp.body.len() as u64,
                claimed_by: "host".into(),
                prev_hash: String::new(),
                hash: String::new(),
            })?;
            return Ok(FetchOutcome {
                allowed: false,
                need_approval: false,
                rule_ids: vec!["budget:exceeded".into()],
                body: String::new(),
            });
        }
        w.append(Event {
            seq: 0,
            ts_wall: now_wall(),
            session: self.session.clone(),
            actor: "proxy".into(),
            action: format!("http.request {method} {alias_or_host}{path}"),
            request_hash: "net".into(),
            decision: "allow".into(),
            rule_ids: pd.rule_ids.clone(),
            token_rev_id: token.map(|t| t.rev_id.clone()).unwrap_or_default(),
            result: format!(
                "proxied upstream={upstream} status={} cred={}",
                resp.status,
                bound_cred
                    .map(|c| toolcage_broker::Broker::log_id(&c.name))
                    .unwrap_or_else(|| "none".into())
            ),
            // What was charged (resp.body), not the scrubbed view the guest
            // sees — the audit must match the budget state.
            bytes: resp.body.len() as u64,
            claimed_by: "host".into(),
            prev_hash: String::new(),
            hash: String::new(),
        })?;
        Ok(FetchOutcome {
            allowed: true,
            need_approval: false,
            rule_ids: pd.rule_ids,
            body: safe_body,
        })
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
        seq: 0,
        ts_wall: now_wall(),
        session: "supervisor".into(),
        actor: "operator".into(),
        action: "panic".into(),
        request_hash: "panic".into(),
        decision: "deny-all".into(),
        rule_ids: vec!["panic:freeze".into()],
        token_rev_id: String::new(),
        result: format!("frozen: {reason}"),
        bytes: 0,
        claimed_by: "host".into(),
        prev_hash: String::new(),
        hash: String::new(),
    })?;
    let taint = audit_path.with_extension("tainted");
    std::fs::write(
        &taint,
        format!("tainted at {} head {}\n", e.ts_wall, e.hash),
    )?;
    Ok(e.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_argv_deterministic_and_disambiguates() {
        // Same argv -> same hash (deterministic).
        let a = hash_argv(&["/bin/echo".into(), "hello".into()]);
        assert_eq!(a, hash_argv(&["/bin/echo".into(), "hello".into()]));

        // The NUL length-prefix separator avoids concatenation ambiguity:
        // ["ab"] must not hash the same as ["a", "b"].
        assert_ne!(
            hash_argv(&["ab".into()]),
            hash_argv(&["a".into(), "b".into()]),
            "NUL separator must prevent argv concatenation ambiguity"
        );

        // Arguments longer than 255 bytes must be hashed fully: the old u8
        // length prefix wrapped mod 256 (300 and 44 both became 44). With u64
        // the full length is preserved, so distinct arguments stay distinct.
        let long = "A".repeat(300);
        let short = "A".repeat(44);
        assert_ne!(
            hash_argv(&[long]),
            hash_argv(&[short]),
            "arguments longer than 255 bytes must not collide on the u8 length prefix"
        );

        // An empty argument still hashes distinctly from a missing one.
        assert_ne!(
            hash_argv(&["".into()]),
            hash_argv(&[]),
            "empty argv must differ from no argv"
        );
    }
}
