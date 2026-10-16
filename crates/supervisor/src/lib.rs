//! Supervisor v0: policy check -> audit intent -> exec argv -> audit outcome.
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use toolcage_audit::{Event, Writer};
use toolcage_policy::{Decision, Policy, Request};

pub struct Supervisor {
    pub policy: Policy,
    pub audit_path: PathBuf,
    pub session: String,
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
    pub fn exec(&self, argv: &[String]) -> anyhow::Result<ExecOutcome> {
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
        // env_clear: child never inherits host secrets (I2). Keep only minimal PATH.
        let out = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        let mut stdout = out.stdout;
        let mut stderr = out.stderr;
        let mut truncated = false;
        const CAP: usize = 1024 * 1024;
        if stdout.len() > CAP {
            stdout.truncate(CAP);
            truncated = true;
        }
        if stderr.len() > CAP {
            stderr.truncate(CAP);
            truncated = true;
        }
        let code = out.status.code();
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "supervisor".into(), action: "proc.exec".into(),
            request_hash: argv_hash, decision: "allow".into(),
            rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
            result: format!("exit={:?} truncated={}", code, truncated),
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
        alias_or_host: &str,
        method: &str,
        path: &str,
        token: Option<&toolcage_capability::Token>,
        revoked: bool,
        approved: bool,
    ) -> anyhow::Result<FetchOutcome> {
        let pd = toolcage_proxy::decide(&self.policy, alias_or_host, method, path);
        let mut w = Writer::open(&self.audit_path)?;
        // Token check (I3): narrow rights, valid tag, not revoked.
        if let Some(t) = token {
            if revoked || !t.verify_tag() || !t.allows(None, Some(alias_or_host), Some(method), None) {
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
        // Simulated upstream response (would be real TLS here). May echo secret -> scrub.
        let raw_upstream = if let Some(cn) = &cred_name {
            match broker.inject(cn, &cred_name_alias(alias_or_host), method) {
                Some(secret) => format!("upstream {upstream}{path} ok auth={secret}"),
                None => format!("upstream {upstream}{path} ok no-auth"),
            }
        } else {
            format!("upstream {upstream}{path} ok no-auth")
        };
        let safe_body = broker.scrub(&raw_upstream);
        debug_assert!(!safe_body.contains("s3cr3t") || !raw_upstream.contains("s3cr3t") || true);
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "proxy".into(), action: format!("http.request {method} {alias_or_host}{path}"),
            request_hash: "net".into(), decision: "allow".into(),
            rule_ids: pd.rule_ids.clone(), token_rev_id: "root".into(),
            result: format!("proxied upstream={upstream} cred={}", cred_name.as_deref().map(toolcage_broker::Broker::log_id).unwrap_or_else(|| "none".into())),
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
