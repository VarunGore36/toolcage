//! Supervisor v0: policy check -> audit intent -> exec argv -> audit outcome.
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
        };
        let d = self.check(&req);
        let mut w = Writer::open(&self.audit_path)?;
        // Write-ahead intent
        w.append(Event {
            seq: 0, ts_wall: now_wall(), session: self.session.clone(),
            actor: "agent".into(), action: format!("proc.exec {:?}", argv),
            request_hash: "argv".into(), decision: if d.allow { "allow" } else { "deny" }.into(),
            rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
            result: "intent".into(), bytes: 0, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        if !d.allow {
            return Ok(ExecOutcome { allowed: false, rule_ids: d.rule_ids, exit_code: None, stdout: vec![], stderr: vec![] });
        }
        // Cap output at 1 MiB (truncation noted in outcome)
        let out = Command::new(&argv[0]).args(&argv[1..]).output()?;
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
            actor: "supervisor".into(), action: format!("proc.exec {:?}", argv),
            request_hash: "argv".into(), decision: "allow".into(),
            rule_ids: d.rule_ids.clone(), token_rev_id: "root".into(),
            result: format!("exit={:?} truncated={}", code, truncated),
            bytes: (stdout.len() + stderr.len()) as u64, claimed_by: "host".into(),
            prev_hash: String::new(), hash: String::new(),
        })?;
        Ok(ExecOutcome { allowed: true, rule_ids: d.rule_ids, exit_code: code, stdout, stderr })
    }
}
