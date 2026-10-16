use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "toolcage")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run argv array under policy with audit (no shell)
    Run {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        audit: PathBuf,
        #[arg(trailing_var_arg = true, required = true)]
        argv: Vec<String>,
    },
    /// Check a network request against policy
    CheckNet {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "/")]
        path: String,
    },
    Doctor,
    Panic,
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
}

#[derive(Subcommand)]
enum Audit {
    Verify { #[arg(long)] log: PathBuf, #[arg(long)] pubkey: Option<PathBuf> },
}

type AuditOp = Audit;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { policy, audit, argv } => {
            let text = std::fs::read_to_string(&policy).with_context(|| "read policy")?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let sup = toolcage_supervisor::Supervisor { policy: pol, audit_path: audit, session: "cli".into() };
            let o = sup.exec(&argv)?;
            if !o.allowed {
                eprintln!("denied: {:?}", o.rule_ids);
                std::process::exit(2);
            }
            print!("{}", String::from_utf8_lossy(&o.stdout));
            eprint!("{}", String::from_utf8_lossy(&o.stderr));
            use std::io::Write as _Write;
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            std::process::exit(o.exit_code.unwrap_or(0));
        }
        Cmd::CheckNet { policy, host, method, path } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let d = toolcage_policy::decide(
                &pol,
                &toolcage_policy::Request { action: "http.request".into(), host: Some(host), method: Some(method), path: Some(path), fs_path: None, argv: None },
            );
            println!("{} {:?} {}", if d.allow { "allow" } else { "deny" }, d.rule_ids, d.reason);
            if !d.allow {
                std::process::exit(2);
            }
        }
        Cmd::Doctor => {
            let st = std::process::Command::new("bash").arg("scripts/doctor.sh").status();
            if st.is_err() {
                println!("run scripts/doctor.sh");
            }
        }
        Cmd::Panic => {
            println!("panic: stop all sessions (M6)");
        }
        Cmd::Audit { op } => match op {
            Audit::Verify { log, pubkey } => {
                if pubkey.is_some() {
                    eprintln!("note: signature checkpoints not yet enforced (M6); checking hash chain");
                }
                let (n, head) = toolcage_audit::verify(&log)?;
                println!("ok: {n} events, head {head}");
            }
        },
    }
    Ok(())
}
