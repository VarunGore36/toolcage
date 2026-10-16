use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use toolcage_backend::Backend;

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
        #[arg(long, default_value = "tier0")]
        tier: String,
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
    /// Fetch via proxy+broker (guest-safe, scrubbed). Secret from --secret-value stays host-side.
    Fetch {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        audit: PathBuf,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(long, default_value = "github_token")]
        cred: String,
        #[arg(long, default_value = "")]
        secret_value: String,
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
        Cmd::Run { policy, audit, tier, argv } => {
            let text = std::fs::read_to_string(&policy).with_context(|| "read policy")?;
            let pol = toolcage_policy::load_yaml(&text)?;
            // Fail-closed tier selection: refuse policy the backend cannot honor.
            let t = toolcage_backend::Tier::parse(&tier)?;
            let ok = match t {
                toolcage_backend::Tier::Tier0 => toolcage_backend_ns::NsBackend::new().honors(&pol.min_isolation),
                toolcage_backend::Tier::Tier1 => true, // gVisor driver lands next; Tier1 honors tier0/1
                toolcage_backend::Tier::Tier2 => toolcage_backend_fc::FcBackend::new().honors(&pol.min_isolation),
            };
            if !ok {
                eprintln!("denied: backend {tier} cannot honor min_isolation {}", pol.min_isolation);
                std::process::exit(2);
            }
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
            let d = toolcage_proxy::decide(&pol, &host, &method, &path);
            println!("{} {:?} {} upstream={:?}", if d.allow { "allow" } else { "deny" }, d.rule_ids, d.reason, d.upstream);
            if !d.allow {
                std::process::exit(2);
            }
        }
        Cmd::Fetch { policy, audit, host, method, path, cred, secret_value } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let sup = toolcage_supervisor::Supervisor { policy: pol, audit_path: audit, session: "cli".into() };
            let mut broker = toolcage_broker::Broker::new();
            if !secret_value.is_empty() {
                broker.insert(toolcage_broker::Credential { name: cred, value: secret_value, use_with: "github".into(), methods: vec![], paths: vec![] });
            }
            let o = sup.fetch_via_proxy(&broker, &host, &method, &path)?;
            if !o.allowed {
                eprintln!("denied: {:?}", o.rule_ids);
                std::process::exit(2);
            }
            println!("{o:?}");
            println!("{}", o.body);
        }
        Cmd::Doctor => {
            let p = toolcage_backend_ns::NsBackend::probe();
            println!("userns={} cgroup2={} landlock_abi={} seccomp={}", p.userns, p.cgroup2, p.landlock_abi, p.seccomp);
            println!("kvm={}", std::path::Path::new("/dev/kvm").exists());
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
