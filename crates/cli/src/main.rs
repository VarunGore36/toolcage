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
        /// Out-of-band approval (operator approved). Without it, gated actions pause.
        #[arg(long, default_value_t = false)]
        approve: bool,
        /// Optional capability token JSON file (dual-auth: policy AND token).
        #[arg(long)]
        token: Option<PathBuf>,
    },
    /// Mint root token / attenuate child (never widens).
    Token {
        #[command(subcommand)]
        op: TokenOp,
    },
    /// MCP front door (stdio JSON-RPC).
    Mcp {
        #[command(subcommand)]
        op: McpOp,
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

#[derive(Subcommand)]
enum McpOp {
    /// Serve stdio JSON-RPC (tools/call x4).
    Serve {
        #[arg(long)] policy: PathBuf,
        #[arg(long)] audit: PathBuf,
    },
    /// Single call (for tests): --name run_command --args-json '{...}'.
    Call {
        #[arg(long)] policy: PathBuf,
        #[arg(long)] audit: PathBuf,
        #[arg(long)] name: String,
        #[arg(long, default_value = "{}")] args_json: String,
    },
}

fn load_token(p: &Option<PathBuf>) -> anyhow::Result<Option<toolcage_capability::Token>> {
    if let Some(f) = p {
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(f)?)?))
    } else {
        Ok(None)
    }
}

#[derive(Subcommand)]
enum TokenOp {
    /// Mint a root token.
    Mint {
        #[arg(long)] rev: String,
        #[arg(long)] out: PathBuf,
    },
    /// Attenuate parent token into narrower child.
    Attenuate {
        #[arg(long)] parent: PathBuf,
        #[arg(long)] rev: String,
        #[arg(long)] out: PathBuf,
        #[arg(long, default_value = "")] hosts: String,
        #[arg(long, default_value_t = 100)] budget: u64,
    },
}

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
                toolcage_backend::Tier::Tier1 => toolcage_backend_gv::GvBackend::new().honors(&pol.min_isolation),
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
        Cmd::Fetch { policy, audit, host, method, path, cred, secret_value, approve, token } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let sup = toolcage_supervisor::Supervisor { policy: pol, audit_path: audit, session: "cli".into() };
            let mut broker = toolcage_broker::Broker::new();
            if !secret_value.is_empty() {
                broker.insert(toolcage_broker::Credential { name: cred, value: secret_value, use_with: "github".into(), methods: vec![], paths: vec![] });
            }
            let tok = load_token(&token)?;
            let o = sup.fetch_via_proxy(&broker, &host, &method, &path, tok.as_ref(), false, approve)?;
            if o.need_approval {
                eprintln!("paused: approval required {:?}", o.rule_ids);
                std::process::exit(3);
            }
            if !o.allowed {
                eprintln!("denied: {:?}", o.rule_ids);
                std::process::exit(2);
            }
            println!("{o:?}");
            println!("{}", o.body);
        }
        Cmd::Token { op } => match op {
            TokenOp::Mint { rev, out } => {
                let t = toolcage_capability::Token::root(&rev, toolcage_capability::Rights {
                    fs_prefixes: vec!["/workspace".into()],
                    net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
                    methods: vec!["GET".into(), "POST".into()],
                    cred_use: vec!["github_token".into()],
                    budget_bytes: 1000,
                    expires_at: 9999,
                });
                std::fs::write(&out, serde_json::to_string_pretty(&t)?)?;
                println!("minted {rev} -> {}", out.display());
            }
            TokenOp::Attenuate { parent, rev, out, hosts, budget } => {
                let p: toolcage_capability::Token = serde_json::from_str(&std::fs::read_to_string(&parent)?)?;
                let hs: Vec<String> = if hosts.is_empty() { vec![] } else { hosts.split(',').map(|s| s.to_string()).collect() };
                let c = p.attenuate(&rev, toolcage_capability::Rights {
                    fs_prefixes: vec![],
                    net_hosts: hs,
                    methods: vec![],
                    cred_use: vec![],
                    budget_bytes: budget,
                    expires_at: 1,
                })?;
                std::fs::write(&out, serde_json::to_string_pretty(&c)?)?;
                println!("attenuated {} -> {rev}", p.rev_id);
            }
        },
        Cmd::Mcp { op } => match op {
            McpOp::Serve { policy, audit } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let sup = toolcage_supervisor::Supervisor { policy: pol, audit_path: audit, session: "mcp".into() };
                let broker = toolcage_broker::Broker::new();
                let stdin = std::io::stdin();
                use std::io::BufRead;
                for line in stdin.lock().lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let req: toolcage_mcp::RpcReq = match serde_json::from_str(&line) {
                        Ok(r) => r,
                        Err(e) => {
                            let r = toolcage_mcp::RpcResp::deny(serde_json::Value::Null, &[format!("bad-request:{e}")]);
                            println!("{}", serde_json::to_string(&r)?);
                            continue;
                        }
                    };
                    let resp = if req.method == "tools/call" {
                        match serde_json::from_value::<toolcage_mcp::CallParams>(req.params) {
                            Ok(cp) => match toolcage_mcp::route(&sup, &broker, None, &cp.name, &cp.arguments) {
                                Ok(v) => toolcage_mcp::RpcResp::ok(req.id, v),
                                Err(e) => toolcage_mcp::RpcResp::deny(req.id, &[e.to_string()]),
                            },
                            Err(e) => toolcage_mcp::RpcResp::deny(req.id, &[format!("bad-params:{e}")]),
                        }
                    } else if req.method == "tools/list" {
                        toolcage_mcp::RpcResp::ok(req.id, serde_json::json!({"tools": ["run_command","read_file","write_file","http_fetch"]}))
                    } else {
                        toolcage_mcp::RpcResp::deny(req.id, &["unknown-method".into()])
                    };
                    println!("{}", serde_json::to_string(&resp)?);
                }
            }
            McpOp::Call { policy, audit, name, args_json } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let sup = toolcage_supervisor::Supervisor { policy: pol, audit_path: audit, session: "mcp-call".into() };
                let broker = toolcage_broker::Broker::new();
                let args: serde_json::Value = serde_json::from_str(&args_json)?;
                match toolcage_mcp::route(&sup, &broker, None, &name, &args) {
                    Ok(v) => println!("{v}"),
                    Err(e) => {
                        eprintln!("denied: {e}");
                        std::process::exit(2);
                    }
                }
            }
        },
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
