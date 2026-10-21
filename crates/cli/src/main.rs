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
        #[arg(long, default_value = "tier0")]
        tier: String,
        /// Host path bind-mounted as `/workspace` inside Tier0 (defaults to cwd).
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// ESCAPE HATCH: run UNCONFINED on the host (tier0 only, never tier1/2).
        /// Off by default: without a wired backend the call is denied, not downgraded.
        #[arg(long, default_value_t = false)]
        unsafe_no_isolation: bool,
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
        /// Capability HMAC key file (64 hex chars), required to verify --token.
        #[arg(long)]
        key_hex: Option<PathBuf>,
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
    Panic {
        #[arg(long)]
        audit: PathBuf,
        #[arg(long, default_value = "operator panic")]
        reason: String,
    },
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
}

#[derive(Subcommand)]
enum Audit {
    Verify {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
    /// Sign checkpoint over current head (key file = 64 hex chars, 32 bytes).
    Checkpoint {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        key_hex: PathBuf,
    },
    /// Generate Ed25519 keypair (linux /dev/urandom); prints hex pubkey.
    Keygen {
        #[arg(long)]
        out_prefix: PathBuf,
    },
}

type AuditOp = Audit;

#[derive(Subcommand)]
enum McpOp {
    /// Serve stdio JSON-RPC (tools/call x4).
    Serve {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        audit: PathBuf,
        /// Isolation tier for run_command (guest processes are contained here).
        #[arg(long, default_value = "tier0")]
        tier: String,
        /// Host path bind-mounted as `/workspace` inside Tier0 (defaults to cwd).
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// ESCAPE HATCH: run tools UNCONFINED on the host (tier0 only, never tier1/2).
        #[arg(long, default_value_t = false)]
        unsafe_no_isolation: bool,
        /// Capability HMAC key file (64 hex chars) for token verification.
        #[arg(long)]
        key_hex: Option<PathBuf>,
    },
    /// Single call (for tests): --name run_command --args-json '{...}'.
    Call {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        audit: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "{}")]
        args_json: String,
        /// Isolation tier for run_command (guest processes are contained here).
        #[arg(long, default_value = "tier0")]
        tier: String,
        /// Host path bind-mounted as `/workspace` inside Tier0 (defaults to cwd).
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// ESCAPE HATCH: run tools UNCONFINED on the host (tier0 only, never tier1/2).
        #[arg(long, default_value_t = false)]
        unsafe_no_isolation: bool,
        /// Capability HMAC key file (64 hex chars) for token verification.
        #[arg(long)]
        key_hex: Option<PathBuf>,
    },
}

/// Wire the isolation backend for a session. Fail-closed by default: there is
/// always a backend, and it must honor the policy's min_isolation (exit 2
/// otherwise). `--unsafe-no-isolation` is the only route to `None`, it is
/// refused for tier1/tier2 (asking for strong isolation and none at once is a
/// contradiction), and it always warns — the run is additionally flagged
/// `isolation:unisolated` in the audit log by the supervisor.
fn wire_backend(
    tier_str: &str,
    t: toolcage_backend::Tier,
    pol: &toolcage_policy::Policy,
    spec: &toolcage_backend::SessionSpec,
    unsafe_no_isolation: bool,
) -> Option<Box<dyn toolcage_backend::Backend>> {
    if unsafe_no_isolation {
        if t != toolcage_backend::Tier::Tier0 {
            eprintln!("denied: --unsafe-no-isolation conflicts with --tier {tier_str}");
            std::process::exit(2);
        }
        eprintln!(
            "warning: --unsafe-no-isolation: commands run UNCONFINED on the host \
             (audited as isolation:unisolated)"
        );
        return None;
    }
    let mut b: Box<dyn toolcage_backend::Backend> = match t {
        toolcage_backend::Tier::Tier0 => Box::new(toolcage_backend_ns::NsBackend::new()),
        toolcage_backend::Tier::Tier1 => Box::new(toolcage_backend_gv::GvBackend::new()),
        toolcage_backend::Tier::Tier2 => Box::new(toolcage_backend_fc::FcBackend::new()),
    };
    if !b.honors(&pol.min_isolation) {
        eprintln!(
            "denied: backend {tier_str} cannot honor min_isolation {}",
            pol.min_isolation
        );
        std::process::exit(2);
    }
    if let Err(e) = b.create(spec) {
        eprintln!("denied: create isolated session: {e:#}");
        std::process::exit(2);
    }
    Some(b)
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
    /// Generate the capability HMAC key (host-side secret, 64 hex chars).
    Keygen {
        #[arg(long)]
        out_prefix: PathBuf,
    },
    /// Mint a root token (signed with the host key).
    Mint {
        #[arg(long)]
        rev: String,
        #[arg(long)]
        out: PathBuf,
        /// Host key file (64 hex chars), from `token keygen`.
        #[arg(long)]
        key_hex: PathBuf,
    },
    /// Attenuate parent token into narrower child.
    Attenuate {
        #[arg(long)]
        parent: PathBuf,
        #[arg(long)]
        rev: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "")]
        hosts: String,
        /// Methods to keep (comma-separated). Empty = inherit the parent's
        /// methods unchanged; an empty set grants nothing on this axis.
        #[arg(long, default_value = "")]
        methods: String,
        #[arg(long, default_value_t = 100)]
        budget: u64,
        /// Host key file (64 hex chars), from `token keygen`.
        #[arg(long)]
        key_hex: PathBuf,
    },
}

fn load_key(p: &Option<PathBuf>) -> anyhow::Result<Option<toolcage_capability::Key>> {
    match p {
        Some(f) => Ok(Some(toolcage_capability::Key::from_hex(
            &std::fs::read_to_string(f)?,
        )?)),
        None => Ok(None),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run {
            policy,
            audit,
            tier,
            workspace,
            unsafe_no_isolation,
            argv,
        } => {
            let text = std::fs::read_to_string(&policy).with_context(|| "read policy")?;
            let pol = toolcage_policy::load_yaml(&text)?;
            // Fail-closed tier selection: refuse policy the backend cannot honor.
            let t = toolcage_backend::Tier::parse(&tier)?;
            // Resolve workspace to an absolute path so it works from inside the
            // namespace regardless of cwd changes.
            let workspace = std::fs::canonicalize(&workspace).unwrap_or_else(|_| workspace.clone());
            let spec = toolcage_backend::SessionSpec {
                id: format!("run-{}", std::process::id()),
                tier: t,
                mem_mb: pol.limits.memory_mb,
                workspace_mb: 0, // not enforced yet; cgroup placement lands with the drivers
                workspace: workspace.display().to_string(),
            };
            let backend = wire_backend(&tier, t, &pol, &spec, unsafe_no_isolation);
            let mut sup = toolcage_supervisor::Supervisor {
                policy: pol,
                audit_path: audit,
                session: spec.id.clone(),
                tier: t,
                backend,
                allow_unisolated: unsafe_no_isolation,
                cap_key: None,
            };
            let o = sup.exec(&argv)?;
            if let Some(mut b) = sup.backend.take() {
                let _ = b.destroy(&spec.id);
            }
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
        Cmd::CheckNet {
            policy,
            host,
            method,
            path,
        } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let d = toolcage_proxy::decide(&pol, &host, &method, &path);
            println!(
                "{} {:?} {} upstream={:?}",
                if d.allow { "allow" } else { "deny" },
                d.rule_ids,
                d.reason,
                d.upstream
            );
            if !d.allow {
                std::process::exit(2);
            }
        }
        Cmd::Fetch {
            policy,
            audit,
            host,
            method,
            path,
            cred,
            secret_value,
            approve,
            token,
            key_hex,
        } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let cap_key = load_key(&key_hex)?;
            let sup = toolcage_supervisor::Supervisor {
                policy: pol,
                audit_path: audit,
                session: "cli".into(),
                tier: toolcage_backend::Tier::Tier0,
                backend: None,
                allow_unisolated: false,
                cap_key,
            };
            let mut broker = toolcage_broker::Broker::new();
            if !secret_value.is_empty() {
                broker.insert(toolcage_broker::Credential {
                    name: cred,
                    value: secret_value,
                    use_with: "github".into(),
                    methods: vec![],
                    paths: vec![],
                    expires_at: None,
                    encrypted_value: None,
                });
            }
            let tok = load_token(&token)?;
            let rl = toolcage_capability::RevocationList::default();
            let mut budgets = toolcage_proxy::Budgets::default();
            let mut proxy = toolcage_proxy::Proxy::new()?;
            let o = sup.fetch_via_proxy(
                &broker,
                &mut budgets,
                &mut proxy,
                &host,
                &method,
                &path,
                tok.as_ref(),
                &rl,
                approve,
            )?;
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
            TokenOp::Keygen { out_prefix } => {
                // Read exactly 32 bytes from urandom (fs::read would block forever).
                use std::io::Read;
                let mut rnd = std::fs::File::open("/dev/urandom")?;
                let mut kb = [0u8; 32];
                rnd.read_exact(&mut kb)?;
                let k = toolcage_capability::Key::from_bytes(kb);
                // REVIEW: key file stays host-side (never a guest, never a
                // token). Never commit *.key.hex.
                let dest = out_prefix.with_extension("key.hex");
                std::fs::write(&dest, k.to_hex())?;
                println!("wrote {}", dest.display());
            }
            TokenOp::Mint { rev, out, key_hex } => {
                let key = toolcage_capability::Key::from_hex(&std::fs::read_to_string(&key_hex)?)?;
                // Far-future expiry: allows() enforces wall-clock expiry fail-closed.
                let t = toolcage_capability::Token::root(
                    &key,
                    &rev,
                    toolcage_capability::Rights {
                        fs_prefixes: vec!["/workspace".into()],
                        net_hosts: vec!["github".into(), "registry.npmjs.org".into()],
                        methods: vec!["GET".into(), "POST".into()],
                        cred_use: vec!["github_token".into()],
                        budget_bytes: 1000,
                        expires_at: 9_999_999_999,
                    },
                );
                std::fs::write(&out, serde_json::to_string_pretty(&t)?)?;
                println!("minted {rev} -> {}", out.display());
            }
            TokenOp::Attenuate {
                parent,
                rev,
                out,
                hosts,
                methods,
                budget,
                key_hex,
            } => {
                let key = toolcage_capability::Key::from_hex(&std::fs::read_to_string(&key_hex)?)?;
                let p: toolcage_capability::Token =
                    serde_json::from_str(&std::fs::read_to_string(&parent)?)?;
                let hs: Vec<String> = if hosts.is_empty() {
                    vec![]
                } else {
                    hosts.split(',').map(|s| s.to_string()).collect()
                };
                // Empty --methods = inherit parent's methods (narrowing is
                // per-axis: unchanged on an axis is still <= the parent).
                let ms: Vec<String> = if methods.is_empty() {
                    p.rights.methods.clone()
                } else {
                    methods.split(',').map(|s| s.to_string()).collect()
                };
                // Child expiry: 1h from now, clamped to parent expiry so attenuation
                // never widens (and stays usable with wall-clock enforcement).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let child_exp = if p.rights.expires_at == 0 {
                    now + 3600
                } else {
                    p.rights.expires_at.min(now + 3600)
                };
                let c = p.attenuate(
                    &key,
                    &rev,
                    toolcage_capability::Rights {
                        fs_prefixes: vec![],
                        net_hosts: hs,
                        methods: ms,
                        cred_use: vec![],
                        budget_bytes: budget.min(p.rights.budget_bytes),
                        expires_at: child_exp,
                    },
                )?;
                std::fs::write(&out, serde_json::to_string_pretty(&c)?)?;
                println!("attenuated {} -> {rev}", p.rev_id);
            }
        },
        Cmd::Mcp { op } => match op {
            McpOp::Serve {
                policy,
                audit,
                tier,
                workspace,
                unsafe_no_isolation,
                key_hex,
            } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let t = toolcage_backend::Tier::parse(&tier)?;
                let cap_key = load_key(&key_hex)?;
                let workspace =
                    std::fs::canonicalize(&workspace).unwrap_or_else(|_| workspace.clone());
                let spec = toolcage_backend::SessionSpec {
                    id: format!("mcp-{}", std::process::id()),
                    tier: t,
                    mem_mb: pol.limits.memory_mb,
                    workspace_mb: 0,
                    workspace: workspace.display().to_string(),
                };
                // Tools run as contained guest processes under the same policy and
                // audit trail as `run` — a poisoned tool is a sandboxed process.
                let backend = wire_backend(&tier, t, &pol, &spec, unsafe_no_isolation);
                let mut sup = toolcage_supervisor::Supervisor {
                    policy: pol,
                    audit_path: audit,
                    session: spec.id.clone(),
                    tier: t,
                    backend,
                    allow_unisolated: unsafe_no_isolation,
                    cap_key,
                };
                let broker = toolcage_broker::Broker::new();
                let mut proxy = toolcage_proxy::Proxy::new()?;
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
                            let r = toolcage_mcp::RpcResp::deny(
                                serde_json::Value::Null,
                                &[format!("bad-request:{e}")],
                            );
                            println!("{}", serde_json::to_string(&r)?);
                            continue;
                        }
                    };
                    let resp = if req.method == "tools/call" {
                        match serde_json::from_value::<toolcage_mcp::CallParams>(req.params) {
                            Ok(cp) => match toolcage_mcp::route(
                                &mut sup,
                                &broker,
                                &mut proxy,
                                &mut toolcage_proxy::Budgets::default(),
                                None,
                                &toolcage_capability::RevocationList::default(),
                                &cp.name,
                                &cp.arguments,
                            ) {
                                Ok(v) => toolcage_mcp::RpcResp::ok(req.id, v),
                                Err(e) => toolcage_mcp::RpcResp::deny(req.id, &[e.to_string()]),
                            },
                            Err(e) => {
                                toolcage_mcp::RpcResp::deny(req.id, &[format!("bad-params:{e}")])
                            }
                        }
                    } else if req.method == "tools/list" {
                        toolcage_mcp::RpcResp::ok(
                            req.id,
                            serde_json::json!({"tools": ["run_command","read_file","write_file","http_fetch"]}),
                        )
                    } else {
                        toolcage_mcp::RpcResp::deny(req.id, &["unknown-method".into()])
                    };
                    println!("{}", serde_json::to_string(&resp)?);
                }
            }
            McpOp::Call {
                policy,
                audit,
                name,
                args_json,
                tier,
                workspace,
                unsafe_no_isolation,
                key_hex,
            } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let t = toolcage_backend::Tier::parse(&tier)?;
                let cap_key = load_key(&key_hex)?;
                let workspace =
                    std::fs::canonicalize(&workspace).unwrap_or_else(|_| workspace.clone());
                let spec = toolcage_backend::SessionSpec {
                    id: format!("mcp-call-{}", std::process::id()),
                    tier: t,
                    mem_mb: pol.limits.memory_mb,
                    workspace_mb: 0,
                    workspace: workspace.display().to_string(),
                };
                let backend = wire_backend(&tier, t, &pol, &spec, unsafe_no_isolation);
                let mut sup = toolcage_supervisor::Supervisor {
                    policy: pol,
                    audit_path: audit,
                    session: spec.id.clone(),
                    tier: t,
                    backend,
                    allow_unisolated: unsafe_no_isolation,
                    cap_key,
                };
                let broker = toolcage_broker::Broker::new();
                let mut proxy = toolcage_proxy::Proxy::new()?;
                let args: serde_json::Value = serde_json::from_str(&args_json)?;
                match toolcage_mcp::route(
                    &mut sup,
                    &broker,
                    &mut proxy,
                    &mut toolcage_proxy::Budgets::default(),
                    None,
                    &toolcage_capability::RevocationList::default(),
                    &name,
                    &args,
                ) {
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
            println!(
                "userns={} cgroup2={} landlock_abi={} seccomp={}",
                p.userns, p.cgroup2, p.landlock_abi, p.seccomp
            );
            println!("kvm={}", std::path::Path::new("/dev/kvm").exists());
            let gv = toolcage_backend_gv::GvBackend::probe();
            println!("runsc={} version={:?}", gv.runsc_present, gv.runsc_version);
            let st = std::process::Command::new("bash")
                .arg("scripts/doctor.sh")
                .status();
            if st.is_err() {
                println!("run scripts/doctor.sh");
            }
        }
        Cmd::Panic { audit, reason } => {
            let head = toolcage_supervisor::panic_freeze(&audit, &reason)?;
            println!("frozen head {head}; taint file written; clear it out-of-band");
        }
        Cmd::Audit { op } => match op {
            Audit::Verify { log, pubkey } => {
                if let Some(pkf) = pubkey {
                    // REVIEW: pinned-pubkey mode — chain + every sibling
                    // checkpoint must verify, or this fails (no silent skip).
                    let hex = std::fs::read_to_string(&pkf)?.trim().to_string();
                    let mut pk = vec![0u8; 32];
                    for i in 0..32 {
                        pk[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
                    }
                    let (n, head) = toolcage_audit::verify_with_pubkey(&log, Some(&pk))?;
                    println!("ok: {n} events, head {head} (checkpoints verified)");
                } else {
                    let (n, head) = toolcage_audit::verify(&log)?;
                    println!("ok: {n} events, head {head}");
                }
            }
            Audit::Checkpoint { log, key_hex } => {
                let hex = std::fs::read_to_string(&key_hex)?.trim().to_string();
                let mut sk = vec![0u8; 32];
                for i in 0..32 {
                    sk[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
                }
                let (n, head) = toolcage_audit::verify(&log)?;
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string();
                let cp = toolcage_audit::sign_checkpoint(n, &head, &t, &sk)?;
                let dest = log.with_extension(format!("jsonl.checkpoint.{n}"));
                // REVIEW: key file stays host-side; checkpoint (sig+pubkey) is
                // public. Never commit *-secret.hex.
                std::fs::write(&dest, serde_json::to_string_pretty(&cp)?)?;
                println!("checkpoint seq={n} -> {}", dest.display());
            }
            Audit::Keygen { out_prefix } => {
                // REVIEW fix: never fs::read() /dev/urandom (infinite stream —
                // it blocks forever and balloons RAM). Read exactly 32 bytes.
                use std::io::Read;
                let mut rnd = std::fs::File::open("/dev/urandom")?;
                let mut skb = [0u8; 32];
                rnd.read_exact(&mut skb)?;
                let sk_hex: String = skb.iter().map(|x| format!("{:02x}", x)).collect();
                let mut sk = vec![0u8; 32];
                for i in 0..32 {
                    sk[i] = u8::from_str_radix(&sk_hex[2 * i..2 * i + 2], 16)?;
                }
                // REVIEW: pubkey derived locally; secret never leaves host.
                let cp = toolcage_audit::sign_checkpoint(0, "GENESIS", "0", &sk)?;
                std::fs::write(out_prefix.with_extension("secret.hex"), &sk_hex)?;
                std::fs::write(out_prefix.with_extension("pub.hex"), &cp.pubkey_hex)?;
                println!(
                    "wrote {} + {}",
                    out_prefix.with_extension("secret.hex").display(),
                    out_prefix.with_extension("pub.hex").display()
                );
            }
        },
    }
    Ok(())
}
