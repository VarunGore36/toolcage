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
        /// Secret value. UNSAFE: argv is visible to other local users via
        /// `ps` / `/proc/*/cmdline` and usually lands in shell history. Prefer
        /// --secret-file.
        #[arg(long, default_value = "")]
        secret_value: String,
        /// File holding the secret value. Read host-side, never on argv —
        /// the safe way to pass a credential to `fetch`.
        #[arg(long)]
        secret_file: Option<PathBuf>,
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
        /// Session capability token (JSON, as minted by `token mint`). REQUIRED
        /// when --key-hex is armed: the front door is dual-auth, policy AND
        /// token, so an agent cannot drop the token to escape its attenuation.
        #[arg(long)]
        token: Option<PathBuf>,
        /// Revoked rev_id (repeatable). Checked against every presented token
        /// and its parent chain on every call.
        #[arg(long = "revocation")]
        revocations: Vec<String>,
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
        /// Session capability token (JSON, as minted by `token mint`). REQUIRED
        /// when --key-hex is armed: the front door is dual-auth, policy AND
        /// token, so an agent cannot drop the token to escape its attenuation.
        #[arg(long)]
        token: Option<PathBuf>,
        /// Revoked rev_id (repeatable). Checked against every presented token
        /// and its parent chain on every call.
        #[arg(long = "revocation")]
        revocations: Vec<String>,
    },
}

/// Wire the isolation backend for a session. Fail-closed by default: there is
/// always a backend, and it must honor the policy's min_isolation (exit 2
/// otherwise). `--unsafe-no-isolation` is the only route to `None`, it is
/// refused for tier1/tier2 (asking for strong isolation and none at once is a
/// contradiction), and it always warns — the run is additionally flagged
/// `isolation:unisolated` in the audit log by the supervisor.
/// Can backend tier `tier` honor a policy demanding `min_isolation`?
/// Lattice: Tier0 < Tier1 < Tier2; a tier honors its own floor and anything
/// below it, never above. Unknown min_isolation strings deny. Used by the
/// CLI so the policy floor is enforced even when --unsafe-no-isolation runs
/// with no backend instance to consult.
fn tier_honors_min(tier: toolcage_backend::Tier, min_isolation: &str) -> bool {
    let need = match toolcage_backend::Tier::parse(min_isolation) {
        Ok(n) => n,
        Err(_) => return false,
    };
    matches!(
        (need, tier),
        (toolcage_backend::Tier::Tier0, _)
            | (
                toolcage_backend::Tier::Tier1,
                toolcage_backend::Tier::Tier1 | toolcage_backend::Tier::Tier2
            )
            | (toolcage_backend::Tier::Tier2, toolcage_backend::Tier::Tier2)
    )
}

fn wire_backend(
    tier_str: &str,
    t: toolcage_backend::Tier,
    pol: &toolcage_policy::Policy,
    spec: &toolcage_backend::SessionSpec,
    unsafe_no_isolation: bool,
) -> Option<Box<dyn toolcage_backend::Backend>> {
    // The policy's min_isolation floor applies to every run, including
    // --unsafe-no-isolation: an unconfined tier0 backend cannot honor a
    // policy demanding tier1/tier2, so refuse here instead of silently
    // running unconfined and weakening the policy.
    if !tier_honors_min(t, &pol.min_isolation) {
        eprintln!(
            "denied: tier {tier_str} cannot honor min_isolation {}",
            pol.min_isolation
        );
        std::process::exit(2);
    }
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
    if let Err(e) = b.create(spec) {
        eprintln!("denied: create isolated session: {e:#}");
        std::process::exit(2);
    }
    Some(b)
}

/// Budget persistence file for an audit log. The suffix is APPENDED, not
/// substituted for the extension: `with_extension("budgets.json")` collapsed
/// `audit.jsonl` / `audit.log` / `audit.v1` / `audit.v2` into one shared
/// `audit.budgets.json`, so one session could drain another's damage bound.
fn budget_file(audit: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.budgets.json", audit.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn budget_file_appends_not_replaces_extension() {
        use super::budget_file;
        use std::path::Path;
        // Distinct logs get distinct budget stores.
        let a = budget_file(Path::new("audit.jsonl"));
        let b = budget_file(Path::new("audit.log"));
        assert_eq!(a, Path::new("audit.jsonl.budgets.json"));
        assert_eq!(b, Path::new("audit.log.budgets.json"));
        assert_ne!(a, b, "distinct logs must not share a budget store");
        // The old with_extension naming collapsed them all.
        assert_ne!(a, Path::new("audit.budgets.json"));
    }
}

fn load_token(p: &Option<PathBuf>) -> anyhow::Result<Option<toolcage_capability::Token>> {
    if let Some(f) = p {
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(f)?)?))
    } else {
        Ok(None)
    }
}

/// Session revocation list from `--revocation` flags. The presented token is
/// tracked so that revoking a *parent* id invalidates the whole subtree.
fn build_revocations(
    ids: &[String],
    tok: Option<&toolcage_capability::Token>,
) -> toolcage_capability::RevocationList {
    let mut rl = toolcage_capability::RevocationList::default();
    for id in ids {
        rl.revoke(id);
    }
    if let Some(t) = tok {
        rl.track(t);
    }
    rl
}

/// Write secret material (keys / tokens / credentials) mode 0600:
/// `fs::write` defaults to 0644, which leaves secret bytes world-readable
/// on a multi-user host.
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Decode a 64-char (32-byte) hex string into [u8; 32]. Returns an error
/// (never panics) on wrong length, odd length, or non-hex input — replaces
/// the old `hex[2*i..2*i+2]` slicing that panicked on short or non-ASCII input.
fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    let b = s.as_bytes();
    anyhow::ensure!(
        b.len() == 64 && b.iter().all(|c| c.is_ascii_hexdigit()),
        "expected 64 hex chars (32 bytes), got {} chars",
        b.len()
    );
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| anyhow::anyhow!("bad hex at position {}", 2 * i))?;
    }
    Ok(out)
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
            // exit_code is None when the child died from a signal or was
            // killed by the wall-clock timeout: that is a failure, not
            // success. unwrap_or(0) used to report both as exit 0.
            std::process::exit(o.exit_code.unwrap_or(1));
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
            secret_file,
            approve,
            token,
            key_hex,
        } => {
            let text = std::fs::read_to_string(&policy)?;
            let pol = toolcage_policy::load_yaml(&text)?;
            let cap_key = load_key(&key_hex)?;
            // The credential is host-side material. Prefer --secret-file so it
            // never reaches argv, where every local user can read it from
            // ps / /proc/*/cmdline (and it lands in shell history).
            let secret_value = match &secret_file {
                Some(f) => std::fs::read_to_string(f)?.trim().to_string(),
                None => {
                    if !secret_value.is_empty() {
                        eprintln!(
                            "warning: --secret-value puts the credential on the command \
                             line (visible to other users via ps); prefer --secret-file"
                        );
                    }
                    secret_value
                }
            };
            // Destination the policy binds this credential to (used below when
            // the secret is loaded into the broker).
            let cred_use_with = pol
                .credentials
                .iter()
                .find(|c| c.name == cred)
                .map(|c| c.use_with.clone());
            // Persistent egress budget file, tied to the audit log so repeated
            // `fetch` calls accumulate damage across invocations (restart-safe).
            let budget_file = budget_file(&audit);
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
                // Bind the secret to the destination the policy names for this
                // credential. With no policy rule there is no authorized
                // destination, so the secret is not loaded at all rather than
                // bound to a hardcoded host.
                match cred_use_with {
                    Some(use_with) => {
                        broker.insert(toolcage_broker::Credential {
                            name: cred.clone(),
                            value: secret_value,
                            use_with,
                            methods: vec![],
                            paths: vec![],
                            expires_at: None,
                            encrypted_value: None,
                        });
                    }
                    None => {
                        eprintln!(
                            "warning: no policy credential named {cred}; secret not loaded"
                        );
                    }
                }
            }
            let tok = load_token(&token)?;
            let rl = toolcage_capability::RevocationList::default();
            let mut budgets =
                toolcage_proxy::Budgets::with_path(&budget_file).unwrap_or_else(|e| {
                    eprintln!("warning: budget persistence unavailable (in-memory): {e}");
                    toolcage_proxy::Budgets::default()
                });
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
                // Append .key.hex instead of with_extension: with_extension
                // replaces the existing extension, so out/a.v1 and out/a.v2
                // would both collapse to out/a.key.hex and clobber each other.
                let key_name = format!("{}.key.hex", out_prefix.display());
                let dest = std::path::Path::new(&key_name);
                write_secret(&dest, k.to_hex().as_bytes())?;
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
                write_secret(&out, serde_json::to_string_pretty(&t)?.as_bytes())?;
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
                write_secret(&out, serde_json::to_string_pretty(&c)?.as_bytes())?;
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
                token,
                revocations,
            } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let t = toolcage_backend::Tier::parse(&tier)?;
                let cap_key = load_key(&key_hex)?;
                let tok = load_token(&token)?;
                let rl = build_revocations(&revocations, tok.as_ref());
                // Persistent egress budget store, derived from the audit log.
                let budget_file = budget_file(&audit);
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
                let mut budgets =
                    toolcage_proxy::Budgets::with_path(&budget_file).unwrap_or_else(|e| {
                        eprintln!("warning: budget persistence unavailable (in-memory): {e}");
                        toolcage_proxy::Budgets::default()
                    });
                let stdin = std::io::stdin();
                use std::io::BufRead;
                for line in stdin.lock().lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    // Bound the frame: the id is reflected and the line is
                    // parsed whole, so an unbounded line is a memory amp.
                    if line.len() > 64 * 1024 {
                        let r = toolcage_mcp::RpcResp::error(
                            serde_json::Value::Null,
                            toolcage_mcp::PARSE_ERROR,
                            "frame too large",
                        );
                        println!("{}", serde_json::to_string(&r)?);
                        continue;
                    }
                    let req: toolcage_mcp::RpcReq = match serde_json::from_str(&line) {
                        Ok(r) => r,
                        Err(e) => {
                            // Parse error: the id is unknowable, so it is null.
                            let r = toolcage_mcp::RpcResp::error(
                                serde_json::Value::Null,
                                toolcage_mcp::PARSE_ERROR,
                                format!("parse error: {e}"),
                            );
                            println!("{}", serde_json::to_string(&r)?);
                            continue;
                        }
                    };
                    // JSON-RPC 2.0 request shape: version, id type and size.
                    if let Err((code, msg)) = req.validate() {
                        let r = toolcage_mcp::RpcResp::error(
                            req.id.clone().unwrap_or(serde_json::Value::Null),
                            code,
                            msg,
                        );
                        println!("{}", serde_json::to_string(&r)?);
                        continue;
                    }
                    // A notification is processed but MUST NOT be answered.
                    let respond = !req.is_notification();
                    let id = req.id.clone().unwrap_or(serde_json::Value::Null);
                    let resp = if req.method == "tools/call" {
                        match serde_json::from_value::<toolcage_mcp::CallParams>(req.params) {
                            Ok(cp) => match toolcage_mcp::route(
                                &mut sup,
                                &broker,
                                &mut proxy,
                                &mut budgets,
                                tok.as_ref(),
                                &rl,
                                &cp.name,
                                &cp.arguments,
                            ) {
                                Ok(v) => toolcage_mcp::RpcResp::ok(id, v),
                                Err(e) => toolcage_mcp::RpcResp::deny(id, &[e.to_string()]),
                            },
                            Err(e) => toolcage_mcp::RpcResp::error(
                                id,
                                toolcage_mcp::INVALID_PARAMS,
                                format!("invalid params: {e}"),
                            ),
                        }
                    } else if req.method == "tools/list" {
                        toolcage_mcp::RpcResp::ok(
                            id,
                            serde_json::json!({"tools": ["run_command","read_file","write_file","http_fetch"]}),
                        )
                    } else {
                        toolcage_mcp::RpcResp::error(
                            id,
                            toolcage_mcp::METHOD_NOT_FOUND,
                            "method not found",
                        )
                    };
                    if respond {
                        println!("{}", serde_json::to_string(&resp)?);
                    }
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
                token,
                revocations,
            } => {
                let text = std::fs::read_to_string(&policy)?;
                let pol = toolcage_policy::load_yaml(&text)?;
                let t = toolcage_backend::Tier::parse(&tier)?;
                let cap_key = load_key(&key_hex)?;
                let tok = load_token(&token)?;
                let rl = build_revocations(&revocations, tok.as_ref());
                // Persistent egress budget store, derived from the audit log.
                let budget_file = budget_file(&audit);
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
                let mut budgets =
                    toolcage_proxy::Budgets::with_path(&budget_file).unwrap_or_else(|e| {
                        eprintln!("warning: budget persistence unavailable (in-memory): {e}");
                        toolcage_proxy::Budgets::default()
                    });
                let args: serde_json::Value = serde_json::from_str(&args_json)?;
                match toolcage_mcp::route(
                    &mut sup,
                    &broker,
                    &mut proxy,
                    &mut budgets,
                    tok.as_ref(),
                    &rl,
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
                "namespaces={} cgroup2={} landlock_abi={} seccomp={}",
                p.namespaces, p.cgroup2, p.landlock_abi, p.seccomp
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
                    let pk = parse_hex32(&std::fs::read_to_string(&pkf)?)?;
                    let (n, head) = toolcage_audit::verify_with_pubkey(&log, Some(&pk))?;
                    println!("ok: {n} events, head {head} (checkpoints verified)");
                } else {
                    let (n, head) = toolcage_audit::verify(&log)?;
                    println!("ok: {n} events, head {head}");
                }
            }
            Audit::Checkpoint { log, key_hex } => {
                let sk = parse_hex32(&std::fs::read_to_string(&key_hex)?)?;
                let (n, head) = toolcage_audit::verify(&log)?;
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string();
                let cp = toolcage_audit::sign_checkpoint(n, &head, &t, &sk)?;
                let checkpoint_name = format!("{}.checkpoint.{}", log.display(), n);
                let dest = std::path::Path::new(&checkpoint_name);
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
                let sk = parse_hex32(&sk_hex)?;
                // REVIEW: pubkey derived locally; secret never leaves host.
                let cp = toolcage_audit::sign_checkpoint(0, "GENESIS", "0", &sk)?;
                // Append instead of with_extension: out/a.v1 and out/a.v2 must
                // get distinct key files, not both collapse to out/a.*.hex.
                let secret_name = format!("{}.secret.hex", out_prefix.display());
                let pubkey_name = format!("{}.pub.hex", out_prefix.display());
                let secret = std::path::Path::new(&secret_name);
                let pubkey = std::path::Path::new(&pubkey_name);
                write_secret(secret, sk_hex.as_bytes())?;
                std::fs::write(pubkey, &cp.pubkey_hex)?;
                println!(
                    "wrote {} + {}",
                    secret.display(),
                    pubkey.display()
                );
            }
        },
    }
    Ok(())
}
