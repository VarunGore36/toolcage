//! Policy v0: YAML allowlist + default-deny. See schemas/policy-v0.yaml.
//!
//! REVIEW (2026-10-16):
//! - Trust: operator-written YAML is trusted; every Request field is untrusted
//!   (guest/model controlled). Never log Request verbatim (see supervisor argv hash).
//! - Default-deny: unknown actions/hosts/paths deny. `forbid:metadata` runs first
//!   and always wins, even over allowlist entries (I6).
//! - Canonicalize-at-enforcement: fs checks use lexical canonical_path() here,
//!   but Tier 2 guests own their FS so real enforcement is mount design; host
//!   re-checks on file transfer. Lexical only — does NOT resolve symlinks;
//!   symlink races must be closed at the open() site with O_NOFOLLOW.
//! - Case: hosts lowercased, methods uppercased before compare. A policy author
//!   writing `get` still matches `GET`; `REGISTRY...` matches. Deny stays
//!   fail-closed on mismatch.
//! - Glob: only trailing `/**` supported. `*` mid-pattern is literal — do not
//!   assume shell glob semantics when writing paths.
//! - Shell: proc.exec allows argv arrays but denies shells
//!   (sh, bash, dash, zsh, fish, ksh, tcsh, csh, busybox) given any inline
//!   command flag (-c, -lc, -cic, ...), and interpreters (python, perl, ruby,
//!   node, lua, php) given their inline-code flag (-c/-e/-r). Prefer an
//!   explicit allowlist of binaries in a later milestone.
//! - Approval: require_for is data only; enforcement lives in supervisor
//!   (pause + audit). An empty methods/hosts list means "all of that action".
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub tool: String,
    #[serde(default = "default_tier")]
    pub min_isolation: String,
    #[serde(default)]
    pub fs: FsPolicy,
    #[serde(default)]
    pub net: NetPolicy,
    #[serde(default)]
    pub credentials: Vec<CredRule>,
    #[serde(default)]
    pub approval: ApprovalPolicy,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub exec: ExecPolicy,
}

/// Exec authorization for `proc.exec`.
///
/// The v0 denylist (below) blocks shells/interpreters fed inline code, but a
/// denylist is inherently incomplete — wrappers (`env python3 -c`), renamed
/// binaries and new flag spellings keep finding holes. An explicit allowlist
/// closes the class: when `allowlist` is non-empty, ONLY those binaries may
/// run, whatever else argv looks like.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExecPolicy {
    /// Binaries permitted to run, matched on the argv[0] basename with version
    /// tolerance (`python3.12` matches `python3`). Empty = no allowlist
    /// configured, so the denylist below is the only gate (back-compat).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Resource bounds (M2 damage bound). Zero means "no bound set" for that axis
/// except egress_bytes, which callers treat as unlimited when 0 for back-compat.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Limits {
    #[serde(default)]
    pub cpu_seconds: u64,
    #[serde(default)]
    pub memory_mb: u64,
    #[serde(default)]
    pub egress_bytes: u64,
    #[serde(default)]
    pub egress_requests: u64,
}

fn default_tier() -> String {
    "tier0".into()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FsPolicy {
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mount {
    pub path: String,
    pub mode: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetPolicy {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
}

/// Derived Default would give `mode: ""`, bypassing `default_mode()` — a
/// policy with no `net:` section and one with `net:` but no `mode:` must not
/// disagree ("" vs "deny").
impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            hosts: Vec::new(),
        }
    }
}

fn default_mode() -> String {
    "deny".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostRule {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredRule {
    pub name: String,
    pub use_with: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApprovalPolicy {
    #[serde(default)]
    pub require_for: Vec<std::collections::HashMap<String, ApprovalSpec>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApprovalSpec {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub action: String,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub fs_path: Option<String>,
    pub argv: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allow: bool,
    pub rule_ids: Vec<String>,
    pub reason: String,
}

/// Whether a mount mode permits writes. ONLY an explicit `rw` does.
///
/// The old check was `mode == "ro"` on the deny side, so every unrecognized
/// spelling — `readonly`, `read-only`, `r0`, empty — silently became WRITABLE.
/// A typo in a read-only mount is exactly the case that must not open a
/// write path: anything that is not explicitly rw denies writes.
fn mount_allows_write(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("rw")
}

pub fn load_yaml(s: &str) -> anyhow::Result<Policy> {
    let p: Policy = serde_yaml::from_str(s)?;
    // Unknown `mode` spellings must fail closed at load, not degrade into
    // whatever the runtime happens to do with the string (a writable "readonly"
    // mount, a silently ignored net mode).
    for m in &p.fs.mounts {
        anyhow::ensure!(
            m.mode.eq_ignore_ascii_case("ro") || m.mode.eq_ignore_ascii_case("rw"),
            "unknown fs mount mode {:?} on {} (want ro or rw)",
            m.mode,
            m.path
        );
    }
    anyhow::ensure!(
        p.net.mode.eq_ignore_ascii_case("allowlist") || p.net.mode.eq_ignore_ascii_case("deny"),
        "unknown net mode {:?} (want allowlist or deny)",
        p.net.mode
    );
    Ok(p)
}

impl Policy {
    /// Approval gate from policy file: require_for entries (timeout = deny).
    ///
    /// Fail closed on unknown: an absent/empty method or host is UNKNOWN, not
    /// "matches nothing". decide() used to default a missing method to GET
    /// while this gate saw "" and passed — a method-less request sailed past
    /// every gate written for GET. Unknown values must not escape a
    /// method/host-constrained gate.
    pub fn needs_approval(&self, action: &str, method: Option<&str>, host: Option<&str>) -> bool {
        for entry in &self.approval.require_for {
            for (act, spec) in entry {
                if act != action {
                    continue;
                }
                if !spec.methods.is_empty() {
                    let m = method.unwrap_or("");
                    if m.is_empty() || !spec.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
                        continue;
                    }
                }
                if !spec.hosts.is_empty() {
                    let h = host.unwrap_or("");
                    if h.is_empty() || !spec.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                        continue;
                    }
                }
                return true;
            }
        }
        false
    }
}

/// Canonicalize fs path: resolve `.`, `..`, duplicate `/` lexically (no FS access).
pub fn canonical_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return "/".to_string();
    }
    let cap: usize = parts.iter().map(|s| 1 + s.len()).sum();
    let mut out = String::with_capacity(cap);
    for part in parts {
        out.push('/');
        out.push_str(part);
    }
    out
}

fn path_match(pattern: &str, path: &str) -> bool {
    // Support trailing /** only (v0). Exact otherwise.
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    } else {
        pattern == path
    }
}

#[inline]
fn contains_ignore_ascii_case(haystack: &str, needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

/// RFC 7230 token: the only shape allowed in a request method. Anything else
/// (space, CR/LF, NUL) would let the guest restructure the request line that
/// the proxy later writes verbatim.
pub fn method_is_token(m: &str) -> bool {
    !m.is_empty()
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A request target we can both authorise AND forward unchanged.
///
/// The path is matched as a string and then written verbatim into the upstream
/// request line, so anything that makes the string we authorised differ from
/// the resource the upstream serves is denied here:
///   - control characters, space, quotes, backslash: request-line and header
///     injection (`/x HTTP/1.1\r\nX-Injected: 1`), request smuggling;
///   - "." / ".." segments and percent-encoded dots or separators: traversal
///     past a `/**` prefix, since the upstream decodes and normalizes those
///     itself (`/repos/acme/app/../../../evil` matches the prefix as a string
///     but resolves to `/evil` upstream).
///
/// A clean target is already canonical, so prefix matching on it is sound.
pub fn request_target_is_clean(p: &str) -> bool {
    if !p.starts_with('/') {
        return false;
    }
    // The whole target is written into the request line, so nothing that could
    // end it early (or split a header off it) may appear anywhere in it.
    if !p
        .bytes()
        .all(|b| b > 0x20 && b != 0x7f && b != b'\\' && b != b'"' && b != b'<')
    {
        return false;
    }
    // Traversal checks apply to the path component; the query is free-form and
    // the upstream does not resolve it as a path.
    let path = p.split('?').next().unwrap_or("");
    if path.as_bytes().windows(3).any(|w| {
        w[0] == b'%'
            && (w[1..].eq_ignore_ascii_case(b"2e")
                || w[1..].eq_ignore_ascii_case(b"2f")
                || w[1..].eq_ignore_ascii_case(b"5c"))
    }) {
        return false;
    }
    path.split('/').all(|seg| seg != "." && seg != "..")
}

/// Shell binaries whose `-c`-style flag executes an arbitrary command string.
/// A bare denylist is inherently incomplete; prefer an explicit exec allowlist
/// in a later milestone. Until then, deny these plus any inline-code flag,
/// wherever they appear in argv (argv[0] or reached via `env sh -c`).
const SHELL_BINS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "tcsh", "csh", "busybox",
];

/// Interpreters and the flags that feed them an inline code string. Several
/// spellings matter: `-c`/`-C` for python, `-e`/`-E` for perl/ruby/node/lua,
/// `-p`/`--eval`/`--print` for node, `-r`/`-R` for php. The old single
/// lowercase spelling let `perl -E`, `node -p` and `php -R` through — all of
/// which execute arbitrary code exactly like the denied forms. Binaries are
/// matched with version tolerance (`python3.12`, `perl5`).
fn interpreter_flags(bin: &str) -> &'static [&'static str] {
    const NONE: &[&str] = &[];
    let known: &[(&str, &[&str])] = &[
        ("python", &["-c", "-C"]),
        ("python3", &["-c", "-C"]),
        // -x: perl/ruby extract the PROGRAM from a file (skipping leading
        // garbage until #!): `perl -x /workspace/evil.pl` runs guest program
        // text — same class as -e, just sourced from a file.
        ("perl", &["-e", "-E", "-x"]),
        ("ruby", &["-e", "-E", "-x"]),
        ("node", &["-e", "-E", "-p", "-P", "--eval", "--print"]),
        ("lua", &["-e", "-E"]),
        ("php", &["-r", "-R"]),
    ];
    known
        .iter()
        .find(|(k, _)| bin_matches(bin, k))
        .map(|(_, f)| *f)
        .unwrap_or(NONE)
}

/// True if `name` names a known binary, tolerating version suffixes:
/// `python3.12` → `python3`, `bash5` → `bash`, `busybox-1.35` → `busybox`.
/// The known name must be a prefix; everything after it must look like a
/// version (digits and dots) so `python3x` does not match `python`.
fn bin_matches(name: &str, known: &str) -> bool {
    name == known
        || name.strip_prefix(known).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
        })
}

/// True for shell short-flag args that run an inline command string:
/// `-c`, `-lc`, `-cic`, etc. Single-dash flags only (not `--long`).
fn shell_inline_flag(a: &str) -> bool {
    let b = a.as_bytes();
    b.len() >= 2 && b[0] == b'-' && b[1] != b'-' && a.contains('c')
}

/// True when `arg` supplies an inline-code flag from `flags`: a direct or
/// joined match (`-c`, `-cprint(1)`, `--eval=1`) — or the flag's letter
/// bundled in a single-dash short-option cluster (`python3 -ic` is `-i -c`,
/// `perl -le` is `-l -e`). The old check was `b == f || b.starts_with(f)`,
/// which missed every bundled form where another short flag precedes the
/// inline one.
fn interpreter_inline_arg(arg: &str, flags: &[&str]) -> bool {
    if flags.iter().any(|f| arg == *f || arg.starts_with(*f)) {
        return true;
    }
    let b = arg.as_bytes();
    if b.len() >= 2 && b[0] == b'-' && b[1] != b'-' {
        for f in flags {
            let fb = f.as_bytes();
            // Short flags only: the letter after the single dash IS the flag.
            if fb.len() == 2 && fb[0] == b'-' && b[1..].contains(&fb[1]) {
                return true;
            }
        }
    }
    false
}

/// Deny reason for argv shapes that smuggle inline command text past
/// argv-array scrutiny, or None when the v0 denylist accepts the argv.
/// Pure and testable; called from decide()'s proc.exec arm.
///
/// A shell binary anywhere in argv (argv[0] itself, or reached indirectly
/// via `env sh -c`) running an inline-code string executes arbitrary command
/// text outside argv-array scrutiny. Running a shell script file is the same
/// class of risk as `sh -c`, so either form is denied. Interpreters given
/// inline code are denied WHEREVER they appear in argv, not just argv[0]:
/// `env python3 -c`, `nice perl -E` and `timeout 5 python3 -c` must be
/// caught just like `python3 -c`. Every spelling of the inline-code flag is
/// matched (see interpreter_flags): `-c`, `-e`, `-E`, `-p`, `--eval`, `-r`,
/// `-R`, and the joined forms (`-ccode`).
fn exec_inline_denial(argv: &[String]) -> Option<&'static str> {
    let bin = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
    let rest = &argv[1..];
    // env(1) split-string: `-S` (also joined as `-S<value>`) hands env a
    // whole command line to split at exec time, so neither a shell name nor
    // an inline flag is ever a separate argv token — `env -S "sh -c id"`
    // runs arbitrary shell while the scanner below sees an ordinary argv.
    // Match env by basename wherever it appears and fail closed on ANY
    // -S form: the value is an arbitrary command line the denylist cannot
    // meaningfully scope. (`env -S` is rare in legitimate argv-array
    // workloads; operators who need it have exec.allowlist.)
    let env_here = bin_matches(bin, "env")
        || rest.iter().any(|a| {
            let name = a.rsplit('/').next().unwrap_or(a);
            bin_matches(name, "env")
        });
    if env_here
        && rest
            .iter()
            .any(|a| a == "-S" || a.starts_with("-S") || a.starts_with("--split-string"))
    {
        return Some("env split-string (-S) runs an inline command line; use argv arrays");
    }
    // Strip the path in argv[1..] too: `bin_matches` compares basenames, and
    // `bin_matches("/bin/sh", "sh")` is false — so `env /bin/sh -c` and
    // `/bin/busybox /bin/sh evil.sh` would otherwise reach the gates below
    // with shell_here=false.
    let shell_here = SHELL_BINS.iter().any(|s| bin_matches(bin, s))
        || rest.iter().any(|a| {
            let name = a.rsplit('/').next().unwrap_or(a);
            SHELL_BINS.iter().any(|s| bin_matches(name, s))
        });
    if shell_here && rest.iter().any(|a| shell_inline_flag(a)) {
        return Some("shell -c is not allowed; use argv arrays");
    }
    if shell_here && rest.iter().any(|a| !a.starts_with('-')) {
        return Some("shell script files are not allowed; use argv arrays");
    }
    // Startup-file flags: `bash --rcfile=/workspace/evil.sh -i` sources the
    // script at startup. The script-file rule above only rejects args NOT
    // starting with '-', so the '=' form hides the path behind a dash.
    // (--rcfile/--init-file with a separate path argument is already caught
    // by that rule — the path is a non-dash arg.) Deny the flags outright:
    // a shell that sources an operator-unspecified startup file is exactly
    // the inline-command-text class.
    if shell_here
        && rest
            .iter()
            .any(|a| a.starts_with("--rcfile") || a.starts_with("--init-file"))
    {
        return Some("shell startup-file flags (--rcfile/--init-file) are not allowed");
    }
    // Interpreters whose PROGRAM TEXT arrives as a positional argv token:
    // every awk invocation executes code from argv (or -f file), and
    // system() gives it the shell — there is no non-code-executing use to
    // preserve, so the family is denied outright (version-tolerant:
    // gawk-5.1 matches gawk). Not a shell and not in interpreter_flags,
    // so nothing else fires for it.
    const AWK_BINS: &[&str] = &["awk", "gawk", "mawk"];
    let awk_here = AWK_BINS.iter().any(|s| bin_matches(bin, s))
        || rest.iter().any(|a| {
            let name = a.rsplit('/').next().unwrap_or(a);
            AWK_BINS.iter().any(|s| bin_matches(name, s))
        });
    if awk_here {
        return Some("awk program text is inline code; use argv arrays or an exec allowlist");
    }
    // python -m executes a module by name, and with -m the cwd is
    // sys.path[0]: `python3 -m evil` imports and runs /workspace/evil.py —
    // guest-written code under the trusted python3 name. Denied for
    // python/python3 (version-tolerant) wherever python appears, including
    // cluster forms (-Bm). This also denies legitimate module runs
    // (python3 -m http.server); script-file form (python3 script.py) stays
    // allowed, and operators who need -m have exec.allowlist.
    const PYTHON_BINS: &[&str] = &["python", "python3"];
    let python_here = PYTHON_BINS.iter().any(|s| bin_matches(bin, s))
        || rest.iter().any(|a| {
            let name = a.rsplit('/').next().unwrap_or(a);
            PYTHON_BINS.iter().any(|s| bin_matches(name, s))
        });
    if python_here
        && rest.iter().any(|a| {
            let b = a.as_bytes();
            b.len() >= 2 && b[0] == b'-' && b[1] != b'-' && b[1..].contains(&b'm')
        })
    {
        return Some("python -m executes a module with the workspace on sys.path; use argv arrays");
    }
    for a in argv {
        let name = a.rsplit('/').next().unwrap_or(a);
        let flags = interpreter_flags(name);
        if flags.is_empty() {
            continue;
        }
        if argv.iter().any(|b| interpreter_inline_arg(b, flags)) {
            return Some("interpreter inline code is not allowed; use argv arrays");
        }
    }
    None
}

/// True when `argv0` names a binary at a TRUSTED location: a bare name
/// (resolved by the sandbox's fixed PATH) or an absolute path in the
/// read-only system tree. Relative forms (`./git`, `sub/git`), traversal,
/// and guest-writable locations (`/workspace/git`, `/tmp/git`) are refused —
/// those are a guest-written binary wearing an allowlisted NAME. The trusted
/// set mirrors what the sandbox grants execute on (system tree + workspace):
/// the workspace is the one writable part, so it is the one that must not
/// satisfy an allowlist.
fn trusted_exec_path(argv0: &str) -> bool {
    if !argv0.contains('/') {
        return !argv0.is_empty();
    }
    if argv0.split('/').any(|c| c == "." || c == "..") {
        return false;
    }
    if !argv0.starts_with('/') {
        return false;
    }
    ["/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/"]
        .iter()
        .any(|p| argv0.starts_with(p))
}

pub fn decide(policy: &Policy, req: &Request) -> Decision {
    let deny = |rule: &str, reason: &str| Decision {
        allow: false,
        rule_ids: vec![rule.into()],
        reason: reason.into(),
    };
    // Global forbid: cloud metadata / link-local, always denied.
    // Covers common forms so a string variant can't slip past (I1).
    if let Some(h) = &req.host {
        if contains_ignore_ascii_case(h, b"169.254.169.254")
            || contains_ignore_ascii_case(h, b"metadata")
            || contains_ignore_ascii_case(h, b"instance-data")
            || contains_ignore_ascii_case(h, b"100.100.100.200")
            || contains_ignore_ascii_case(h, b"metadata.google.internal")
        {
            return deny("forbid:metadata", "metadata address is never reachable");
        }
    }
    match req.action.as_str() {
        "net.connect" | "http.request" => {
            // An HTTP request with no method authorizes nothing. The old code
            // defaulted an absent method to "GET" here, so a method-less
            // request acquired every `methods: [GET]` rule's privileges while
            // needs_approval (which saw "") skipped gates written for GET.
            if req.action == "http.request" && req.method.is_none() {
                return deny("deny:method-missing", "http.request requires a method");
            }
            // net.connect carries no method (absent/empty is fine there); any
            // method that IS present must be a clean token. Note an empty
            // method string is a malformed method, not a missing one.
            let method = req.method.as_deref().unwrap_or("");
            let host = req.host.as_deref().unwrap_or("");
            let path = req.path.as_deref().unwrap_or("/");
            // Request-line hygiene before any rule matching: the method and
            // path are forwarded verbatim upstream, so a guest must not be able
            // to smuggle a different resource or extra headers past the rule
            // that was checked (see request_target_is_clean).
            if (req.method.is_some() && !method_is_token(method)) || !request_target_is_clean(path)
            {
                return deny(
                    "deny:request-target",
                    "malformed or ambiguous request target",
                );
            }
            for h in &policy.net.hosts {
                // A rule matches if EITHER host or alias equals the request host.
                let rule_match = h
                    .host
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(host))
                    || h.alias
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(host));
                if rule_match {
                    if !h.methods.is_empty()
                        && !h.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
                    {
                        continue;
                    }
                    if !h.paths.is_empty() && !h.paths.iter().any(|p| path_match(p, path)) {
                        continue;
                    }
                    let host_lower = host.to_ascii_lowercase();
                    return Decision {
                        allow: true,
                        rule_ids: vec![format!("net:allow:{host_lower}")],
                        reason: "allowlisted".into(),
                    };
                }
            }
            deny("net:deny-default", "host not in allowlist")
        }
        "fs.read" | "fs.write" => {
            let raw = req.fs_path.as_deref().unwrap_or("/");
            let canon = canonical_path(raw);
            // Every mount covering the path has a say, not just the first one
            // that matches: with overlapping mounts the first-match rule let a
            // narrow `rw` listed before a `ro` parent shadow the read-only
            // mount (and the same two mounts in the other order behaved
            // differently). Effective permission is the MOST restrictive of
            // the covering mounts — a write needs all of them to be writable.
            let mut covered: Option<String> = None;
            let mut write_denied_by: Option<String> = None;
            for m in &policy.fs.mounts {
                let mount = canonical_path(&m.path);
                if canon == mount
                    || canon
                        .strip_prefix(&mount)
                        .is_some_and(|rest| rest.starts_with('/'))
                {
                    if req.action == "fs.write"
                        && !mount_allows_write(&m.mode)
                        && write_denied_by.is_none()
                    {
                        write_denied_by = Some(mount.clone());
                    }
                    if covered.is_none() {
                        covered = Some(mount);
                    }
                }
            }
            if req.action == "fs.write" {
                if let Some(mount) = write_denied_by {
                    return deny("fs:deny-ro", &format!("mount {mount} is not writable"));
                }
            }
            match covered {
                Some(mount) => Decision {
                    allow: true,
                    rule_ids: vec![format!("fs:allow:{mount}")],
                    reason: format!("under mount {mount}"),
                },
                None => deny("fs:deny-default", "path outside mounts"),
            }
        }
        "proc.exec" => {
            // An exec with no argv authorizes nothing — deny it outright
            // rather than wave it through (an empty or missing argv used to
            // skip every check below).
            let argv = match &req.argv {
                Some(a) if !a.is_empty() => a.as_slice(),
                _ => return deny("deny:exec-no-argv", "proc.exec requires argv"),
            };
            // Explicit allowlist: when the policy names the binaries that may
            // run, ONLY those run — whatever else argv looks like. This is the
            // fix for the denylist being inherently incomplete (wrappers,
            // renamed binaries, new flag spellings). Matched on argv[0] with
            // version tolerance, and the denylist below still applies on top:
            // an allowlisted interpreter still cannot take inline code.
            if !policy.exec.allowlist.is_empty() {
                // The name may match while the BINARY is guest-controlled:
                // /workspace/git or ./git is a file the guest just wrote.
                if !trusted_exec_path(&argv[0]) {
                    return deny(
                        "deny:exec-untrusted-path",
                        "allowlisted name at an untrusted path",
                    );
                }
                let bin = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
                if !policy.exec.allowlist.iter().any(|a| bin_matches(bin, a)) {
                    return deny(
                        "deny:exec-not-allowlisted",
                        "binary not in the policy exec allowlist",
                    );
                }
            }
            // argv smuggling: `sh -c` / `bash -c` is its own gated capability.
            // Deny shells and interpreters given an inline command string
            // fail-closed, since the guest could otherwise run arbitrary code
            // outside argv-array scrutiny. v0 has no shell policy, so deny here;
            // prefer an explicit exec allowlist in a later milestone.
            if let Some(reason) = exec_inline_denial(argv) {
                return deny("deny:shell", reason);
            }
            Decision {
                allow: true,
                rule_ids: vec!["proc:allow".into()],
                reason: "argv exec allowed; shell strings denied".into(),
            }
        }
        _ => deny("deny:unknown-action", "unknown action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Policy {
        load_yaml(include_str!("../../../schemas/policy-v0.yaml")).unwrap()
    }
    #[test]
    fn metadata_always_denied() {
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("169.254.169.254".into()),
                method: Some("GET".into()),
                path: Some("/".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(!d.allow);
    }
    #[test]
    fn allowlisted_get_allowed() {
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("registry.npmjs.org".into()),
                method: Some("GET".into()),
                path: Some("/".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(d.allow);
    }
    #[test]
    fn post_to_registry_denied() {
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("registry.npmjs.org".into()),
                method: Some("POST".into()),
                path: Some("/".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(!d.allow);
    }
    #[test]
    fn symlink_dotdot_contained() {
        assert_eq!(canonical_path("/workspace/a/../b"), "/workspace/b");
        assert_eq!(canonical_path("/workspace/../../etc/passwd"), "/etc/passwd");
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "fs.read".into(),
                host: None,
                method: None,
                path: None,
                fs_path: Some("/workspace/../../etc/passwd".into()),
                argv: None,
            },
        );
        assert!(!d.allow);
    }
    #[test]
    fn shell_c_denied() {
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(vec!["sh".into(), "-c".into(), "echo hi".into()]),
            },
        );
        assert!(!d.allow);
        let ok = decide(
            &p,
            &Request {
                action: "proc.exec".into(),
                host: None,
                method: None,
                path: None,
                fs_path: None,
                argv: Some(vec!["/bin/echo".into(), "hi".into()]),
            },
        );
        assert!(ok.allow);
    }
    #[test]
    fn host_case_insensitive_and_metadata_variants() {
        let p = sample();
        let d = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("REGISTRY.NPMJS.ORG".into()),
                method: Some("get".into()),
                path: Some("/".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(d.allow);
        let m = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("metadata.google.internal".into()),
                method: Some("GET".into()),
                path: Some("/".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(!m.allow);
    }
    #[test]
    fn path_glob() {
        let p = sample();
        let ok = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("github".into()),
                method: Some("GET".into()),
                path: Some("/repos/acme/app/issues/1".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(ok.allow);
        let bad = decide(
            &p,
            &Request {
                action: "http.request".into(),
                host: Some("github".into()),
                method: Some("GET".into()),
                path: Some("/repos/evil/x".into()),
                fs_path: None,
                argv: None,
            },
        );
        assert!(!bad.allow);
    }
}

#[cfg(test)]
mod trusted_exec_path_tests {
    use super::*;

    /// The contract the backend's program-path resolution must uphold (and
    /// now does): a bare argv[0] is trusted *because* the sandbox resolves
    /// bare names only from its fixed PATH (GUEST_PATH, system tree). These
    /// tests pin that reasoning so a change on either side fails here.
    #[test]
    fn bare_names_are_trusted() {
        assert!(trusted_exec_path("git"));
        assert!(trusted_exec_path("dependency-updater"));
        assert!(trusted_exec_path("python3.12"));
        assert!(!trusted_exec_path(""));
    }

    #[test]
    fn absolute_system_tree_is_trusted() {
        for p in [
            "/bin/sh",
            "/usr/bin/git",
            "/sbin/mkfs",
            "/lib64/ld-linux-x86-64.so.2",
        ] {
            assert!(trusted_exec_path(p), "{p} must be trusted");
        }
    }

    #[test]
    fn relative_and_traversal_forms_are_refused() {
        for p in ["./git", "sub/git", "../git", "a/../evil", "/usr/../evil"] {
            assert!(!trusted_exec_path(p), "{p} must be refused");
        }
    }

    #[test]
    fn guest_writable_locations_are_refused() {
        for p in ["/workspace/git", "/tmp/git", "/home/user/tool", "/root/x"] {
            assert!(!trusted_exec_path(p), "{p} must be refused");
        }
    }

    #[test]
    fn lookalike_prefixes_are_refused() {
        // Not under /usr/ — "/usrfoo/" is a different directory.
        assert!(!trusted_exec_path("/usrfoo/sh"));
        assert!(!trusted_exec_path("/usrshare/tool"));
    }
}

#[cfg(test)]
mod exec_denylist_tests {
    use super::*;

    fn denied<S: AsRef<str>>(argv: &[S]) -> bool {
        let owned: Vec<String> = argv.iter().map(|s| s.as_ref().to_string()).collect();
        exec_inline_denial(&owned).is_some()
    }

    // ---- pinned (working) denylist coverage ----

    #[test]
    fn shell_inline_code_is_denied() {
        assert!(denied(&["sh", "-c", "id"]));
        assert!(denied(&["/bin/sh", "-c", "id"]));
        assert!(denied(&["bash", "-lc", "id"]));
        assert!(denied(&["env", "sh", "-c", "id"]));
        assert!(denied(&["timeout", "5", "python3", "-c", "print(1)"]));
    }

    #[test]
    fn shell_script_files_are_denied() {
        assert!(denied(&["bash", "evil.sh"]));
        assert!(denied(&["sh", "/workspace/evil.sh"]));
        assert!(denied(&["/bin/busybox", "/bin/sh", "evil.sh"]));
    }

    #[test]
    fn interpreter_inline_code_is_denied() {
        assert!(denied(&["python3", "-c", "print(1)"]));
        assert!(denied(&["perl", "-E", "say 1"]));
        assert!(denied(&["node", "--eval", "1+1"]));
        assert!(denied(&["env", "python3", "-c", "print(1)"]));
        // bundled short flags
        assert!(denied(&["python3", "-ic", "print(1)"]));
        // -x: perl/ruby extract the program from a file and run it.
        assert!(denied(&["perl", "-x", "/workspace/evil.pl"]));
        assert!(denied(&["ruby", "-x", "/workspace/evil.rb"]));
        assert!(denied(&["perl", "-x/workspace", "evil.pl"])); // joined dir form
        assert!(denied(&["perl5", "-x", "evil.pl"])); // version tolerance
        assert!(denied(&["env", "perl", "-x", "evil.pl"])); // reached in rest
    }

    #[test]
    fn ordinary_argv_is_allowed() {
        assert!(!denied(&["/bin/echo", "hello"]));
        assert!(!denied(&["git", "status"]));
        assert!(!denied(&["env", "FOO=bar", "git", "status"]));
        assert!(!denied(&["python3", "script.py"]));
        assert!(!denied(&["ls", "-la"]));
    }

    // ---- KNOWN BUGS (each pinned in the buggy state; the fix PR for each
    // ---- vector flips its assertion to the safe direction) ----

    #[test]
    fn env_split_string_is_denied() {
        // env -S splits the single token into "sh -c id" at exec time; neither
        // a shell name nor -c is ever a separate argv token, so the shell and
        // interpreter gates never fire. Denied outright (fixed).
        assert!(denied(&["env", "-S", "sh -c id > /tmp/pwned"]));
        assert!(denied(&["/usr/bin/env", "-S", "sh -c id"]));
        assert!(denied(&["env", "-Ssh -c id"])); // joined -S<value>
        assert!(denied(&["env", "--split-string=sh -c id"])); // long form, =value
        assert!(denied(&["env", "--split-string", "sh -c id"])); // long form, separate value
        assert!(denied(&["/usr/bin/env", "--split-string=python3 -c id"]));
        assert!(denied(&["env", "-i", "-S", "bash -c id"])); // env with other flags
        assert!(!denied(&["env", "FOO=bar", "git", "status"])); // env without -S stays allowed
        assert!(!denied(&["env", "-u", "SECRET", "git", "push"]));
        // A -S-shaped data arg without env in argv is not denied.
        assert!(!denied(&["grep", "-S", "pattern", "file"]));
    }

    #[test]
    fn shell_startup_file_flags_are_denied() {
        // The script-file rule only rejects args NOT starting with '-'; the
        // '=' form hides the script path behind a dash. Denied outright
        // (fixed).
        assert!(denied(&["bash", "--rcfile=/workspace/evil.sh", "-i"]));
        assert!(denied(&["bash", "--init-file=/workspace/evil.sh", "-i"]));
        assert!(denied(&["/bin/bash", "--rcfile=/workspace/evil.sh"]));
        // The separate-path form was always caught (the path is a non-dash
        // arg) — pinned so the new rule doesn't regress it.
        assert!(denied(&["bash", "--rcfile", "/workspace/evil.sh"]));
        // Non-shell argv with rcfile-shaped data args stays allowed.
        assert!(!denied(&["grep", "--rcfile=x", "file"]));
    }

    #[test]
    fn awk_program_text_is_denied() {
        // awk executes its program from a positional argv token (or -f file)
        // and system() gives it the shell — there is no non-code-executing
        // use, so the family is denied outright (fixed).
        assert!(denied(&[
            "awk",
            "BEGIN{system(\"sh -c id\")}",
            "/workspace/f"
        ]));
        assert!(denied(&["gawk", "'{print}'", "f"]));
        assert!(denied(&["mawk", "-f", "evil.awk"]));
        assert!(denied(&["/usr/bin/awk", "{print}"]));
        assert!(denied(&["gawk-5.1", "{print}"])); // version tolerance
        assert!(denied(&["env", "awk", "{print}"])); // reached in rest
        assert!(denied(&["sort", "file", "awk"])); // awk-shaped token anywhere
    }

    #[test]
    fn python_module_exec_is_denied() {
        // python -m puts the cwd (the workspace) at sys.path[0]:
        // `python3 -m evil` imports and runs /workspace/evil.py.
        assert!(denied(&["python3", "-m", "evil"]));
        assert!(denied(&["python3", "-m", "http.server"])); // legit module runs pay the same price
        assert!(denied(&["/usr/bin/python3", "-m", "evil"]));
        assert!(denied(&["python3.12", "-m", "evil"])); // version tolerance
        assert!(denied(&["env", "python3", "-m", "evil"])); // reached in rest
        assert!(denied(&["python3", "-Bm", "evil"])); // bundled short flags
        assert!(!denied(&["python3", "script.py"]));
        assert!(!denied(&["python3", "-u", "script.py"]));
        assert!(denied(&["python", "script.py", "-m"]));
        // Non-python argv with -m stays allowed.
        assert!(!denied(&["grep", "-m", "5", "pattern", "file"]));
    }

    #[test]
    fn busybox_applet_forms_are_denied() {
        // busybox is a shell-shaped multi-call binary: it is in SHELL_BINS,
        // so ANY argument after it (applet names included) trips the
        // script-file rule. Deliberately broad — busybox <applet> can be
        // sh, awk, and more — and fail-closed.
        assert!(denied(&["busybox", "sh", "-c", "id"]));
        assert!(denied(&["/bin/busybox", "awk", "{print}"]));
        assert!(denied(&["busybox", "echo", "hi"])); // over-broad by design
        assert!(denied(&["busybox-1.35", "sh", "evil.sh"])); // version tolerance
    }

    #[test]
    fn every_vector_denies_with_deny_shell_and_a_reason() {
        // The rule id is part of the operator contract (explain.rs teaches
        // it); the reason is operator-facing. Every vector must deny with
        // exactly ['deny:shell'] and a non-empty reason.
        let vectors: &[&[&str]] = &[
            &["sh", "-c", "id"],
            &["bash", "evil.sh"],
            &["bash", "--rcfile=/workspace/evil.sh", "-i"],
            &["env", "-S", "sh -c id"],
            &["env", "--split-string=sh -c id"],
            &["python3", "-c", "print(1)"],
            &["awk", "{print}", "f"],
            &["python3", "-m", "evil"],
            &["perl", "-x", "evil.pl"],
            &["busybox", "sh", "-c", "id"],
        ];
        let mut reasons = std::collections::HashSet::new();
        for argv in vectors {
            let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            let d = exec_inline_denial(&owned);
            let reason = match d {
                Some(r) => r,
                None => panic!("{argv:?} must be denied"),
            };
            assert!(!reason.is_empty(), "{argv:?}: reason must not be empty");
            reasons.insert(reason);
        }
        // Distinct classes give distinct reasons (an operator reading a
        // denial should be able to tell which vector fired).
        assert!(
            reasons.len() >= 6,
            "expected distinct reasons per vector class, got {reasons:?}"
        );
    }

    #[test]
    fn interpreters_reached_by_absolute_path_in_rest_are_denied() {
        // The interpreter loop strips paths from every token before matching:
        // a wrapper carrying an absolute interpreter path must not dodge the
        // inline-code gate the way a bare name would not.
        assert!(denied(&["env", "/usr/bin/python3", "-c", "print(1)"]));
        assert!(denied(&["nice", "/usr/bin/perl", "-E", "say 1"]));
        assert!(denied(&["/usr/bin/env", "/bin/sh", "-c", "id"]));
        assert!(denied(&["timeout", "5", "/usr/bin/python3.12", "-C", "x"]));
    }

    #[test]
    fn bin_matches_version_tolerance_edges() {
        // Version tolerance: known name + digits/dots/dashes suffix.
        assert!(bin_matches("python3.12", "python3"));
        assert!(bin_matches("bash5", "bash"));
        assert!(bin_matches("busybox-1.35", "busybox"));
        assert!(bin_matches("gawk-5.1.1", "gawk"));
        // Not tolerance: prefix impersonations and junk suffixes must not
        // match, or an allowlist entry could be widened by a guest-written
        // lookalike name.
        assert!(!bin_matches("python3x", "python3"));
        assert!(!bin_matches("pythonista", "python"));
        assert!(!bin_matches("3", "python3"));
        assert!(!bin_matches("", "sh"));
        // An allowlisted name must not match a different known binary.
        assert!(!bin_matches("sh", "bash"));
    }

    #[test]
    fn interpreter_flag_forms_deny_across_wrappers() {
        // The scanner must be insensitive to WHERE the interpreter appears
        // and HOW the flag is spelled. Build the cross product: wrapper x
        // interpreter x the interpreter's OWN inline flags (from
        // interpreter_flags, used as ground truth) x spelling forms (bare,
        // joined-with-code, bundled-in-a-cluster). Every inline form denies;
        // the same argv with a script file instead of a flag stays allowed.
        let wrappers: &[&[&str]] = &[
            &[],
            &["env"],
            &["nice", "-5"],
            &["timeout", "5"],
            &["nohup"],
            &["env", "-u", "X"],
        ];
        let interpreters = ["python3", "python", "perl", "ruby", "node", "lua", "php"];
        for i in interpreters {
            let flags: Vec<String> = interpreter_flags(i).iter().map(|s| s.to_string()).collect();
            assert!(!flags.is_empty(), "{i} should have inline flags");
            for f in &flags {
                for w in wrappers {
                    let base: Vec<String> = w
                        .iter()
                        .map(|s| s.to_string())
                        .chain([i.to_string()])
                        .collect();

                    let mut argv = base.clone();
                    argv.push(f.clone());
                    assert!(denied(&argv), "bare flag: {argv:?} must be denied");

                    if f.len() == 2 {
                        let mut argv = base.clone();
                        argv.push(format!("{f}code"));
                        assert!(denied(&argv), "joined flag: {argv:?} must be denied");

                        let mut argv = base.clone();
                        argv.push(format!("-v{}", &f[1..]));
                        assert!(denied(&argv), "bundled flag: {argv:?} must be denied");
                    }

                    let mut argv = base.clone();
                    argv.push("script.py".to_string());
                    assert!(!denied(&argv), "no inline flag: {argv:?} must be allowed");
                }
            }
        }
    }

    #[test]
    fn known_bug_awk_program_text_is_inline_code() {
        // SUPERSEDED by awk_program_text_is_denied; kept as a marker that the
        // vector is closed.
        assert!(denied(&[
            "awk",
            "BEGIN{system(\"sh -c id\")}",
            "/workspace/f"
        ]));
    }
}
