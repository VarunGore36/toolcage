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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetPolicy {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
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

pub fn load_yaml(s: &str) -> anyhow::Result<Policy> {
    Ok(serde_yaml::from_str(s)?)
}

impl Policy {
    /// Approval gate from policy file: require_for entries (timeout = deny).
    pub fn needs_approval(&self, action: &str, method: Option<&str>, host: Option<&str>) -> bool {
        for entry in &self.approval.require_for {
            for (act, spec) in entry {
                if act != action {
                    continue;
                }
                if !spec.methods.is_empty() {
                    let m = method.unwrap_or("");
                    if !spec.methods.iter().any(|x| x.eq_ignore_ascii_case(m)) {
                        continue;
                    }
                }
                if !spec.hosts.is_empty() {
                    let h = host.unwrap_or("");
                    if !spec.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)) {
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
    let mut parts: Vec<&str> = vec![];
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn path_match(pattern: &str, path: &str) -> bool {
    // Support trailing /** only (v0). Exact otherwise.
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{}/", prefix))
    } else {
        pattern == path
    }
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
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
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
        ("perl", &["-e", "-E"]),
        ("ruby", &["-e", "-E"]),
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
        || name
            .strip_prefix(known)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b'-'))
}

/// True for shell short-flag args that run an inline command string:
/// `-c`, `-lc`, `-cic`, etc. Single-dash flags only (not `--long`).
fn shell_inline_flag(a: &str) -> bool {
    let b = a.as_bytes();
    b.len() >= 2 && b[0] == b'-' && b[1] != b'-' && a.contains('c')
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
        let hl = h.to_ascii_lowercase();
        if hl.contains("169.254.169.254")
            || hl.contains("metadata")
            || hl.contains("instance-data")
            || hl.contains("100.100.100.200")
            || hl.contains("metadata.google.internal")
        {
            return deny("forbid:metadata", "metadata address is never reachable");
        }
    }
    match req.action.as_str() {
        "net.connect" | "http.request" => {
            let host = req.host.as_deref().unwrap_or("").to_ascii_lowercase();
            let method = req.method.as_deref().unwrap_or("GET").to_ascii_uppercase();
            let path = req.path.as_deref().unwrap_or("/");
            // Request-line hygiene before any rule matching: the method and
            // path are forwarded verbatim upstream, so a guest must not be able
            // to smuggle a different resource or extra headers past the rule
            // that was checked (see request_target_is_clean).
            if !method_is_token(&method) || !request_target_is_clean(path) {
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
                    .is_some_and(|x| x.to_ascii_lowercase() == host)
                    || h.alias
                        .as_deref()
                        .is_some_and(|x| x.to_ascii_lowercase() == host);
                if rule_match {
                    if !h.methods.is_empty()
                        && !h.methods.iter().any(|m| m.to_ascii_uppercase() == method)
                    {
                        continue;
                    }
                    if !h.paths.is_empty() && !h.paths.iter().any(|p| path_match(p, path)) {
                        continue;
                    }
                    return Decision {
                        allow: true,
                        rule_ids: vec![format!("net:allow:{host}")],
                        reason: "allowlisted".into(),
                    };
                }
            }
            deny("net:deny-default", "host not in allowlist")
        }
        "fs.read" | "fs.write" => {
            let raw = req.fs_path.as_deref().unwrap_or("/");
            let canon = canonical_path(raw);
            for m in &policy.fs.mounts {
                let mount = canonical_path(&m.path);
                let mount = mount.trim_end_matches('/').to_string();
                let mount = if mount.is_empty() {
                    "/".to_string()
                } else {
                    mount
                };
                if canon == mount || canon.starts_with(&format!("{mount}/")) {
                    if req.action == "fs.write" && m.mode == "ro" {
                        return deny("fs:deny-ro", "mount is read-only");
                    }
                    return Decision {
                        allow: true,
                        rule_ids: vec![format!("fs:allow:{mount}")],
                        reason: format!("under mount {mount}"),
                    };
                }
            }
            deny("fs:deny-default", "path outside mounts")
        }
        "proc.exec" => {
            // argv smuggling: `sh -c` / `bash -c` is its own gated capability.
            // Deny shells and interpreters given an inline command string
            // fail-closed, since the guest could otherwise run arbitrary code
            // outside argv-array scrutiny. v0 has no shell policy, so deny here;
            // prefer an explicit exec allowlist in a later milestone.
            if let Some(argv) = &req.argv {
                if !argv.is_empty() {
                    let bin = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
                    let rest = &argv[1..];
                    // A shell binary anywhere in argv (argv[0] itself, or reached
                    // indirectly via `env sh -c`) running an inline-code string
                    // executes arbitrary command text outside argv-array
                    // scrutiny. Running a shell script file is the same class of
                    // risk as `sh -c`, so either form is denied.
                    let shell_here = SHELL_BINS
                        .iter()
                        .any(|s| bin_matches(bin, s))
                        || rest
                            .iter()
                            .any(|a| SHELL_BINS.iter().any(|s| bin_matches(a, s)));
                    if shell_here && rest.iter().any(|a| shell_inline_flag(a)) {
                        return deny("deny:shell", "shell -c is not allowed; use argv arrays");
                    }
                    if shell_here && rest.iter().any(|a| !a.starts_with('-')) {
                        return deny(
                            "deny:shell",
                            "shell script files are not allowed; use argv arrays",
                        );
                    }
                    // Interpreters given inline code are denied WHEREVER they
                    // appear in argv, not just argv[0]: `env python3 -c`, `nice
                    // perl -E` and `timeout 5 python3 -c` must be caught just
                    // like `python3 -c`. Every spelling of the inline-code flag
                    // is matched (see interpreter_flags): `-c`, `-e`, `-E`, `-p`,
                    // `--eval`, `-r`, `-R`, and the joined forms (`-ccode`).
                    for a in argv {
                        let name = a.rsplit('/').next().unwrap_or(a);
                        let flags = interpreter_flags(name);
                        if flags.is_empty() {
                            continue;
                        }
                        if argv
                            .iter()
                            .any(|b| flags.iter().any(|f| b == f || b.starts_with(*f)))
                        {
                            return deny(
                                "deny:shell",
                                "interpreter inline code is not allowed; use argv arrays",
                            );
                        }
                    }
                }
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
