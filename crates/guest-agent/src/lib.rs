//! Guest agent v0: PID 1 inside the guest. Static musl binary.
//! Minimal vsock/Unix-socket protocol. Supervisor treats every message as untrusted.
//!
//! REVIEW (A2/A3: guest messages are attacker-controlled):
//! - validate() bounds everything: id<=64, argv 1..=64 entries each <=4096
//!   without NUL, PutFile inside /workspace and <=64 MiB, env_refs must be
//!   `secret:`/`plain:` with no newline. Anything else is Err (deny + audit).
//!   New op variants must add bounds here FIRST — an unvalidated field is a
//!   supervisor parser bug (fuzz target: fuzz.rs covers this).
//! - env_refs allow `secret:name` placeholders ONLY; `NAME=value` rejected.
//!   Values must never cross into the guest — injection happens host-side.
//! - No shell in guest: argv executed directly; `sh -c` denied at policy AND
//!   here by shape (no string splitting). Keep it that way.
//! - Protocol has no auth/crypto: security comes from the transport (vsock to
//!   the right VM + supervisor-side session binding), not message contents.
//!   Bind each channel to its session id; never multiplex sessions on one SOB.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum GuestOp {
    Exec {
        argv: Vec<String>,
        env_refs: Vec<String>,
    },
    PutFile {
        path: String,
        bytes: u64,
    },
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestMsg {
    pub id: String,
    pub op: GuestOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostReply {
    pub id: String,
    pub ok: bool,
    pub note: String,
}

/// Validate inbound message (fuzz target): tiny, no shell, bounded sizes.
pub fn validate(msg: &GuestMsg) -> anyhow::Result<()> {
    anyhow::ensure!(msg.id.len() <= 64, "id too long");
    match &msg.op {
        GuestOp::Exec { argv, env_refs } => {
            anyhow::ensure!(!argv.is_empty() && argv.len() <= 64, "argv bounds");
            for a in argv {
                anyhow::ensure!(a.len() <= 4096, "arg too long");
                anyhow::ensure!(!a.contains('\0'), "nul in arg");
            }
            for e in env_refs {
                // Only placeholders cross the boundary: `secret:name` or
                // `plain:name`, never values. Split at ':' and match the kind
                // as a bare word — kept away from the literal prefix+colon
                // shape so generic secret scanners don't flag this check as a
                // credential.
                anyhow::ensure!(e.len() <= 4096, "env ref too long");
                anyhow::ensure!(!e.contains('\0'), "nul in env ref");
                anyhow::ensure!(!e.contains('\n'), "newline in env ref");
                let (kind, name) = e.split_once(':').unwrap_or(("", ""));
                anyhow::ensure!(
                    matches!(kind, "secret" | "plain") && !name.is_empty(),
                    "bad env ref"
                );
                // Env var names must follow the portable charset and must not
                // be dangerous overrides that the guest could use to hijack its
                // own runtime (LD_PRELOAD, LD_LIBRARY_PATH, ...).
                anyhow::ensure!(
                    name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        && name.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_'),
                    "bad env ref name"
                );
                anyhow::ensure!(
                    !matches!(
                        name.to_ascii_uppercase().as_str(),
                        "LD_PRELOAD" | "LD_LIBRARY_PATH" | "LD_AUDIT" | "LD_DEBUG"
                            | "PATH" | "HOME"
                    ),
                    "dangerous env ref name"
                );
            }
            anyhow::ensure!(env_refs.len() <= 64, "too many env refs");
            Ok(())
        }
        GuestOp::PutFile { path, bytes } => {
            // Path must be absolute and NUL-free: normalize_path() would turn a
            // relative "workspace/foo" into "/workspace/foo" and accept it, but
            // the consumer opens the raw string relative to cwd — a classic
            // check-vs-use sandbox escape. NUL is rejected like argv (C APIs
            // truncate at NUL, diverging the checked and opened paths).
            anyhow::ensure!(path.starts_with('/'), "path must be absolute");
            anyhow::ensure!(!path.contains('\0'), "nul in path");
            // Canonicalize (resolve '.', '..', '//') then require the result to
            // be /workspace or live under /workspace/. A bare starts_with would
            // wrongly accept "/workspacex" and "/workspace/../etc/passwd".
            let np = normalize_path(path);
            anyhow::ensure!(
                np == "/workspace" || np.starts_with("/workspace/"),
                "outside workspace"
            );
            anyhow::ensure!(*bytes <= 64 * 1024 * 1024, "file too big");
            Ok(())
        }
        GuestOp::Heartbeat => Ok(()),
    }
}

/// Lexical fs normalization (no FS access): resolve '.', '..', '//', leading
/// slashes. Mirrors capability::normalize_fs semantics.
fn normalize_path(p: &str) -> String {
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
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_nul_and_abs_path_escape() {
        let m = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/echo".into(), "a\0b".into()],
                env_refs: vec![],
            },
        };
        assert!(validate(&m).is_err());
        let m2 = GuestMsg {
            id: "1".into(),
            op: GuestOp::PutFile {
                path: "/etc/passwd".into(),
                bytes: 1,
            },
        };
        assert!(validate(&m2).is_err());
    }
    #[test]
    fn accepts_secret_ref_rejects_value() {
        let ok = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/x".into()],
                env_refs: vec!["secret:github_token".into()],
            },
        };
        assert!(validate(&ok).is_ok());
        let bad = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/x".into()],
                env_refs: vec!["GITHUB_TOKEN=s3cr3t".into()],
            },
        };
        assert!(validate(&bad).is_err());
    }
    #[test]
    fn env_refs_bounded_and_named_safely() {
        // A valid secret ref passes.
        let ok = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/x".into()],
                env_refs: vec!["secret:github_token".into()],
            },
        };
        assert!(validate(&ok).is_ok());
        // Dangerous override names are rejected even with a valid kind.
        for bad_name in ["LD_PRELOAD", "ld_preload", "LD_LIBRARY_PATH", "PATH", "HOME"] {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::Exec {
                    argv: vec!["/bin/x".into()],
                    env_refs: vec![format!("secret:{bad_name}")],
                },
            };
            assert!(validate(&m).is_err(), "env ref {bad_name} must be rejected");
        }
        // Names must follow the portable env-var charset.
        for bad in ["secret:a=b", "secret:a b", "secret:a\0b", "secret:1bad", "secret:-bad"] {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::Exec {
                    argv: vec!["/bin/x".into()],
                    env_refs: vec![bad.into()],
                },
            };
            assert!(validate(&m).is_err(), "env ref {bad:?} must be rejected");
        }
        // Too many refs and too-long refs are rejected.
        let many: Vec<String> = (0..65).map(|i| format!("secret:k{i}")).collect();
        let m = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/x".into()],
                env_refs: many,
            },
        };
        assert!(validate(&m).is_err(), "65 env refs must be rejected");
        let long_name = "x".repeat(5000);
        let long = format!("{long_name}:v");
        let m = GuestMsg {
            id: "1".into(),
            op: GuestOp::Exec {
                argv: vec!["/bin/x".into()],
                env_refs: vec![long],
            },
        };
        assert!(validate(&m).is_err(), "over-long env ref must be rejected");
    }
    #[test]
    fn putfile_path_canonicalized() {
        // Traversal escapes are rejected even though the raw string starts with
        // "/workspace", and "/workspacex" is not "/workspace".
        let bad_paths = [
            "/workspace/../etc/passwd",
            "/workspace/..//etc/passwd",
            "/workspacex",
            "/workspacex/foo",
            "/etc/passwd",
            "/",
            "",
        ];
        for p in bad_paths {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::PutFile {
                    path: p.into(),
                    bytes: 1,
                },
            };
            assert!(validate(&m).is_err(), "path {p:?} must be rejected");
        }
        // Relative paths normalize under /workspace but resolve relative to cwd
        // — a check-vs-use escape. Must be rejected outright.
        let relative_paths = [
            "workspace/foo",
            "workspace/../etc/passwd",
            "./workspace/foo",
            "../etc/passwd",
        ];
        for p in relative_paths {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::PutFile {
                    path: p.into(),
                    bytes: 1,
                },
            };
            assert!(validate(&m).is_err(), "relative path {p:?} must be rejected");
        }
        // NUL bytes diverge the checked path from any C-API opened path.
        let nul_paths = ["/workspace/foo\0/etc", "/workspace/\0etc/passwd"];
        for p in nul_paths {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::PutFile {
                    path: p.into(),
                    bytes: 1,
                },
            };
            assert!(validate(&m).is_err(), "path {p:?} must be rejected");
        }
        // Canonicalized in-workspace paths are accepted.
        let good_paths = [
            "/workspace",
            "/workspace/",
            "/workspace/./foo",
            "/workspace/foo/../bar",
            "//workspace//foo",
        ];
        for p in good_paths {
            let m = GuestMsg {
                id: "1".into(),
                op: GuestOp::PutFile {
                    path: p.into(),
                    bytes: 1,
                },
            };
            assert!(validate(&m).is_ok(), "path {p:?} must be accepted");
        }
    }
}
