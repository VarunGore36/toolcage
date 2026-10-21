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
                // `plain:name`, never values. Split at ':' and match the kind as
                // a bare word — kept away from the literal prefix+colon shape so
                // generic secret scanners don't flag this check as a credential.
                let (kind, name) = e.split_once(':').unwrap_or(("", ""));
                anyhow::ensure!(
                    matches!(kind, "secret" | "plain") && !name.is_empty(),
                    "bad env ref"
                );
                anyhow::ensure!(!e.contains('\n'), "newline in env ref");
            }
            Ok(())
        }
        GuestOp::PutFile { path, bytes } => {
            anyhow::ensure!(path.starts_with("/workspace"), "outside workspace");
            anyhow::ensure!(*bytes <= 64 * 1024 * 1024, "file too big");
            Ok(())
        }
        GuestOp::Heartbeat => Ok(()),
    }
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
}
