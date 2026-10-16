//! Guest agent v0: PID 1 inside the guest. Static musl binary.
//! Minimal vsock/Unix-socket protocol. Supervisor treats every message as untrusted.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum GuestOp {
    Exec { argv: Vec<String>, env_refs: Vec<String> },
    PutFile { path: String, bytes: u64 },
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
                // Only secret: references cross the boundary, never values.
                anyhow::ensure!(e.starts_with("secret:") || e.starts_with("plain:"), "bad env ref");
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
        let m = GuestMsg { id: "1".into(), op: GuestOp::Exec { argv: vec!["/bin/echo".into(), "a\0b".into()], env_refs: vec![] } };
        assert!(validate(&m).is_err());
        let m2 = GuestMsg { id: "1".into(), op: GuestOp::PutFile { path: "/etc/passwd".into(), bytes: 1 } };
        assert!(validate(&m2).is_err());
    }
    #[test]
    fn accepts_secret_ref_rejects_value() {
        let ok = GuestMsg { id: "1".into(), op: GuestOp::Exec { argv: vec!["/bin/x".into()], env_refs: vec!["secret:github_token".into()] } };
        assert!(validate(&ok).is_ok());
        let bad = GuestMsg { id: "1".into(), op: GuestOp::Exec { argv: vec!["/bin/x".into()], env_refs: vec!["GITHUB_TOKEN=s3cr3t".into()] } };
        assert!(validate(&bad).is_err());
    }
}
