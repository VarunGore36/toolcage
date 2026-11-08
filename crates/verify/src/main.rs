//! Standalone verifier: re-hashes the chain, checks seq + linkage.
//!
//! With --pubkey, also verifies every sibling `<log>.checkpoint.*` file against
//! the pinned Ed25519 pubkey and binds each checkpoint's (seq, head) to the
//! actual chain prefix. Without --pubkey: chain only (back-compat).
//!
//! Exit nonzero on ANY failure (first break), prints ok count + head hash on
//! success. Partial/corrupt tail (truncated write) fails closed as Err.
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    log: PathBuf,
    /// Verify Ed25519 checkpoints against this pinned pubkey (32 hex bytes).
    #[arg(long)]
    pubkey: Option<PathBuf>,
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a 64-char (32-byte) hex string into [u8; 32]. Returns an error
/// (never panics) on wrong length, odd length, or non-hex input.
fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    let b = s.as_bytes();
    anyhow::ensure!(
        b.len() == 64,
        "expected 64 hex chars (32 bytes), got {} chars",
        b.len()
    );
    let mut out = [0u8; 32];
    for (i, (slot, &[hi_b, lo_b])) in out.iter_mut().zip(b.as_chunks::<2>().0).enumerate() {
        let hi =
            hex_nibble(hi_b).ok_or_else(|| anyhow::anyhow!("bad hex at position {}", 2 * i))?;
        let lo =
            hex_nibble(lo_b).ok_or_else(|| anyhow::anyhow!("bad hex at position {}", 2 * i + 1))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    match &a.pubkey {
        Some(pkf) => {
            let pk = parse_hex32(&std::fs::read_to_string(pkf)?)?;
            let (n, head) = toolcage_audit::verify_with_pubkey(&a.log, Some(&pk))?;
            println!("ok: {n} events, head {head} (checkpoints verified)");
        }
        None => {
            let (n, head) = toolcage_audit::verify(&a.log)?;
            println!("ok: {n} events, head {head}");
        }
    }
    Ok(())
}
