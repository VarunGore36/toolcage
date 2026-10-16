//! Standalone verifier: re-hashes the chain, checks seq + linkage.
//!
//! REVIEW:
//! - Verifies continuity + integrity (seq gap, prev_hash link, recomputed
//!   hash). Must be run with the OUT-OF-BAND log copy: verifying the live
//!   file the writer still appends to races the tail (use --follow or copy).
//! - --pubkey accepted for CLI compat; Ed25519 checkpoint enforcement is NOT
//!   implemented yet — chain only. Do not represent output as "signed OK".
//! - Exit nonzero on ANY failure (first break), prints ok count + head hash
//!   on success. Partial/corrupt tail (truncated write) fails closed as Err.
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    log: PathBuf,
    /// Accepted for CLI compatibility; Ed25519 checkpoint enforcement lands in M6.
    #[arg(long)]
    pubkey: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let (n, head) = toolcage_audit::verify(&a.log)?;
    println!("ok: {n} events, head {head}");
    Ok(())
}
