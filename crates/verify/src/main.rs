use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    log: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let (n, head) = toolcage_audit::verify(&a.log)?;
    println!("ok: {n} events, head {head}");
    Ok(())
}
