use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "toolcage")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Doctor,
    Panic,
    Audit { op: String },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Doctor => println!("run scripts/doctor.sh"),
        Cmd::Panic => println!("panic: stop all sessions (M6)"),
        Cmd::Audit { op } => println!("audit {op} (M1)"),
    }
}
