use anyhow::Result;
use clap::Parser;

mod commands;
mod error;
mod extract;
mod input;
mod payload;
mod proto;

use commands::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let insecure = cli.insecure;

    match cli.command {
        Commands::Extract(args) => commands::extract::run(args, insecure),
        Commands::List(args) => commands::list::run(args, insecure),
        Commands::Verify(args) => commands::verify::run(args, insecure),
        Commands::Metadata(args) => commands::metadata::run(args, insecure),
    }
}
