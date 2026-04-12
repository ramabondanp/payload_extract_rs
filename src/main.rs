use clap::Parser;

mod commands;
mod error;
mod extract;
mod input;
mod payload;
mod proto;
mod style;

use commands::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let insecure = cli.insecure;

    let result = match cli.command {
        Commands::Extract(args) => commands::extract::run(args, insecure),
        Commands::List(args) => commands::list::run(args, insecure),
        Commands::Verify(args) => commands::verify::run(args, insecure),
        Commands::Metadata(args) => commands::metadata::run(args, insecure),
    };

    if let Err(e) = result {
        eprintln!("{} {e}", style::error().apply_to("Error:"));
        std::process::exit(1);
    }
}
