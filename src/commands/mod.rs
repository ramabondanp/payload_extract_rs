pub mod extract;
pub mod list;
pub mod metadata;
pub mod verify;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "payload-extract",
    version,
    about = "Android OTA payload.bin extractor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Skip SSL certificate verification for HTTPS URLs
    #[arg(short = 'k', long, global = true)]
    pub insecure: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Extract partition images from payload.bin
    Extract(extract::ExtractArgs),
    /// List partitions in payload.bin
    List(list::ListArgs),
    /// Verify extracted partition images against payload hashes
    Verify(verify::VerifyArgs),
    /// Show payload metadata
    Metadata(metadata::MetadataArgs),
}
