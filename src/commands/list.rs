use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::input;

#[derive(Args)]
pub struct ListArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
    pub input: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Show SHA256 hash for each partition
    #[arg(short = 'H', long)]
    pub hash: bool,
}

#[derive(Serialize)]
struct PartitionEntry {
    name: String,
    size: u64,
    operations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

pub fn run(args: ListArgs, insecure: bool) -> Result<()> {
    let payload = input::open(&args.input, insecure)?;
    let partitions = payload.partitions();

    let entries: Vec<PartitionEntry> = partitions
        .iter()
        .map(|p| {
            let info = p.new_partition_info.as_ref();
            let size = info.and_then(|i| i.size).unwrap_or(0);
            let hash = if args.hash {
                info.and_then(|i| i.hash.as_ref()).map(hex::encode)
            } else {
                None
            };
            PartitionEntry {
                name: p.partition_name.clone(),
                size,
                operations: p.operations.len(),
                hash,
            }
        })
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else if args.hash {
        println!(
            "{:<25} {:>12} {:>6}  SHA256",
            "PARTITION", "SIZE", "OPS"
        );
        println!("{}", "-".repeat(110));
        for entry in &entries {
            println!(
                "{:<25} {:>12} {:>6}  {}",
                entry.name,
                format_size(entry.size),
                entry.operations,
                entry.hash.as_deref().unwrap_or("-")
            );
        }
    } else {
        println!("{:<25} {:>12} {:>6}", "PARTITION", "SIZE", "OPS");
        println!("{}", "-".repeat(46));
        for entry in &entries {
            println!(
                "{:<25} {:>12} {:>6}",
                entry.name,
                format_size(entry.size),
                entry.operations
            );
        }
    }
    println!("{}", "-".repeat(if args.hash { 110 } else { 46 }));
    println!("Total: {} partitions", entries.len());

    Ok(())
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}
