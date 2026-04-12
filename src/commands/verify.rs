use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use rayon::prelude::*;

use crate::extract::verify::{verify_fec, verify_hash_tree, verify_partition};
use crate::input;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
    pub input: String,

    /// Directory containing extracted .img files
    #[arg(short, long, default_value = "output")]
    pub dir: PathBuf,

    /// Comma-separated partition names (empty = all)
    #[arg(short, long, value_delimiter = ',')]
    pub partitions: Option<Vec<String>>,

    /// Also verify dm-verity hash tree
    #[arg(long)]
    pub hash_tree: bool,

    /// Also verify FEC (Forward Error Correction) data
    #[arg(long)]
    pub fec: bool,
}

pub fn run(args: VerifyArgs, insecure: bool) -> Result<()> {
    let start = Instant::now();
    let payload = input::open(&args.input, insecure)?;
    let block_size = payload.block_size();

    let partition_names = args.partitions.unwrap_or_default();
    let partitions = payload.selected_partitions(&partition_names);

    println!("Verifying {} partitions...", partitions.len());

    let results: Vec<(&str, bool)> = partitions
        .par_iter()
        .filter_map(|p| {
            let info = p.new_partition_info.as_ref()?;
            let hash = info.hash.as_ref()?;
            let size = info.size?;
            let path = args.dir.join(format!("{}.img", p.partition_name));

            if !path.exists() {
                println!("  SKIP  {}: file not found", p.partition_name);
                return Some((p.partition_name.as_str(), false));
            }

            // SHA256 partition verification
            match verify_partition(&path, hash, size) {
                Ok(true) => {
                    println!("  OK    {}", p.partition_name);
                }
                Ok(false) => {
                    println!("  FAIL  {} (SHA256 mismatch)", p.partition_name);
                    return Some((p.partition_name.as_str(), false));
                }
                Err(e) => {
                    println!("  ERR   {}: {e}", p.partition_name);
                    return Some((p.partition_name.as_str(), false));
                }
            }

            // Hash tree and FEC verification share the same mmap
            let needs_mmap = (args.hash_tree && p.hash_tree_extent.is_some())
                || (args.fec && p.fec_extent.is_some());

            if needs_mmap {
                let file = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        println!("  ERR   {} open: {e}", p.partition_name);
                        return Some((p.partition_name.as_str(), false));
                    }
                };
                let mmap = match unsafe { memmap2::Mmap::map(&file) } {
                    Ok(m) => m,
                    Err(e) => {
                        println!("  ERR   {} mmap: {e}", p.partition_name);
                        return Some((p.partition_name.as_str(), false));
                    }
                };

                if args.hash_tree && p.hash_tree_extent.is_some() {
                    match verify_hash_tree(&mmap, p, block_size) {
                        Ok(true) => println!("  OK    {} (hash tree)", p.partition_name),
                        Ok(false) => {
                            println!("  FAIL  {} (hash tree mismatch)", p.partition_name);
                            return Some((p.partition_name.as_str(), false));
                        }
                        Err(e) => {
                            println!("  ERR   {} hash tree: {e}", p.partition_name);
                            return Some((p.partition_name.as_str(), false));
                        }
                    }
                }

                if args.fec && p.fec_extent.is_some() {
                    match verify_fec(&mmap, p, block_size) {
                        Ok(true) => println!("  OK    {} (FEC)", p.partition_name),
                        Ok(false) => {
                            println!("  FAIL  {} (FEC check failed)", p.partition_name);
                            return Some((p.partition_name.as_str(), false));
                        }
                        Err(e) => {
                            println!("  ERR   {} FEC: {e}", p.partition_name);
                            return Some((p.partition_name.as_str(), false));
                        }
                    }
                }
            }

            Some((p.partition_name.as_str(), true))
        })
        .collect();

    let passed = results.iter().filter(|(_, ok)| *ok).count();
    let total = results.len();
    let elapsed = start.elapsed();

    println!("\n{passed}/{total} partitions verified in {elapsed:.2?}");

    if passed != total {
        anyhow::bail!("verification failed for {} partition(s)", total - passed);
    }

    Ok(())
}
