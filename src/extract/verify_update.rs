/// Compute and write back dm-verity hash tree and FEC data into extracted partition images.
///
/// Functionality:
/// 1. Compute the dm-verity Merkle hash tree from data blocks and write it back
/// 2. Compute Reed-Solomon FEC parity data and write it back
///
/// Both are needed to produce partition images that pass Android's verified boot checks.
use std::path::Path;

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::extract::fec::{self, FEC_RSM, RsEncoder};
use crate::proto::PartitionUpdate;

const SHA256_DIGEST_SIZE: usize = 32;

/// Align `value` up to the next multiple of `alignment`.
#[inline]
fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// A single level of the dm-verity hash tree.
struct Level {
    /// Number of blocks at this level (each block holds block_size/32 hashes).
    block_count: u64,
    /// Padded to block_size boundary.
    total_hash_size: u64,
    /// Hash data buffer (padded with zeros).
    data: Vec<u8>,
}

impl Level {
    fn new(target_size: u64, block_size: u64) -> Self {
        let block_count = target_size / block_size;
        let total_hash_size = align_up(block_count * SHA256_DIGEST_SIZE as u64, block_size);
        let data = vec![0u8; total_hash_size as usize];
        Self {
            block_count,
            total_hash_size,
            data,
        }
    }
}

/// Compute the dm-verity hash tree and write it into the partition image.
///
/// Returns `Ok(true)` if hash tree was computed and written, `Ok(false)` if partition
/// has no hash tree metadata, or `Err` on failure.
pub fn compute_and_write_hash_tree(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    let hash_tree_data_extent = match &partition.hash_tree_data_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };
    let hash_tree_extent = match &partition.hash_tree_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };

    let salt = partition.hash_tree_salt.as_deref().unwrap_or(&[]);
    let algorithm = partition.hash_tree_algorithm.as_deref().unwrap_or("sha256");
    if algorithm != "sha256" {
        bail!("unsupported hash tree algorithm: '{algorithm}'");
    }

    let bs = block_size as u64;
    let data_extent_offset = hash_tree_data_extent.start_block.unwrap_or(0) * bs;
    let data_extent_size = hash_tree_data_extent.num_blocks.unwrap_or(0) * bs;
    let hash_tree_offset = hash_tree_extent.start_block.unwrap_or(0) * bs;

    // Memory-map the partition file for reading data blocks
    let file = std::fs::File::open(output_path)
        .with_context(|| format!("failed to open '{}' for hash tree", output_path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("failed to mmap '{}'", output_path.display()))?;
    let partition_data = &mmap[..];

    // Build level hierarchy
    // Top level: one hash per data block
    let mut top_level = Level::new(data_extent_size, bs);

    // Compute top level hashes in parallel: SHA256(salt || data_block)
    top_level
        .data
        .par_chunks_mut(SHA256_DIGEST_SIZE)
        .enumerate()
        .take(top_level.block_count as usize)
        .for_each(|(i, hash_slot)| {
            let offset = data_extent_offset as usize + i * block_size as usize;
            let end = (offset + block_size as usize).min(partition_data.len());
            let block_data = &partition_data[offset..end];

            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(block_data);
            hash_slot.copy_from_slice(&hasher.finalize());
        });

    // Build intermediate levels until block_count == 1 (the root level).
    let mut levels: Vec<Level> = Vec::new();
    let mut prev_hash_size = top_level.total_hash_size;
    let mut prev_hash_data: &[u8] = &top_level.data;

    let compute_level = |prev_data: &[u8], prev_size: u64, salt: &[u8], block_size: usize| {
        let bs = block_size as u64;
        let salt_len = salt.len();
        let mut level = Level::new(prev_size, bs);
        let mut salt_buf = vec![0u8; salt_len + block_size];
        salt_buf[..salt_len].copy_from_slice(salt);

        let mut write_pos = 0usize;
        let mut read_pos = 0usize;
        while read_pos < prev_size as usize {
            let end = (read_pos + block_size).min(prev_data.len());
            salt_buf[salt_len..salt_len + (end - read_pos)]
                .copy_from_slice(&prev_data[read_pos..end]);
            // Zero-fill if short
            for b in &mut salt_buf[salt_len + (end - read_pos)..salt_len + block_size] {
                *b = 0;
            }

            let hash = Sha256::digest(&salt_buf[..salt_len + block_size]);
            level.data[write_pos..write_pos + SHA256_DIGEST_SIZE].copy_from_slice(hash.as_slice());

            read_pos += block_size;
            write_pos += SHA256_DIGEST_SIZE;
        }
        level
    };

    while prev_hash_size > bs {
        let level = compute_level(prev_hash_data, prev_hash_size, salt, block_size as usize);
        prev_hash_size = level.total_hash_size;
        levels.push(level);
        prev_hash_data = &levels.last().unwrap().data;
    }

    // Compute root level (block_count == 1) and pop it from the write list,
    // matching the C++ reference which saves it for potential verification use.
    let _root_level = levels.last().map(|last| {
        compute_level(&last.data, last.total_hash_size, salt, block_size as usize)
    });

    // Arrange levels for write-back:
    // Reverse intermediate levels (deepest first), then append the top (leaf) level
    levels.reverse();
    levels.push(top_level);

    // Write all levels to the output file at hash_tree_offset
    let out_file = std::fs::OpenOptions::new()
        .write(true)
        .open(output_path)
        .with_context(|| {
            format!(
                "failed to open '{}' for hash tree write",
                output_path.display()
            )
        })?;

    let mut write_offset = hash_tree_offset;
    for level in &levels {
        write_at_offset(
            &out_file,
            &level.data[..level.total_hash_size as usize],
            write_offset,
        )?;
        write_offset += level.total_hash_size;
    }

    Ok(true)
}

/// Compute FEC (Forward Error Correction) parity data and write it into the partition image.
///
/// Returns `Ok(true)` if FEC was computed and written, `Ok(false)` if partition
/// has no FEC metadata, or `Err` on failure.
pub fn compute_and_write_fec(
    partition: &PartitionUpdate,
    output_path: &Path,
    block_size: u32,
) -> Result<bool> {
    let fec_data_extent = match &partition.fec_data_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };
    let fec_extent = match &partition.fec_extent {
        Some(ext) => ext,
        None => return Ok(false),
    };

    let bs = block_size as u64;
    let fec_roots = partition.fec_roots.unwrap_or(2);
    let fec_rsn = FEC_RSM - fec_roots;

    let fec_data_extent_offset = fec_data_extent.start_block.unwrap_or(0) * bs;
    let fec_data_extent_size = fec_data_extent.num_blocks.unwrap_or(0) * bs;
    let fec_write_offset = fec_extent.start_block.unwrap_or(0) * bs;
    let fec_extent_size = fec_extent.num_blocks.unwrap_or(0) * bs;
    let fec_data_size = fec::fec_ecc_get_data_size(fec_data_extent_size, fec_roots);

    // Validate that the proto-declared FEC extent size matches the computed size
    if fec_extent_size != fec_data_size {
        bail!(
            "FEC extent size mismatch: proto declares {} but computed {}",
            fec_extent_size,
            fec_data_size
        );
    }

    let rounds = (fec_data_extent_size / bs).div_ceil(fec_rsn as u64);

    // Memory-map partition for reading
    let file = std::fs::File::open(output_path)
        .with_context(|| format!("failed to open '{}' for FEC", output_path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("failed to mmap '{}'", output_path.display()))?;
    let partition_data = &mmap[..];

    // Allocate FEC output buffer
    let mut fec_output = vec![0u8; fec_data_size as usize];

    // Process each round in parallel
    let chunk_size = block_size as usize * fec_roots as usize;
    fec_output
        .par_chunks_mut(chunk_size)
        .enumerate()
        .take(rounds as usize)
        .for_each(|(round_idx, fec_chunk)| {
            let rs = RsEncoder::new(fec_roots as usize);
            let mut buffer = vec![0u8; block_size as usize];
            let rs_block_size = block_size as usize * fec_rsn as usize;
            let mut rs_blocks = vec![0u8; rs_block_size];

            // Construct RS blocks from interleaved data
            for j in 0..fec_rsn as usize {
                let offset = fec::fec_ecc_interleave(
                    round_idx as u64 * fec_rsn as u64 * bs + j as u64,
                    fec_rsn,
                    rounds,
                );

                buffer.fill(0);
                if offset < fec_data_extent_size {
                    let src_offset = fec_data_extent_offset + offset;
                    let src_end = (src_offset + block_size as u64).min(partition_data.len() as u64);
                    if src_offset < partition_data.len() as u64 {
                        let len = (src_end - src_offset) as usize;
                        buffer[..len].copy_from_slice(
                            &partition_data[src_offset as usize..src_end as usize],
                        );
                    }
                }

                // Place into RS block: rsBlocks[col * rsn + row] = buffer[col]
                for k in 0..block_size as usize {
                    rs_blocks[k * fec_rsn as usize + j] = buffer[k];
                }
            }

            // Encode each byte column
            for j in 0..block_size as usize {
                let data_start = j * fec_rsn as usize;
                let data_slice = &rs_blocks[data_start..data_start + fec_rsn as usize];
                let parity_start = j * fec_roots as usize;
                let parity_end = parity_start + fec_roots as usize;
                rs.encode(data_slice, &mut fec_chunk[parity_start..parity_end]);
            }
        });

    // Write FEC data to output file
    drop(mmap);
    drop(file);

    let out_file = std::fs::OpenOptions::new()
        .write(true)
        .open(output_path)
        .with_context(|| format!("failed to open '{}' for FEC write", output_path.display()))?;

    write_at_offset(&out_file, &fec_output, fec_write_offset)?;

    Ok(true)
}

/// Run verify-update (hash tree + FEC write-back) for selected partitions.
pub fn verify_update_partitions(
    partitions: &[&PartitionUpdate],
    output_dir: &Path,
    block_size: u32,
    threads: usize,
    quiet: bool,
) -> Result<()> {
    let thread_count = if threads == 0 {
        num_cpus::get()
    } else {
        threads
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .context("failed to create thread pool")?;

    pool.install(|| {
        partitions
            .par_iter()
            .try_for_each(|partition| -> Result<()> {
                let name = &partition.partition_name;
                let output_path = output_dir.join(format!("{name}.img"));

                if !output_path.exists() {
                    if !quiet {
                        eprintln!("  SKIP  {name}: file not found");
                    }
                    return Ok(());
                }

                // Hash tree
                let ht_result = compute_and_write_hash_tree(partition, &output_path, block_size)?;
                if ht_result && !quiet {
                    eprintln!("  HASH  {name}");
                }

                // FEC (only if hash tree succeeded)
                if ht_result {
                    let fec_result = compute_and_write_fec(partition, &output_path, block_size)?;
                    if fec_result && !quiet {
                        eprintln!("  FEC   {name}");
                    }
                }

                Ok(())
            })
    })
}

/// Write data at a specific byte offset in a file (platform-specific positional write).
fn write_at_offset(file: &std::fs::File, data: &[u8], offset: u64) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(data, offset)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0;
        while written < data.len() {
            let n = file.seek_write(&data[written..], offset + written as u64)?;
            written += n;
        }
    }
    Ok(())
}
