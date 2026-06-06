use sha2::{Digest, Sha256};

use crate::proto::PartitionUpdate;

/// Verify SHA256 hash of data against expected hash.
/// Returns Ok(()) if hashes match or if expected is None.
pub fn verify_sha256(
    data: &[u8],
    expected: &Option<Vec<u8>>,
    context: &str,
) -> Result<(), crate::error::PayloadError> {
    if let Some(expected_hash) = expected {
        let actual = Sha256::digest(data);
        if actual.as_slice() != expected_hash.as_slice() {
            return Err(crate::error::PayloadError::HashMismatch {
                context: context.to_string(),
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual),
            });
        }
    }
    Ok(())
}

/// Verify a complete partition file against expected hash.
pub fn verify_partition(
    path: &std::path::Path,
    expected_hash: &[u8],
    expected_size: u64,
) -> anyhow::Result<bool> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }?;

    if (mmap.len() as u64) < expected_size {
        return Ok(false);
    }

    let actual = Sha256::digest(&mmap[..expected_size as usize]);
    Ok(actual.as_slice() == expected_hash)
}

/// Verify dm-verity hash tree for a partition.
///
/// The hash tree is a Merkle tree where:
/// - Leaf nodes are SHA256 hashes of data blocks (with salt prepended)
/// - Internal nodes are SHA256 hashes of child hashes (with salt prepended)
/// - The root hash should match the expected value in the manifest
pub fn verify_hash_tree(
    partition_data: &[u8],
    partition: &PartitionUpdate,
    block_size: u32,
) -> anyhow::Result<bool> {
    let hash_tree_data_extent = match &partition.hash_tree_data_extent {
        Some(ext) => ext,
        None => return Ok(true), // No hash tree to verify
    };
    let hash_tree_extent = match &partition.hash_tree_extent {
        Some(ext) => ext,
        None => return Ok(true),
    };

    let salt = partition.hash_tree_salt.as_deref().unwrap_or(&[]);
    let algorithm = partition.hash_tree_algorithm.as_deref().unwrap_or("sha256");

    if algorithm != "sha256" {
        anyhow::bail!("unsupported hash tree algorithm: '{algorithm}' (only sha256 is supported)");
    }

    // Calculate data range covered by hash tree
    let data_start = hash_tree_data_extent.start_block.unwrap_or(0) * block_size as u64;
    let data_blocks = hash_tree_data_extent.num_blocks.unwrap_or(0);
    let data_end = data_start + data_blocks * block_size as u64;

    // Hash tree storage location
    let tree_start = hash_tree_extent.start_block.unwrap_or(0) * block_size as u64;
    let tree_blocks = hash_tree_extent.num_blocks.unwrap_or(0);
    let tree_end = tree_start + tree_blocks * block_size as u64;

    if data_end as usize > partition_data.len() || tree_end as usize > partition_data.len() {
        return Ok(false);
    }

    // Align helper
    #[inline]
    fn align_up(value: u64, alignment: u64) -> u64 {
        value.div_ceil(alignment) * alignment
    }

    // Reconstruct top level (leaf hashes of data blocks)
    let mut current_level_data = vec![0u8; align_up(data_blocks * 32, block_size as u64) as usize];
    use rayon::prelude::*;
    current_level_data
        .par_chunks_mut(32)
        .enumerate()
        .take(data_blocks as usize)
        .for_each(|(block_idx, hash_slot)| {
            let offset = (data_start + block_idx as u64 * block_size as u64) as usize;
            let end = offset + block_size as usize;
            let block_data = &partition_data[offset..end];

            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(block_data);
            hash_slot.copy_from_slice(&hasher.finalize());
        });

    let mut reconstructed_tree_data = Vec::new();
    let mut levels = Vec::new();
    let mut prev_hash_size = current_level_data.len() as u64;
    let mut prev_hash_data = current_level_data.clone();

    while prev_hash_size > block_size as u64 {
        // Compute next level up
        let mut next_level_data = vec![
            0u8;
            align_up(
                (prev_hash_size / block_size as u64) * 32,
                block_size as u64
            ) as usize
        ];
        let mut write_pos = 0usize;
        let mut read_pos = 0usize;
        let mut chunk_to_hash = vec![0u8; salt.len() + block_size as usize];
        chunk_to_hash[..salt.len()].copy_from_slice(salt);

        while read_pos < prev_hash_size as usize {
            let end = (read_pos + block_size as usize).min(prev_hash_data.len());
            let len = end - read_pos;
            chunk_to_hash[salt.len()..salt.len() + len]
                .copy_from_slice(&prev_hash_data[read_pos..end]);
            // Zero-fill if short
            chunk_to_hash[salt.len() + len..].fill(0);

            let hash = Sha256::digest(&chunk_to_hash);
            next_level_data[write_pos..write_pos + 32].copy_from_slice(hash.as_slice());

            read_pos += block_size as usize;
            write_pos += 32;
        }
        prev_hash_size = next_level_data.len() as u64;
        prev_hash_data = next_level_data;
        levels.push(prev_hash_data.clone());
    }

    levels.reverse();
    for lvl in levels {
        reconstructed_tree_data.extend_from_slice(&lvl);
    }
    reconstructed_tree_data.extend_from_slice(&current_level_data);

    // Compare computed hash tree with stored hash tree
    let stored_tree = &partition_data[tree_start as usize..tree_end as usize];
    if stored_tree.len() < reconstructed_tree_data.len() {
        return Ok(false);
    }
    Ok(reconstructed_tree_data == stored_tree[..reconstructed_tree_data.len()])
}

/// Verify Forward Error Correction (FEC) data for a partition.
///
/// FEC uses Reed-Solomon codes to provide redundancy for data recovery.
/// This verifies that the FEC data is consistent with the partition data.
pub fn verify_fec(
    partition_data: &[u8],
    partition: &PartitionUpdate,
    block_size: u32,
) -> anyhow::Result<bool> {
    let fec_data_extent = match &partition.fec_data_extent {
        Some(ext) => ext,
        None => return Ok(true), // No FEC to verify
    };
    let fec_extent = match &partition.fec_extent {
        Some(ext) => ext,
        None => return Ok(true),
    };

    let bs = block_size as u64;
    let fec_roots = partition.fec_roots.unwrap_or(2);
    let fec_rsn = crate::extract::fec::FEC_RSM - fec_roots;

    let fec_data_extent_offset = fec_data_extent.start_block.unwrap_or(0) * bs;
    let fec_data_extent_size = fec_data_extent.num_blocks.unwrap_or(0) * bs;
    let fec_start = fec_extent.start_block.unwrap_or(0) * bs;
    let fec_end = fec_start + fec_extent.num_blocks.unwrap_or(0) * bs;
    let fec_extent_size = fec_extent.num_blocks.unwrap_or(0) * bs;
    let fec_data_size = crate::extract::fec::fec_ecc_get_data_size(fec_data_extent_size, fec_roots);

    if fec_extent_size != fec_data_size {
        return Ok(false);
    }

    if fec_end as usize > partition_data.len() {
        return Ok(false);
    }

    let rounds = (fec_data_extent_size / bs).div_ceil(fec_rsn as u64);
    let mut fec_computed = vec![0u8; fec_data_size as usize];

    use rayon::prelude::*;
    let chunk_size = block_size as usize * fec_roots as usize;
    fec_computed
        .par_chunks_mut(chunk_size)
        .enumerate()
        .take(rounds as usize)
        .for_each(|(round_idx, fec_chunk)| {
            let rs = crate::extract::fec::RsEncoder::new(fec_roots as usize);
            let mut buffer = vec![0u8; block_size as usize];
            let rs_block_size = block_size as usize * fec_rsn as usize;
            let mut rs_blocks = vec![0u8; rs_block_size];

            for j in 0..fec_rsn as usize {
                let offset = crate::extract::fec::fec_ecc_interleave(
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

                for k in 0..block_size as usize {
                    rs_blocks[k * fec_rsn as usize + j] = buffer[k];
                }
            }

            for j in 0..block_size as usize {
                let data_start = j * fec_rsn as usize;
                let data_slice = &rs_blocks[data_start..data_start + fec_rsn as usize];
                let parity_start = j * fec_roots as usize;
                let parity_end = parity_start + fec_roots as usize;
                rs.encode(data_slice, &mut fec_chunk[parity_start..parity_end]);
            }
        });

    let stored_fec = &partition_data[fec_start as usize..fec_end as usize];
    Ok(fec_computed == stored_fec)
}
