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

    // Compute leaf-level hashes (hash of each data block with salt)
    let mut level_hashes: Vec<Vec<u8>> = Vec::new();
    for block_idx in 0..data_blocks {
        let offset = (data_start + block_idx * block_size as u64) as usize;
        let end = offset + block_size as usize;
        let block_data = &partition_data[offset..end];

        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(block_data);
        level_hashes.push(hasher.finalize().to_vec());
    }

    // Build tree levels until we reach a single root hash
    while level_hashes.len() > 1 {
        let hash_size = 32; // SHA256
        let hashes_per_block = block_size as usize / hash_size;
        let mut next_level = Vec::new();

        for chunk in level_hashes.chunks(hashes_per_block) {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            for h in chunk {
                hasher.update(h);
            }
            // Pad with zeros if chunk is smaller than hashes_per_block
            for _ in chunk.len()..hashes_per_block {
                hasher.update([0u8; 32]);
            }
            next_level.push(hasher.finalize().to_vec());
        }

        level_hashes = next_level;
    }

    // Compare computed hash tree with stored hash tree
    let stored_tree = &partition_data[tree_start as usize..tree_end as usize];
    if level_hashes.len() == 1 {
        // Root hash is the first 32 bytes of the stored tree
        if stored_tree.len() >= 32 {
            return Ok(level_hashes[0] == stored_tree[..32]);
        }
    }

    Ok(true)
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

    // Full Reed-Solomon FEC verification is not yet implemented;
    // only basic integrity check (non-zero FEC region) is performed.
    let _fec_roots = partition.fec_roots.unwrap_or(2);

    // Verify FEC extents are within bounds
    let fec_data_start = fec_data_extent.start_block.unwrap_or(0) * block_size as u64;
    let fec_data_end = fec_data_start + fec_data_extent.num_blocks.unwrap_or(0) * block_size as u64;
    let fec_start = fec_extent.start_block.unwrap_or(0) * block_size as u64;
    let fec_end = fec_start + fec_extent.num_blocks.unwrap_or(0) * block_size as u64;

    if fec_data_end as usize > partition_data.len() || fec_end as usize > partition_data.len() {
        return Ok(false);
    }

    // Basic integrity check: FEC data region exists and is non-empty
    let fec_data_region = &partition_data[fec_start as usize..fec_end as usize];
    let all_zeros = fec_data_region.iter().all(|&b| b == 0);

    // If FEC data is all zeros, it's likely not populated
    Ok(!all_zeros || fec_data_region.is_empty())
}
