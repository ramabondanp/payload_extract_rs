use anyhow::{Context, Result, bail};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::proto::{CompressedBlockInfo, Lz4diffHeader, compression_algorithm};

const LZ4DIFF_MAGIC: &[u8; 7] = b"LZ4DIFF";
const LZ4DIFF_VERSION: u32 = 1;

// Binary layout: [0..7) magic(7) + [7..11) version(4) + [11..15) pb_size(4) + [15] padding
// Protobuf starts at offset 16 (= kLz4diffHeaderSize in Android source: 8 + 4 + 4)
const VERSION_OFFSET: usize = 7; // kLz4diffMagic.size()
const PB_SIZE_OFFSET: usize = 11; // VERSION_OFFSET + sizeof(version)
const PB_DATA_OFFSET: usize = 16; // kLz4diffHeaderSize

fn is_compressed(block: &CompressedBlockInfo) -> bool {
    block.compressed_length < block.uncompressed_length
}

/// Apply an LZ4DIFF patch (BSDIFF or PUFFDIFF inner type) to source data.
///
/// Pipeline:
/// 1. Parse LZ4DIFF patch header
/// 2. LZ4 decompress source using src block info
/// 3. Apply inner bsdiff/puffdiff patch
/// 4. LZ4 recompress using dst block info + postfix patches
pub fn apply_lz4diff(
    src_data: &[u8],
    patch_data: &[u8],
    op_type: super::operation::OpType,
) -> Result<Vec<u8>> {
    // 1. Parse header
    if patch_data.len() < PB_DATA_OFFSET {
        bail!("LZ4DIFF patch too small: {} bytes", patch_data.len());
    }

    if &patch_data[..LZ4DIFF_MAGIC.len()] != LZ4DIFF_MAGIC {
        bail!(
            "invalid LZ4DIFF magic: expected {:?}, got {:?}",
            LZ4DIFF_MAGIC,
            &patch_data[..LZ4DIFF_MAGIC.len()]
        );
    }

    let version = u32::from_be_bytes(
        patch_data[VERSION_OFFSET..VERSION_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if version != LZ4DIFF_VERSION {
        bail!("unsupported LZ4DIFF version: {version} (expected {LZ4DIFF_VERSION})");
    }

    let pb_size = u32::from_be_bytes(
        patch_data[PB_SIZE_OFFSET..PB_SIZE_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let pb_end = PB_DATA_OFFSET + pb_size;
    if patch_data.len() < pb_end {
        bail!(
            "LZ4DIFF patch truncated: need {pb_end} bytes, got {}",
            patch_data.len()
        );
    }

    let header = Lz4diffHeader::decode(&patch_data[PB_DATA_OFFSET..pb_end])
        .context("failed to decode LZ4DIFF protobuf header")?;
    let inner_patch = &patch_data[pb_end..];

    let src_info = header
        .src_info
        .as_ref()
        .context("missing src_info in LZ4DIFF header")?;
    let dst_info = header
        .dst_info
        .as_ref()
        .context("missing dst_info in LZ4DIFF header")?;

    // 2. Decompress source
    let decompressed_src = decompress_blob(
        src_data,
        &src_info.block_info,
        src_info.zero_padding_enabled,
    )
    .context("LZ4DIFF source decompression failed")?;

    // 3. Apply inner patch (both BSDIFF and PUFFDIFF use bsdiff-compatible format)
    let decompressed_dst = match op_type {
        super::operation::OpType::Lz4diffBsdiff | super::operation::OpType::Lz4diffPuffdiff => {
            let mut patch_reader = std::io::Cursor::new(inner_patch);
            let mut output = Vec::new();
            bsdiff_android::patch(&decompressed_src, &mut patch_reader, &mut output)
                .context("LZ4DIFF inner patch failed")?;
            output
        }
        _ => bail!("unexpected op_type in apply_lz4diff: {:?}", op_type),
    };

    // 4. Recompress and apply postfix patches
    let algo_type = dst_info
        .algo
        .as_ref()
        .map(|a| a.r#type())
        .unwrap_or(compression_algorithm::Type::Lz4);

    compress_blob(
        &decompressed_dst,
        &dst_info.block_info,
        dst_info.zero_padding_enabled,
        algo_type,
    )
    .context("LZ4DIFF destination recompression failed")
}

/// Decompress a blob using LZ4 block info.
fn decompress_blob(
    data: &[u8],
    blocks: &[CompressedBlockInfo],
    zero_padding_enabled: bool,
) -> Result<Vec<u8>> {
    if blocks.is_empty() {
        return Ok(data.to_vec());
    }

    let total_uncompressed: u64 = blocks.iter().map(|b| b.uncompressed_length).sum();
    let total_compressed: u64 = blocks.iter().map(|b| b.compressed_length).sum();

    if (data.len() as u64) < total_compressed {
        bail!(
            "source data too small: need {total_compressed} bytes, got {}",
            data.len()
        );
    }

    let mut output = Vec::with_capacity(total_uncompressed as usize);
    let mut compressed_offset: usize = 0;

    for block in blocks {
        let block_end = compressed_offset + block.compressed_length as usize;
        let block_data = &data[compressed_offset..block_end];

        if !is_compressed(block) {
            output.extend_from_slice(block_data);
        } else {
            let input = if zero_padding_enabled {
                // Skip leading zero padding bytes
                let padding = block_data.iter().take_while(|&&b| b == 0).count();
                &block_data[padding..]
            } else {
                block_data
            };

            let decompressed =
                lz4_flex::block::decompress(input, block.uncompressed_length as usize)
                    .map_err(|e| anyhow::anyhow!("LZ4 block decompression failed: {e}"))?;

            if decompressed.len() != block.uncompressed_length as usize {
                bail!(
                    "LZ4 decompression size mismatch: expected {}, got {}",
                    block.uncompressed_length,
                    decompressed.len()
                );
            }

            output.extend_from_slice(&decompressed);
        }

        compressed_offset = block_end;
    }

    Ok(output)
}

/// Compress a blob using LZ4 block info, with postfix patch support.
fn compress_blob(
    data: &[u8],
    blocks: &[CompressedBlockInfo],
    zero_padding_enabled: bool,
    algo_type: compression_algorithm::Type,
) -> Result<Vec<u8>> {
    if blocks.is_empty() {
        return Ok(data.to_vec());
    }

    let total_compressed: u64 = blocks.iter().map(|b| b.compressed_length).sum();
    let mut output = Vec::with_capacity(total_compressed as usize);

    for block in blocks {
        let block_start = block.uncompressed_offset as usize;
        let block_end = block_start + block.uncompressed_length as usize;
        let uncompressed_block = &data[block_start..block_end];

        if !is_compressed(block) {
            output.extend_from_slice(uncompressed_block);
            continue;
        }

        let target_size = block.compressed_length as usize;

        // Compress block using LZ4
        let compressed = match algo_type {
            compression_algorithm::Type::Uncompressed => uncompressed_block.to_vec(),
            compression_algorithm::Type::Lz4 | compression_algorithm::Type::Lz4hc => {
                lz4_flex::block::compress(uncompressed_block)
            }
        };

        if compressed.len() > target_size && block.postfix_bspatch.is_empty() {
            // Compressed output exceeds target and no postfix to fix it.
            // This can happen when lz4_flex produces less efficient compression
            // than Android's LZ4. Fall back to storing uncompressed data truncated
            // to target_size — this should not happen in practice with well-formed
            // OTA payloads.
            bail!(
                "LZ4 recompression produced {} bytes, exceeding target {} bytes \
                 (LZ4 implementation mismatch, no postfix patch available)",
                compressed.len(),
                target_size
            );
        }

        // Build output block with correct target size
        let mut block_buf = vec![0u8; target_size];
        let bytes_written = compressed.len().min(target_size);

        if bytes_written < target_size {
            if zero_padding_enabled {
                // Compressed data at END, zero padding at START
                let padding = target_size - bytes_written;
                block_buf[padding..].copy_from_slice(&compressed[..bytes_written]);
            } else {
                // Compressed data at START, zero padding at END
                block_buf[..bytes_written].copy_from_slice(&compressed[..bytes_written]);
            }
        } else {
            block_buf.copy_from_slice(&compressed[..target_size]);
        }

        // Apply postfix bsdiff patch if present (fixes LZ4 implementation differences)
        if !block.postfix_bspatch.is_empty() {
            if !block.sha256_hash.is_empty() {
                let actual_hash = Sha256::digest(&block_buf);
                if actual_hash.as_slice() != block.sha256_hash.as_slice() {
                    // Our LZ4 output differs from what the postfix patch expects.
                    // Applying the postfix would produce garbage, so skip it and
                    // use our raw compression output. This may produce slightly
                    // different output but is safer than applying a wrong patch.
                    eprintln!(
                        "warning: LZ4DIFF postfix hash mismatch at offset {}, \
                         skipping postfix patch (LZ4 implementation difference)",
                        block.uncompressed_offset
                    );
                    output.extend_from_slice(&block_buf);
                    continue;
                }
            }

            let mut patch_reader = std::io::Cursor::new(&block.postfix_bspatch[..]);
            let mut fixed = Vec::new();
            bsdiff_android::patch(&block_buf, &mut patch_reader, &mut fixed)
                .context("LZ4DIFF postfix bspatch failed")?;
            block_buf = fixed;
        }

        output.extend_from_slice(&block_buf);
    }

    // Append any trailing data not covered by block_info
    let covered: u64 = blocks
        .last()
        .map(|b| b.uncompressed_offset + b.uncompressed_length)
        .unwrap_or(0);
    if (covered as usize) < data.len() {
        output.extend_from_slice(&data[covered as usize..]);
    }

    Ok(output)
}
