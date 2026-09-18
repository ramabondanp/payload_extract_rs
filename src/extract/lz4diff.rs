use anyhow::{bail, Context, Result};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::extract::bufpool;
use crate::proto::{compression_algorithm, CompressedBlockInfo, Lz4diffHeader};
use crate::style;

const LZ4DIFF_MAGIC: &[u8; 7] = b"LZ4DIFF";
const LZ4DIFF_VERSION: u32 = 1;

// Binary layout: [0..7) magic(7) + [7..11) version(4) + [11..15) pb_size(4) + [15] padding
// Protobuf starts at offset 16 (= kLz4diffHeaderSize in Android source: 8 + 4 + 4)
const VERSION_OFFSET: usize = 7; // kLz4diffMagic.size()
const PB_SIZE_OFFSET: usize = 11; // VERSION_OFFSET + sizeof(version)
const PB_DATA_OFFSET: usize = 16; // kLz4diffHeaderSize

extern crate lz4_sys;

unsafe extern "C" {
    fn LZ4_createStreamHC() -> *mut std::ffi::c_void;
    fn LZ4_freeStreamHC(stateHC: *mut std::ffi::c_void) -> std::ffi::c_int;
    fn LZ4_compress_destSize(
        src: *const std::ffi::c_char,
        dst: *mut std::ffi::c_char,
        srcSizePtr: *mut std::ffi::c_int,
        targetDstSize: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn LZ4_compress_HC_destSize(
        stateHC: *mut std::ffi::c_void,
        src: *const std::ffi::c_char,
        dst: *mut std::ffi::c_char,
        srcSizePtr: *mut std::ffi::c_int,
        targetDstSize: std::ffi::c_int,
        compressionLevel: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn LZ4_decompress_safe_partial(
        src: *const std::ffi::c_char,
        dst: *mut std::ffi::c_char,
        compressedSize: std::ffi::c_int,
        targetOutputSize: std::ffi::c_int,
        dstCapacity: std::ffi::c_int,
    ) -> std::ffi::c_int;
}

fn is_compressed(block: &CompressedBlockInfo) -> bool {
    block.compressed_length < block.uncompressed_length
}

fn apply_bsdiff(old: &[u8], patch_data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    if patch_data.starts_with(b"BSDIFF40") || patch_data.starts_with(b"BSDF2") {
        bsdiff_android::patch_bsdf2(old, patch_data, &mut output)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        let mut patch_reader = std::io::Cursor::new(patch_data);
        bsdiff_android::patch(old, &mut patch_reader, &mut output)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(output)
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

    // 3. Apply inner patch
    let decompressed_dst = match op_type {
        super::operation::OpType::Lz4diffBsdiff => {
            if header.inner_type == 1 {
                puffdiff::puffpatch(&decompressed_src, inner_patch)
                    .context("LZ4DIFF inner puffdiff patch failed")?
            } else {
                apply_bsdiff(&decompressed_src, inner_patch)
                    .context("LZ4DIFF inner bsdiff patch failed")?
            }
        }
        super::operation::OpType::Lz4diffPuffdiff => {
            puffdiff::puffpatch(&decompressed_src, inner_patch)
                .context("LZ4DIFF inner puffdiff patch failed")?
        }
        _ => bail!("unexpected op_type in apply_lz4diff: {:?}", op_type),
    };

    // 4. Recompress and apply postfix patches
    let (algo_type, algo_level) = dst_info
        .algo
        .as_ref()
        .map(|a| (a.r#type(), a.level))
        .unwrap_or((compression_algorithm::Type::Lz4, 0));

    compress_blob(
        &decompressed_dst,
        &dst_info.block_info,
        dst_info.zero_padding_enabled,
        algo_type,
        algo_level,
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

    // Fallible allocation: a corrupt block_info declaring gigabytes must surface
    // as an error, not an allocation-failure abort.
    let mut output = bufpool::try_alloc_capacity(total_uncompressed as usize)?;
    let mut compressed_offset: usize = 0;

    for block in blocks {
        let block_end = compressed_offset + block.compressed_length as usize;
        let block_data = &data[compressed_offset..block_end];

        if !is_compressed(block) {
            let to_copy = (block.uncompressed_length as usize).min(block_data.len());
            output.extend_from_slice(&block_data[..to_copy]);
        } else {
            let mut inputmargin = 0usize;
            if zero_padding_enabled {
                let scan_len = (4096).min(block_data.len());
                while inputmargin < scan_len && block_data[inputmargin] == 0 {
                    inputmargin += 1;
                }
            }
            let input = &block_data[inputmargin..];
            let out_start = output.len();
            let uncompressed_len = block.uncompressed_length as usize;
            output.resize(out_start + uncompressed_len, 0);

            let ret = unsafe {
                LZ4_decompress_safe_partial(
                    input.as_ptr() as *const std::ffi::c_char,
                    output[out_start..].as_mut_ptr() as *mut std::ffi::c_char,
                    input.len() as std::ffi::c_int,
                    uncompressed_len as std::ffi::c_int,
                    uncompressed_len as std::ffi::c_int,
                )
            };

            if ret < 0 || (ret as usize) != uncompressed_len {
                bail!(
                    "LZ4 decompression failed: ret={ret}, expected {uncompressed_len} bytes"
                );
            }
        }

        compressed_offset = block_end;
    }

    // Trailing data not recorded by compressed block info is treated as uncompressed
    if compressed_offset < data.len() {
        output.extend_from_slice(&data[compressed_offset..]);
    }

    Ok(output)
}

/// Compress a blob using LZ4 block info, with postfix patch support.
fn compress_blob(
    data: &[u8],
    blocks: &[CompressedBlockInfo],
    zero_padding_enabled: bool,
    algo_type: compression_algorithm::Type,
    algo_level: i32,
) -> Result<Vec<u8>> {
    if blocks.is_empty() {
        return Ok(data.to_vec());
    }

    let uncompressed_size: usize = blocks.iter().map(|b| b.uncompressed_length as usize).sum();
    let total_compressed: u64 = blocks.iter().map(|b| b.compressed_length).sum();
    let mut output = bufpool::try_alloc_capacity(total_compressed as usize)?;

    let hc = unsafe { LZ4_createStreamHC() };
    struct HcGuard(*mut std::ffi::c_void);
    impl Drop for HcGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LZ4_freeStreamHC(self.0) };
            }
        }
    }
    let _hc_guard = HcGuard(hc);

    for block in blocks {
        let block_start = block.uncompressed_offset as usize;
        let block_end = block_start + block.uncompressed_length as usize;
        if block_end > data.len() {
            bail!(
                "LZ4DIFF block out of bounds: [{block_start}..{block_end}) exceeds {} bytes",
                data.len()
            );
        }
        let uncompressed_block = &data[block_start..block_end];

        if !is_compressed(block) {
            output.extend_from_slice(uncompressed_block);
            let clen = block.compressed_length as usize;
            if clen > uncompressed_block.len() {
                output.resize(output.len() + (clen - uncompressed_block.len()), 0);
            }
            continue;
        }

        let target_size = block.compressed_length as usize;
        let mut block_buf = bufpool::try_alloc_zeroed(target_size)?;

        // Remaining uncompressed bytes from this block's start up to uncompressed_size,
        // mirroring AOSP update_engine's TryCompressBlob.
        let mut src_size = (uncompressed_size.saturating_sub(block_start)) as std::ffi::c_int;

        let ret = match algo_type {
            compression_algorithm::Type::Uncompressed => {
                let to_copy = uncompressed_block.len().min(target_size);
                block_buf[..to_copy].copy_from_slice(&uncompressed_block[..to_copy]);
                to_copy as std::ffi::c_int
            }
            compression_algorithm::Type::Lz4hc => unsafe {
                LZ4_compress_HC_destSize(
                    hc,
                    uncompressed_block.as_ptr() as *const std::ffi::c_char,
                    block_buf.as_mut_ptr() as *mut std::ffi::c_char,
                    &mut src_size,
                    target_size as std::ffi::c_int,
                    algo_level as std::ffi::c_int,
                )
            },
            compression_algorithm::Type::Lz4 => unsafe {
                LZ4_compress_destSize(
                    uncompressed_block.as_ptr() as *const std::ffi::c_char,
                    block_buf.as_mut_ptr() as *mut std::ffi::c_char,
                    &mut src_size,
                    target_size as std::ffi::c_int,
                )
            },
        };

        if ret <= 0 {
            bail!(
                "LZ4 compression failed (code {ret}) for block at offset {block_start} (target {target_size} bytes)"
            );
        }

        let bytes_written = (ret as usize).min(target_size);

        if bytes_written < target_size {
            if zero_padding_enabled {
                // Compressed data at END, zero padding at START
                let padding = target_size - bytes_written;
                block_buf.copy_within(0..bytes_written, padding);
                block_buf[..padding].fill(0);
            } else {
                // Compressed data at START, zero padding at END
                block_buf[bytes_written..].fill(0);
            }
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
                        "{} LZ4DIFF postfix hash mismatch at offset {}, \
                         skipping postfix patch (LZ4 implementation difference)",
                        style::warning().apply_to("warning:"),
                        block.uncompressed_offset
                    );
                    output.extend_from_slice(&block_buf);
                    continue;
                }
            }

            let fixed = apply_bsdiff(&block_buf, &block.postfix_bspatch)
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
