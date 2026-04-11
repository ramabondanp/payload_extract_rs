pub mod bufpool;
pub mod decompress;
pub mod lz4diff;
pub mod operation;
pub mod verify;
pub mod writer;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;

use crate::payload::PayloadView;

use operation::{OpType, OperationTask};
use writer::PartitionWriter;

/// Configuration for extraction.
pub struct ExtractConfig {
    pub verify_ops: bool,
    pub threads: usize,
    pub quiet: bool,
    /// Source directory for delta/incremental OTA (contains old partition .img files)
    pub source_dir: Option<String>,
    /// Custom output paths per partition (from --out-config)
    pub out_config: Option<HashMap<String, PathBuf>>,
}

/// Extract selected partitions from a payload.
pub fn extract_partitions(
    payload: &PayloadView,
    output_dir: &Path,
    partition_names: &[String],
    config: &ExtractConfig,
) -> Result<()> {
    let partitions = payload.selected_partitions(partition_names);
    if partitions.is_empty() {
        bail!("no partitions selected for extraction");
    }

    let block_size = payload.block_size();
    std::fs::create_dir_all(output_dir)?;

    // Check if any partition has delta operations
    let has_delta_ops = partitions.iter().any(|p| {
        p.operations.iter().any(|op| {
            let op_type = op.r#type();
            matches!(
                op_type,
                crate::proto::install_operation::Type::SourceCopy
                    | crate::proto::install_operation::Type::SourceBsdiff
                    | crate::proto::install_operation::Type::BrotliBsdiff
                    | crate::proto::install_operation::Type::Puffdiff
                    | crate::proto::install_operation::Type::Zucchini
                    | crate::proto::install_operation::Type::Lz4diffBsdiff
                    | crate::proto::install_operation::Type::Lz4diffPuffdiff
            )
        })
    });

    if has_delta_ops && config.source_dir.is_none() {
        bail!(
            "this is a delta/incremental OTA payload — \
             source partition directory is required (use --source-dir)"
        );
    }

    // Configure rayon thread pool
    let thread_count = if config.threads == 0 {
        num_cpus::get()
    } else {
        config.threads
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .context("failed to create thread pool")?;

    // Setup progress bars
    let multi_progress = MultiProgress::new();
    let style = ProgressStyle::with_template(
        "{prefix:>20} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) [{elapsed_precise}<{eta_precise}] {msg}",
    )
    .unwrap()
    .progress_chars("=> ");

    pool.install(|| {
        partitions.par_iter().try_for_each(|partition| -> Result<()> {
            let part_name = &partition.partition_name;
            let output_path = if let Some(ref out_config) = config.out_config {
                if let Some(custom_path) = out_config.get(part_name) {
                    // Ensure parent directory exists for custom paths
                    if let Some(parent) = custom_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    custom_path.clone()
                } else {
                    output_dir.join(format!("{part_name}.img"))
                }
            } else {
                output_dir.join(format!("{part_name}.img"))
            };

            // Determine partition size
            let part_size = partition
                .new_partition_info
                .as_ref()
                .and_then(|info| info.size)
                .unwrap_or_else(|| {
                    partition
                        .operations
                        .iter()
                        .flat_map(|op| &op.dst_extents)
                        .map(|ext| {
                            (ext.start_block.unwrap_or(0) + ext.num_blocks.unwrap_or(0))
                                * block_size as u64
                        })
                        .max()
                        .unwrap_or(0)
                });

            // Create pre-allocated output file
            let writer = Arc::new(PartitionWriter::new(&output_path, part_size, block_size)?);

            // Open source partition for delta OTA if needed
            let source_mmap = if let Some(ref source_dir) = config.source_dir {
                let src_path =
                    Path::new(source_dir).join(format!("{part_name}.img"));
                if src_path.exists() {
                    let file = std::fs::File::open(&src_path)?;
                    Some(unsafe { memmap2::Mmap::map(&file) }?)
                } else {
                    None
                }
            } else {
                None
            };

            // Build operation tasks
            let mut tasks: Vec<OperationTask> = Vec::with_capacity(partition.operations.len());
            for op in &partition.operations {
                let op_type_raw = op.r#type();
                let op_type = OpType::from_proto(op_type_raw).map_err(|_| {
                    crate::error::PayloadError::UnsupportedOperation(op_type_raw as i32)
                })?;

                let src_extents: Vec<(u64, u64)> = op
                    .src_extents
                    .iter()
                    .map(|e| (e.start_block.unwrap_or(0), e.num_blocks.unwrap_or(0)))
                    .collect();

                let dst_extents: Vec<(u64, u64)> = op
                    .dst_extents
                    .iter()
                    .map(|e| (e.start_block.unwrap_or(0), e.num_blocks.unwrap_or(0)))
                    .collect();

                tasks.push(OperationTask {
                    op_type,
                    data_offset: op.data_offset.unwrap_or(0),
                    data_length: op.data_length.unwrap_or(0),
                    src_extents,
                    dst_extents,
                    data_sha256: op.data_sha256_hash.clone(),
                });
            }

            // Sort by data_offset for sequential payload reads
            tasks.sort_by_key(|t| t.data_offset);

            // Setup progress bar
            let pb = if !config.quiet {
                let pb = multi_progress.add(ProgressBar::new(tasks.len() as u64));
                pb.set_style(style.clone());
                pb.set_prefix(part_name.clone());
                Some(pb)
            } else {
                None
            };

            let completed = AtomicU64::new(0);

            // Execute operations in parallel via rayon
            tasks.par_iter().try_for_each(|task| -> Result<()> {
                process_operation(
                    payload,
                    task,
                    &writer,
                    block_size,
                    config,
                    source_mmap.as_deref(),
                )?;

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(pb) = &pb {
                    pb.set_position(done);
                }

                Ok(())
            })?;

            if let Some(pb) = &pb {
                pb.finish_with_message("done");
            }

            Ok(())
        })
    })
}

/// Process a single extraction operation.
fn process_operation(
    payload: &PayloadView,
    task: &OperationTask,
    writer: &PartitionWriter,
    block_size: u32,
    config: &ExtractConfig,
    source_data: Option<&[u8]>,
) -> Result<()> {
    match task.op_type {
        OpType::Zero | OpType::Discard => {
            // Write zeros for all destination extents
            // DISCARD semantics: data is undefined, we write zeros for consistency
            for &(start_block, num_blocks) in &task.dst_extents {
                writer.write_zeros(start_block, num_blocks)?;
            }
        }
        OpType::Replace => {
            // Zero-copy: slice directly from mmap and pwrite to output
            let blob = get_blob(payload, task)?;

            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            write_to_extents(blob, &task.dst_extents, writer, block_size)?;
        }
        OpType::SourceCopy => {
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("SOURCE_COPY requires source partition data")
            })?;
            let data = read_from_extents(src, &task.src_extents, block_size);
            write_to_extents(&data, &task.dst_extents, writer, block_size)?;
        }
        OpType::SourceBsdiff => {
            // SOURCE_BSDIFF: BSDIFF40 format (bz2 compressed)
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("SOURCE_BSDIFF requires source partition data")
            })?;
            let src_data = read_from_extents(src, &task.src_extents, block_size);

            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            let patched = apply_bsdiff(&src_data, blob, "source_bsdiff")?;
            write_to_extents(&patched, &task.dst_extents, writer, block_size)?;
        }
        OpType::BrotliBsdiff => {
            // BROTLI_BSDIFF: BSDF2 format (brotli compressed streams)
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("BROTLI_BSDIFF requires source partition data")
            })?;
            let src_data = read_from_extents(src, &task.src_extents, block_size);

            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            let mut patched = Vec::new();
            bsdiff_android::patch_bsdf2(&src_data, blob, &mut patched)
                .map_err(|e| anyhow::anyhow!("BROTLI_BSDIFF patch failed: {e}"))?;
            write_to_extents(&patched, &task.dst_extents, writer, block_size)?;
        }
        OpType::Puffdiff => {
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("PUFFDIFF requires source partition data")
            })?;
            let src_data = read_from_extents(src, &task.src_extents, block_size);

            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            // Puffdiff uses bsdiff internally on "puffed" (inflated) data
            let patched = apply_bsdiff(&src_data, blob, "puffdiff")?;
            write_to_extents(&patched, &task.dst_extents, writer, block_size)?;
        }
        OpType::Zucchini => {
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("ZUCCHINI requires source partition data")
            })?;
            let src_data = read_from_extents(src, &task.src_extents, block_size);

            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            // Zucchini uses bsdiff-compatible format
            let patched = apply_bsdiff(&src_data, blob, "zucchini")?;
            write_to_extents(&patched, &task.dst_extents, writer, block_size)?;
        }
        OpType::Lz4diffBsdiff | OpType::Lz4diffPuffdiff => {
            let src = source_data.ok_or_else(|| {
                anyhow::anyhow!("{:?} requires source partition data", task.op_type)
            })?;
            let src_data = read_from_extents(src, &task.src_extents, block_size);

            let blob = get_blob(payload, task)?;
            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            let patched = lz4diff::apply_lz4diff(&src_data, blob, task.op_type)?;
            write_to_extents(&patched, &task.dst_extents, writer, block_size)?;
        }
        OpType::ReplaceBz | OpType::ReplaceXz | OpType::ReplaceZstd => {
            // Compressed full-OTA operations: decompress then write
            let blob = get_blob(payload, task)?;

            if config.verify_ops {
                verify::verify_sha256(blob, &task.data_sha256)?;
            }

            let expected_size: u64 = task
                .dst_extents
                .iter()
                .map(|&(_, num_blocks)| num_blocks * block_size as u64)
                .sum();

            bufpool::with_buffer(expected_size as usize, |buf| {
                decompress::decompress(task.op_type, blob, buf)?;
                write_to_extents(buf, &task.dst_extents, writer, block_size)
            })?;
        }
    }

    Ok(())
}

/// Get blob data for an operation from the payload (zero-copy mmap slice).
#[inline]
fn get_blob<'a>(payload: &'a PayloadView, task: &OperationTask) -> Result<&'a [u8]> {
    Ok(payload.blob_slice_raw(task.data_offset, task.data_length)?)
}

/// Apply a bsdiff patch to source data, producing new data.
fn apply_bsdiff(old: &[u8], patch_data: &[u8], context: &str) -> Result<Vec<u8>> {
    let mut patch_reader = std::io::Cursor::new(patch_data);
    let mut new = Vec::new();
    bsdiff_android::patch(old, &mut patch_reader, &mut new).map_err(|e| {
        anyhow::anyhow!("{context} bsdiff patch failed: {e}")
    })?;
    Ok(new)
}

/// Read data from source partition by extents.
fn read_from_extents(source: &[u8], extents: &[(u64, u64)], block_size: u32) -> Vec<u8> {
    let total_size: u64 = extents
        .iter()
        .map(|&(_, num_blocks)| num_blocks * block_size as u64)
        .sum();
    let mut data = Vec::with_capacity(total_size as usize);

    for &(start_block, num_blocks) in extents {
        let offset = (start_block * block_size as u64) as usize;
        let len = (num_blocks * block_size as u64) as usize;
        let end = (offset + len).min(source.len());
        if offset < source.len() {
            data.extend_from_slice(&source[offset..end]);
        }
    }

    data
}

/// Write decompressed data to non-contiguous destination extents.
fn write_to_extents(
    data: &[u8],
    extents: &[(u64, u64)],
    writer: &PartitionWriter,
    block_size: u32,
) -> Result<()> {
    let mut data_offset = 0usize;
    for &(start_block, num_blocks) in extents {
        let extent_size = (num_blocks * block_size as u64) as usize;
        let end = (data_offset + extent_size).min(data.len());
        writer.write_at_block(&data[data_offset..end], start_block)?;
        data_offset = end;
    }
    Ok(())
}
