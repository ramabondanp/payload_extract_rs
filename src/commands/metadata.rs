use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::input;

#[derive(Args)]
pub struct MetadataArgs {
    /// Path to payload.bin, OTA ZIP, or HTTP URL
    pub input: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct PayloadMetadata {
    version: u64,
    manifest_size: u64,
    metadata_signature_size: u32,
    block_size: u32,
    partition_count: usize,
    max_timestamp: Option<i64>,
    partial_update: Option<bool>,
    security_patch_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynamic_partition_metadata: Option<DynPartMeta>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    apex_info: Vec<ApexEntry>,
}

#[derive(Serialize)]
struct DynPartMeta {
    snapshot_enabled: Option<bool>,
    vabc_enabled: Option<bool>,
    vabc_compression_param: Option<String>,
    cow_version: Option<u32>,
    groups: Vec<DynPartGroup>,
}

#[derive(Serialize)]
struct DynPartGroup {
    name: String,
    size: Option<u64>,
    partition_names: Vec<String>,
}

#[derive(Serialize)]
struct ApexEntry {
    package_name: Option<String>,
    version: Option<i64>,
    is_compressed: Option<bool>,
    decompressed_size: Option<i64>,
}

pub fn run(args: MetadataArgs, insecure: bool) -> Result<()> {
    let payload = input::open(&args.input, insecure)?;
    let header = payload.header();
    let manifest = payload.manifest();

    let dyn_meta = manifest.dynamic_partition_metadata.as_ref().map(|d| DynPartMeta {
        snapshot_enabled: d.snapshot_enabled,
        vabc_enabled: d.vabc_enabled,
        vabc_compression_param: d.vabc_compression_param.clone(),
        cow_version: d.cow_version,
        groups: d
            .groups
            .iter()
            .map(|g| DynPartGroup {
                name: g.name.clone(),
                size: g.size,
                partition_names: g.partition_names.clone(),
            })
            .collect(),
    });

    let apex_info: Vec<ApexEntry> = manifest
        .apex_info
        .iter()
        .map(|e| ApexEntry {
            package_name: e.package_name.clone(),
            version: e.version,
            is_compressed: e.is_compressed,
            decompressed_size: e.decompressed_size,
        })
        .collect();

    let metadata = PayloadMetadata {
        version: header.version,
        manifest_size: header.manifest_size,
        metadata_signature_size: header.metadata_signature_size,
        block_size: payload.block_size(),
        partition_count: manifest.partitions.len(),
        max_timestamp: manifest.max_timestamp,
        partial_update: manifest.partial_update,
        security_patch_level: manifest.security_patch_level.clone(),
        dynamic_partition_metadata: dyn_meta,
        apex_info,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!("Payload Metadata:");
        println!("  Version:                  {}", metadata.version);
        println!("  Manifest size:            {} bytes", metadata.manifest_size);
        println!(
            "  Metadata signature size:  {} bytes",
            metadata.metadata_signature_size
        );
        println!("  Block size:               {} bytes", metadata.block_size);
        println!("  Partitions:               {}", metadata.partition_count);
        if let Some(ts) = metadata.max_timestamp {
            println!("  Max timestamp:            {ts}");
        }
        if let Some(partial) = metadata.partial_update {
            println!("  Partial update:           {partial}");
        }
        if let Some(ref spl) = metadata.security_patch_level {
            println!("  Security patch level:     {spl}");
        }

        if let Some(ref dyn_meta) = metadata.dynamic_partition_metadata {
            println!("\nDynamic Partition Metadata:");
            if let Some(snap) = dyn_meta.snapshot_enabled {
                println!("  Snapshot enabled:         {snap}");
            }
            if let Some(vabc) = dyn_meta.vabc_enabled {
                println!("  VABC enabled:             {vabc}");
            }
            if let Some(ref param) = dyn_meta.vabc_compression_param {
                println!("  VABC compression:         {param}");
            }
            if let Some(cow) = dyn_meta.cow_version {
                println!("  COW version:              {cow}");
            }
            for group in &dyn_meta.groups {
                println!(
                    "  Group '{}': size={}, partitions=[{}]",
                    group.name,
                    group
                        .size
                        .map(|s| format!("{s}"))
                        .unwrap_or_else(|| "-".into()),
                    group.partition_names.join(", ")
                );
            }
        }

        if !metadata.apex_info.is_empty() {
            println!("\nAPEX Info:");
            for apex in &metadata.apex_info {
                println!(
                    "  {} v{} compressed={} decompressed_size={}",
                    apex.package_name.as_deref().unwrap_or("?"),
                    apex.version.unwrap_or(0),
                    apex.is_compressed.unwrap_or(false),
                    apex.decompressed_size.unwrap_or(0)
                );
            }
        }
    }

    Ok(())
}
