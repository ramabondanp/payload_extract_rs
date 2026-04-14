use anyhow::Result;
use clap::Args;
use serde::Serialize;
use time::OffsetDateTime;
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;

use crate::input;
use crate::style;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    max_timestamp_utc: Option<String>,
    partial_update: Option<bool>,
    security_patch_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_osversion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_device: Option<String>,
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

const HUMAN_UTC_TIMESTAMP_FORMAT: &[time::format_description::BorrowedFormatItem<'static>] = time::macros::format_description!(
    "[weekday repr:short] [month repr:short] [day] [hour repr:12 padding:zero]:[minute]:[second] [period case:upper] UTC [year]"
);

fn format_unix_timestamp_utc(ts: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn format_unix_timestamp_utc_human(ts: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()?
        .to_offset(UtcOffset::UTC)
        .format(HUMAN_UTC_TIMESTAMP_FORMAT)
        .ok()
}

fn print_metadata_line(label: &str, value: impl std::fmt::Display) {
    println!("  {:<25} {}", style::label().apply_to(label), value);
}

pub fn run(args: MetadataArgs, insecure: bool) -> Result<()> {
    let (payload, ota_metadata) = input::open_with_ota_metadata(&args.input, insecure)?;
    let header = payload.header();
    let manifest = payload.manifest();
    let max_timestamp_utc = manifest.max_timestamp.and_then(format_unix_timestamp_utc);

    let dyn_meta = manifest
        .dynamic_partition_metadata
        .as_ref()
        .map(|d| DynPartMeta {
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
        max_timestamp_utc,
        partial_update: manifest.partial_update,
        security_patch_level: manifest.security_patch_level.clone(),
        post_build: ota_metadata.as_ref().and_then(|m| m.post_build.clone()),
        post_osversion: ota_metadata.as_ref().and_then(|m| m.post_osversion.clone()),
        pre_device: ota_metadata.as_ref().and_then(|m| m.pre_device.clone()),
        dynamic_partition_metadata: dyn_meta,
        apex_info,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!("{}", style::label().apply_to("Payload Metadata:"));
        print_metadata_line("Version:", metadata.version);
        print_metadata_line(
            "Manifest size:",
            format!("{} bytes", metadata.manifest_size),
        );
        print_metadata_line(
            "Metadata signature size:",
            format!("{} bytes", metadata.metadata_signature_size),
        );
        print_metadata_line("Block size:", format!("{} bytes", metadata.block_size));
        print_metadata_line("Partitions:", metadata.partition_count);
        if let Some(ts) = metadata.max_timestamp {
            print_metadata_line("Max timestamp:", ts);
            let date = format_unix_timestamp_utc_human(ts)
                .unwrap_or_else(|| "invalid timestamp".to_string());
            print_metadata_line("Date:", date);
        }
        if let Some(partial) = metadata.partial_update {
            print_metadata_line("Partial update:", partial);
        }
        if let Some(ref spl) = metadata.security_patch_level {
            print_metadata_line("Security patch level:", spl);
        }
        if let Some(ref post_build) = metadata.post_build {
            print_metadata_line("Post build:", post_build);
        }
        if let Some(ref post_osversion) = metadata.post_osversion {
            print_metadata_line("Post osversion:", post_osversion);
        }
        if let Some(ref pre_device) = metadata.pre_device {
            print_metadata_line("Pre device:", pre_device);
        }

        if let Some(ref dyn_meta) = metadata.dynamic_partition_metadata {
            println!(
                "\n{}",
                style::label().apply_to("Dynamic Partition Metadata:")
            );
            if let Some(snap) = dyn_meta.snapshot_enabled {
                println!(
                    "  {}         {snap}",
                    style::label().apply_to("Snapshot enabled:")
                );
            }
            if let Some(vabc) = dyn_meta.vabc_enabled {
                println!(
                    "  {}             {vabc}",
                    style::label().apply_to("VABC enabled:")
                );
            }
            if let Some(ref param) = dyn_meta.vabc_compression_param {
                println!(
                    "  {}         {param}",
                    style::label().apply_to("VABC compression:")
                );
            }
            if let Some(cow) = dyn_meta.cow_version {
                println!(
                    "  {}              {cow}",
                    style::label().apply_to("COW version:")
                );
            }
            for group in &dyn_meta.groups {
                println!(
                    "  {} '{}': size={}, partitions=[{}]",
                    style::label().apply_to("Group"),
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
            println!("\n{}", style::label().apply_to("APEX Info:"));
            for apex in &metadata.apex_info {
                println!(
                    "  {} v{} {}={} {}={}",
                    style::bold().apply_to(apex.package_name.as_deref().unwrap_or("?")),
                    apex.version.unwrap_or(0),
                    style::label().apply_to("compressed"),
                    apex.is_compressed.unwrap_or(false),
                    style::label().apply_to("decompressed_size"),
                    apex.decompressed_size.unwrap_or(0)
                );
            }
        }
    }

    Ok(())
}
