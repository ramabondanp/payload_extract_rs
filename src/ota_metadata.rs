use std::collections::BTreeMap;

use anyhow::{Context, Result};
use prost::Message;
use serde::Serialize;

use crate::proto::ota_metadata as pb;

const TEXT_ENTRY: &str = "META-INF/com/android/metadata";
const PB_ENTRY: &str = "META-INF/com/android/metadata.pb";

pub fn text_entry_name() -> &'static str {
    TEXT_ENTRY
}

pub fn pb_entry_name() -> &'static str {
    PB_ENTRY
}

#[derive(Default, Serialize)]
pub struct OtaMetadataData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pb: Option<OtaMetadataPb>,
}

impl OtaMetadataData {
    pub fn is_empty(&self) -> bool {
        self.text.is_none() && self.pb.is_none()
    }
}

#[derive(Default, Serialize)]
pub struct TextMetadata {
    pub entries: BTreeMap<String, String>,
}

pub fn parse_text(s: &str) -> TextMetadata {
    let mut entries = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim_matches(['\r', '\n', ' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            entries.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    TextMetadata { entries }
}

pub fn parse_pb_bytes(bytes: &[u8]) -> Result<OtaMetadataPb> {
    let raw = pb::OtaMetadata::decode(bytes).context("failed to decode metadata.pb")?;
    Ok(OtaMetadataPb::from_proto(raw))
}

#[derive(Default, Serialize)]
pub struct OtaMetadataPb {
    pub r#type: String,
    pub wipe: bool,
    pub downgrade: bool,
    pub retrofit_dynamic_partitions: bool,
    pub required_cache: i64,
    pub spl_downgrade: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub property_files: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precondition: Option<DeviceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postcondition: Option<DeviceState>,
}

#[derive(Default, Serialize)]
pub struct DeviceState {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub device: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub build: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub build_incremental: String,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sdk_level: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub security_patch_level: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub partition_state: Vec<PartitionState>,
}

#[derive(Default, Serialize)]
pub struct PartitionState {
    pub partition_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub device: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub build: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
}

impl OtaMetadataPb {
    fn from_proto(m: pb::OtaMetadata) -> Self {
        let r#type = match pb::ota_metadata::OtaType::try_from(m.r#type) {
            Ok(t) => format!("{t:?}").to_uppercase(),
            Err(_) => format!("UNKNOWN({})", m.r#type),
        };
        Self {
            r#type,
            wipe: m.wipe,
            downgrade: m.downgrade,
            retrofit_dynamic_partitions: m.retrofit_dynamic_partitions,
            required_cache: m.required_cache,
            spl_downgrade: m.spl_downgrade,
            property_files: m.property_files.into_iter().collect(),
            precondition: m.precondition.map(DeviceState::from_proto),
            postcondition: m.postcondition.map(DeviceState::from_proto),
        }
    }
}

impl DeviceState {
    fn from_proto(d: pb::DeviceState) -> Self {
        Self {
            device: d.device,
            build: d.build,
            build_incremental: d.build_incremental,
            timestamp: d.timestamp,
            sdk_level: d.sdk_level,
            security_patch_level: d.security_patch_level,
            partition_state: d
                .partition_state
                .into_iter()
                .map(PartitionState::from_proto)
                .collect(),
        }
    }
}

impl PartitionState {
    fn from_proto(p: pb::PartitionState) -> Self {
        Self {
            partition_name: p.partition_name,
            device: p.device,
            build: p.build,
            version: p.version,
        }
    }
}
