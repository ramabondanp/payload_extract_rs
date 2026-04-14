pub mod local;
pub mod zip_input;

#[cfg(feature = "http")]
pub mod http;

use std::path::Path;

use anyhow::{Context, Result};
use memmap2::Mmap;

use crate::payload::PayloadView;

pub(crate) const ZIP_MAGIC: &[u8; 4] = &[0x50, 0x4B, 0x03, 0x04];
pub(crate) const OTA_METADATA_PATH: &str = "META-INF/com/android/metadata";

#[derive(Debug, Clone, Default)]
pub struct OtaMetadata {
    pub post_build: Option<String>,
    pub post_osversion: Option<String>,
    pub pre_device: Option<String>,
}

/// Open a payload from a file path or URL and return a PayloadView.
/// For HTTP URLs, only downloads header + manifest (sufficient for list/metadata).
pub fn open(input: &str, insecure: bool) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_metadata(input, insecure);
    }

    let _ = insecure;
    open_local_file(input)
}

/// Open a payload and, when the source is an OTA ZIP, extract selected OTA metadata.
pub fn open_with_ota_metadata(
    input: &str,
    insecure: bool,
) -> Result<(PayloadView, Option<OtaMetadata>)> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_metadata_with_ota(input, insecure);
    }

    let _ = insecure;
    open_local_file_with_ota_metadata(input)
}

/// Open a payload for extraction. For HTTP URLs, selectively downloads
/// only the operation data needed for the specified partitions.
/// If `partition_names` is empty, downloads the entire payload.
pub fn open_for_extract(
    input: &str,
    partition_names: &[String],
    insecure: bool,
) -> Result<PayloadView> {
    #[cfg(feature = "http")]
    if input.starts_with("http://") || input.starts_with("https://") {
        return http::open_http_extract(input, partition_names, insecure);
    }

    let _ = (partition_names, insecure);
    open_local_file(input)
}

fn open_local_file(input: &str) -> Result<PayloadView> {
    Ok(open_local_file_with_ota_metadata(input)?.0)
}

fn open_local_file_with_ota_metadata(input: &str) -> Result<(PayloadView, Option<OtaMetadata>)> {
    let path = Path::new(input);
    let file = std::fs::File::open(path).with_context(|| format!("failed to open '{}'", input))?;

    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("failed to mmap '{}'", input))?;

    // Detect format by magic bytes
    if mmap.len() >= 4 && &mmap[0..4] == ZIP_MAGIC {
        zip_input::open_zip_with_metadata(mmap).context("failed to open ZIP payload")
    } else {
        Ok((
            local::open_local(mmap).context("failed to open raw payload")?,
            None,
        ))
    }
}
