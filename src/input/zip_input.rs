use std::io::Cursor;
use std::io::Read;

use anyhow::Result;
use memmap2::Mmap;

use super::{OTA_METADATA_PATH, OtaMetadata};
use crate::error::PayloadError;
use crate::payload::PayloadView;

pub fn open_zip_with_metadata(mmap: Mmap) -> Result<(PayloadView, Option<OtaMetadata>)> {
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let ota_metadata = read_ota_metadata(&mut archive)?;

    // Find the payload.bin entry and get its raw data offset
    let payload_offset = {
        let mut found = None;
        for i in 0..archive.len() {
            let entry = archive.by_index_raw(i)?;
            if entry.name() == "payload.bin" {
                found = entry.data_start();
                break;
            }
        }
        found.ok_or(PayloadError::PayloadNotFoundInZip)?
    };

    Ok((PayloadView::from_mmap(mmap, payload_offset)?, ota_metadata))
}

fn read_ota_metadata<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<Option<OtaMetadata>> {
    let mut entry = match archive.by_name(OTA_METADATA_PATH) {
        Ok(entry) => entry,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut contents = String::new();
    entry.read_to_string(&mut contents)?;
    Ok(Some(parse_ota_metadata(&contents)))
}

pub(crate) fn parse_ota_metadata(contents: &str) -> OtaMetadata {
    let mut meta = OtaMetadata::default();

    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "post-build" => meta.post_build = Some(value.trim().to_string()),
            "post-osversion" => meta.post_osversion = Some(value.trim().to_string()),
            "pre-device" => meta.pre_device = Some(value.trim().to_string()),
            _ => {}
        }
    }

    meta
}
