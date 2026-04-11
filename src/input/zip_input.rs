use std::io::Cursor;

use anyhow::Result;
use memmap2::Mmap;

use crate::error::PayloadError;
use crate::payload::PayloadView;

/// Open a payload.bin from within a ZIP archive via zero-copy passthrough.
///
/// OTA ZIPs store payload.bin with the STORE method (no compression),
/// so we can locate the entry's data offset and mmap through it directly.
pub fn open_zip(mmap: Mmap) -> Result<PayloadView> {
    let cursor = Cursor::new(&mmap[..]);
    let mut archive = zip::ZipArchive::new(cursor)?;

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

    Ok(PayloadView::from_mmap(mmap, payload_offset)?)
}
