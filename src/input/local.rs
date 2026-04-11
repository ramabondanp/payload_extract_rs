use anyhow::Result;
use memmap2::Mmap;

use crate::payload::PayloadView;

/// Open a raw payload.bin file (already mmap'd).
pub fn open_local(mmap: Mmap) -> Result<PayloadView> {
    Ok(PayloadView::from_mmap(mmap, 0)?)
}
