pub mod header;

use std::collections::HashMap;

use memmap2::Mmap;
use prost::Message;

use crate::error::PayloadError;
use crate::proto::{DeltaArchiveManifest, PartitionUpdate};

pub use header::{HEADER_SIZE, PayloadHeader};

/// Data backing for PayloadView — either mmap'd file or in-memory buffer.
enum PayloadData {
    Mmap(Mmap),
    Memory(Vec<u8>),
}

impl PayloadData {
    fn as_slice(&self) -> &[u8] {
        match self {
            PayloadData::Mmap(m) => m,
            PayloadData::Memory(v) => v,
        }
    }
}

/// Zero-copy view over a payload file.
///
/// Supports two modes:
/// - **Mmap mode**: the entire payload (or ZIP containing it) is memory-mapped.
/// - **Compact mode** (HTTP): metadata + only needed data ranges are packed
///   contiguously, with an offset remap table so `blob_slice_raw` still works.
pub struct PayloadView {
    data: PayloadData,
    header: PayloadHeader,
    manifest: DeltaArchiveManifest,
    /// Absolute byte offset where data blobs begin (within payload)
    data_offset: u64,
    /// Byte offset of payload within the backing data (non-zero for ZIP passthrough)
    payload_offset: u64,
    /// Offset remap table for compact HTTP mode:
    /// maps (original_data_region_offset, length) → position in backing data.
    /// When present, blob_slice_raw uses this instead of direct indexing.
    remap: Option<HashMap<u64, (u64, u64)>>, // orig_offset -> (compact_pos, length)
}

impl PayloadView {
    /// Create a PayloadView from a memory-mapped file.
    pub fn from_mmap(mmap: Mmap, payload_offset: u64) -> Result<Self, PayloadError> {
        let data = PayloadData::Mmap(mmap);
        Self::from_data(data, payload_offset, None)
    }

    /// Create a PayloadView from a memory-mapped file with offset remapping.
    /// Used for HTTP selective download where data is stored in a temporary file.
    pub fn from_mmap_with_remap(
        mmap: Mmap,
        payload_offset: u64,
        remap: HashMap<u64, (u64, u64)>,
    ) -> Result<Self, PayloadError> {
        let data = PayloadData::Mmap(mmap);
        Self::from_data(data, payload_offset, Some(remap))
    }

    /// Create a PayloadView from an in-memory buffer with offset remapping.
    /// Used for HTTP selective download where data is packed compactly.
    pub fn from_memory(
        buf: Vec<u8>,
        remap: HashMap<u64, (u64, u64)>,
    ) -> Result<Self, PayloadError> {
        let data = PayloadData::Memory(buf);
        Self::from_data(data, 0, Some(remap))
    }

    fn from_data(
        data: PayloadData,
        payload_offset: u64,
        remap: Option<HashMap<u64, (u64, u64)>>,
    ) -> Result<Self, PayloadError> {
        let base = payload_offset as usize;
        let slice = &data.as_slice()[base..];

        let header = PayloadHeader::parse(slice)?;

        let manifest_start = HEADER_SIZE;
        let manifest_end = manifest_start + header.manifest_size as usize;

        if slice.len() < manifest_end {
            return Err(PayloadError::PayloadTooSmall {
                expected: base + manifest_end,
                actual: data.as_slice().len(),
            });
        }

        let manifest = DeltaArchiveManifest::decode(&slice[manifest_start..manifest_end])?;
        let data_offset = header.data_offset();

        // Advise the kernel about sequential access pattern for better readahead
        #[cfg(unix)]
        if let PayloadData::Mmap(ref mmap) = data {
            let _ = mmap.advise(memmap2::Advice::Sequential);
        }

        Ok(Self {
            data,
            header,
            manifest,
            data_offset,
            payload_offset,
            remap,
        })
    }

    pub fn header(&self) -> &PayloadHeader {
        &self.header
    }

    pub fn manifest(&self) -> &DeltaArchiveManifest {
        &self.manifest
    }

    pub fn block_size(&self) -> u32 {
        self.manifest.block_size.unwrap_or(4096)
    }

    pub fn partitions(&self) -> &[PartitionUpdate] {
        &self.manifest.partitions
    }

    /// Get partitions filtered by name. If `names` is empty, return all.
    pub fn selected_partitions(&self, names: &[String]) -> Vec<&PartitionUpdate> {
        if names.is_empty() {
            self.manifest.partitions.iter().collect()
        } else {
            self.manifest
                .partitions
                .iter()
                .filter(|p| names.iter().any(|n| n == &p.partition_name))
                .collect()
        }
    }

    /// Get data for an operation's blob.
    ///
    /// In mmap mode: zero-copy slice into the mapped region.
    /// In compact/remap mode: looks up the remapped position.
    #[inline]
    pub fn blob_slice_raw(
        &self,
        data_offset: u64,
        data_length: u64,
    ) -> Result<&[u8], PayloadError> {
        let slice = self.data.as_slice();

        if let Some(ref remap) = self.remap {
            // Compact mode: look up remapped position
            if let Some(&(compact_pos, _len)) = remap.get(&data_offset) {
                let start = compact_pos as usize;
                let end = start + data_length as usize;
                return slice.get(start..end).ok_or(PayloadError::PayloadTooSmall {
                    expected: end,
                    actual: slice.len(),
                });
            }
            // Fallback: try direct indexing
        }

        // Mmap mode: direct indexing
        let abs_start =
            self.payload_offset as usize + self.data_offset as usize + data_offset as usize;
        let abs_end = abs_start + data_length as usize;
        slice
            .get(abs_start..abs_end)
            .ok_or(PayloadError::PayloadTooSmall {
                expected: abs_end,
                actual: slice.len(),
            })
    }

    #[allow(dead_code)]
    pub fn metadata_bytes(&self) -> &[u8] {
        let base = self.payload_offset as usize;
        let end = base + HEADER_SIZE + self.header.manifest_size as usize;
        &self.data.as_slice()[base..end]
    }

    #[allow(dead_code)]
    pub fn metadata_signature_bytes(&self) -> Option<&[u8]> {
        if self.header.metadata_signature_size == 0 {
            return None;
        }
        let base = self.payload_offset as usize;
        let start = base + HEADER_SIZE + self.header.manifest_size as usize;
        let end = start + self.header.metadata_signature_size as usize;
        let slice = self.data.as_slice();
        if end <= slice.len() {
            Some(&slice[start..end])
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn metadata_hash(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.metadata_bytes()).to_vec()
    }

    #[allow(dead_code)]
    pub fn payload_signatures_bytes(&self) -> Option<&[u8]> {
        let offset = self.manifest.signatures_offset?;
        let size = self.manifest.signatures_size?;
        let base = self.payload_offset as usize + self.data_offset as usize;
        let start = base + offset as usize;
        let end = start + size as usize;
        let slice = self.data.as_slice();
        if end <= slice.len() {
            Some(&slice[start..end])
        } else {
            None
        }
    }
}
