//! Pure-Rust applier for Android OTA `PUFFDIFF` (puffin) delta operations.
//!
//! This is a faithful port of AOSP `external/puffin` (ChromiumOS, BSD-3-Clause).
//! It implements the deflate <-> "puff" transform and the `PUF1` patch
//! container so a PUFFDIFF operation can be applied entirely in Rust, without
//! shelling out to `puffin`/`puff_stream_tool`.
//!
//! The single entry point is [`puffpatch`]: given the raw source bytes (the
//! concatenation of an operation's source extents) and the `PUF1` patch blob
//! from the payload, it returns the patched destination bytes.
//!
//! Only `BSDIFF`-type PUFFDIFF patches are supported. `ZUCCHINI` patches return
//! an error (matching what the Rust payload-dumper needs today).

// This crate is a faithful, line-by-line port of AOSP puffin (C++). A few clippy
// lints are allowed where idiomatic Rust would diverge from the reference and
// make the port harder to audit against it: byte-rounding written as `(x + 7) / 8`
// (manual_div_ceil / manual_is_multiple_of), index-based loops that mirror the
// C++ (needless_range_loop), puffin's `PuffData::Literal` / `Literals` naming
// (enum_variant_names), and the read-callback types (type_complexity).
#![allow(
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::needless_range_loop,
    clippy::enum_variant_names,
    clippy::type_complexity,
    clippy::unnecessary_sort_by
)]

mod bit_io;
mod huffer;
mod huffman;
mod patch;
mod puff_io;
mod puffer;
mod stream;

use std::fmt;

/// An extent measured in bits (used for deflate locations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BitExtent {
    pub offset: u64,
    pub length: u64,
}

/// An extent measured in bytes (used for puff locations).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ByteExtent {
    pub offset: u64,
    pub length: u64,
}

/// Errors that can occur while applying a PUFFDIFF patch.
#[derive(Debug)]
pub enum Error {
    /// The patch did not start with the `PUF1` magic or was truncated.
    BadPatchHeader(String),
    /// The embedded protobuf header could not be parsed.
    BadProto(String),
    /// The patch declared a type this crate does not implement (e.g. ZUCCHINI).
    UnsupportedPatchType(i32),
    /// A malformed deflate / puff stream was encountered.
    Corrupt(String),
    /// The inner bsdiff patch failed to apply.
    Bsdiff(String),
    /// A produced buffer did not match the size declared in the patch header.
    SizeMismatch { expected: u64, actual: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadPatchHeader(s) => write!(f, "bad PUFFDIFF patch header: {s}"),
            Error::BadProto(s) => write!(f, "bad PUFFDIFF proto header: {s}"),
            Error::UnsupportedPatchType(t) => write!(f, "unsupported PUFFDIFF patch type {t}"),
            Error::Corrupt(s) => write!(f, "corrupt puff/deflate stream: {s}"),
            Error::Bsdiff(s) => write!(f, "inner bsdiff patch failed: {s}"),
            Error::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Apply a `PUF1` PUFFDIFF patch to `source`, returning the patched destination.
///
/// `source` must be the raw bytes of the operation's source extents (contiguous)
/// and `patch` the full `PUF1` blob (header + embedded bsdiff patch).
pub fn puffpatch(source: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    patch::apply(source, patch)
}

/// Test/debug helper: locate deflate sub-blocks and puff locations for a whole
/// single-region deflate stream, as puffin's `puffdiff` creation path does.
/// Returns `(deflates_bits, puffs_bytes, puff_length)`. Not a stable API.
#[doc(hidden)]
pub fn _debug_locate(deflate: &[u8]) -> Result<(Vec<(u64, u64)>, Vec<(u64, u64)>, u64)> {
    use bit_io::BitReader;
    use puff_io::PuffWriter;

    // FindDeflateSubBlocks: puff the whole stream, recording compressed blocks.
    let mut throwaway = vec![0u8; deflate.len() * 8 + 4096];
    let mut deflates: Vec<BitExtent> = Vec::new();
    {
        let mut br = BitReader::new(deflate);
        let mut pw = PuffWriter::new(&mut throwaway);
        puffer::puff_deflate_record(&mut br, &mut pw, &mut deflates)?;
    }

    // FindPuffLocations.
    let mut puffs: Vec<(u64, u64)> = Vec::new();
    let mut total_diff: i64 = 0;
    let mut prev: Option<BitExtent> = None;
    for d in &deflates {
        let start_byte = (d.offset / 8) as usize;
        let end_byte = ((d.offset + d.length + 7) / 8) as usize;
        let block = &deflate[start_byte..end_byte];
        let bits_to_skip = (d.offset % 8) as usize;
        let mut tmp = vec![0u8; block.len() * 8 + 4096];
        let puff_size = {
            let mut br = BitReader::new(block);
            br.cache_bits(bits_to_skip);
            br.drop_bits(bits_to_skip);
            let mut pw = PuffWriter::new(&mut tmp);
            puffer::puff_deflate(&mut br, &mut pw)?;
            pw.size() as u64
        };

        let mut gap = 0i64;
        if let Some(pd) = prev {
            if pd.offset + pd.length == d.offset && d.offset % 8 != 0 {
                gap = 1;
            }
        }
        let sb = ((d.offset + 7) / 8) as i64;
        let eb = ((d.offset + d.length) / 8) as i64;
        let deflate_len_bytes = eb - sb;
        let puff_offset = sb - gap + total_diff;
        puffs.push((puff_offset as u64, puff_size));
        total_diff += puff_size as i64 - deflate_len_bytes - gap;
        prev = Some(*d);
    }
    let puff_len = (deflate.len() as i64 + total_diff) as u64;

    let deflates_tuples = deflates.iter().map(|d| (d.offset, d.length)).collect();
    Ok((deflates_tuples, puffs, puff_len))
}

/// Test/debug helper: run the stream puffer with explicit extents.
#[doc(hidden)]
pub fn _debug_stream_puff(
    deflate: &[u8],
    deflates: &[(u64, u64)],
    puffs: &[(u64, u64)],
    puff_len: u64,
) -> Result<Vec<u8>> {
    let d: Vec<BitExtent> = deflates
        .iter()
        .map(|&(offset, length)| BitExtent { offset, length })
        .collect();
    let p: Vec<ByteExtent> = puffs
        .iter()
        .map(|&(offset, length)| ByteExtent { offset, length })
        .collect();
    stream::puff(deflate, &d, &p, puff_len)
}

#[cfg(test)]
mod tests {
    use crate::bit_io::{BitReader, BitWriter};
    use crate::huffer::huff_deflate;
    use crate::puff_io::{PuffReader, PuffWriter};
    use crate::puffer::puff_deflate;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    fn raw_deflate(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Puff a whole deflate buffer, then huff it back, asserting bit-exactness.
    fn roundtrip(compressed: &[u8]) {
        let mut puffed = vec![0u8; compressed.len() * 8 + 4096];
        let puff_size = {
            let mut br = BitReader::new(compressed);
            let mut pw = PuffWriter::new(&mut puffed);
            puff_deflate(&mut br, &mut pw).expect("puff failed");
            pw.size()
        };

        let mut out = vec![0u8; compressed.len()];
        let deflate_size = {
            let mut pr = PuffReader::new(&puffed[..puff_size]);
            let mut bw = BitWriter::new(&mut out);
            huff_deflate(&mut pr, &mut bw).expect("huff failed");
            bw.size()
        };

        assert_eq!(deflate_size, compressed.len(), "deflate length differs");
        assert_eq!(&out[..deflate_size], compressed, "deflate bytes differ");
    }

    /// Drive a full stream puff()+huff() over a single whole-buffer deflate.
    fn stream_roundtrip(compressed: &[u8]) {
        use crate::{BitExtent, ByteExtent};
        let mut tmp = vec![0u8; compressed.len() * 8 + 4096];
        let puff_size = {
            let mut br = BitReader::new(compressed);
            let mut pw = PuffWriter::new(&mut tmp);
            puff_deflate(&mut br, &mut pw).unwrap();
            pw.size() as u64
        };
        let deflates = [BitExtent {
            offset: 0,
            length: compressed.len() as u64 * 8,
        }];
        let puffs = [ByteExtent {
            offset: 0,
            length: puff_size,
        }];
        let puffed = crate::stream::puff(compressed, &deflates, &puffs, puff_size).unwrap();
        let back = crate::stream::huff(&puffed, &deflates, &puffs, puff_size).unwrap();
        assert_eq!(back, compressed, "stream round-trip differs");
    }

    #[test]
    fn stream_roundtrip_across_levels() {
        let inputs: Vec<Vec<u8>> = vec![
            b"streaming round trip through the driver".to_vec(),
            (0..12000u32)
                .map(|i| (i.wrapping_mul(40503) >> 20) as u8)
                .collect(),
            b"abcabcabc".repeat(500),
        ];
        for data in &inputs {
            for level in [0u32, 1, 6, 9] {
                stream_roundtrip(&raw_deflate(data, level));
            }
        }
    }

    #[test]
    fn roundtrip_across_levels() {
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"hello hello hello world world world".to_vec(),
            (0..20000u32)
                .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
                .collect(),
            vec![0u8; 8000],
            (0..256u32).cycle().take(6000).map(|x| x as u8).collect(),
            b"The quick brown fox jumps over the lazy dog. ".repeat(300),
        ];
        for data in &inputs {
            for level in [0u32, 1, 3, 6, 9] {
                let compressed = raw_deflate(data, level);
                roundtrip(&compressed);
            }
        }
    }
}
