//! Deflate -> puff transform, ported from puffin `puffer.cc`.

use crate::bit_io::BitReader;
use crate::huffman::{
    BlockType, HuffmanTable, DISTANCE_BASES, DISTANCE_EXTRA_BITS, LENGTH_BASES, LENGTH_EXTRA_BITS,
};
use crate::puff_io::{PuffData, PuffWriter, BLOCK_METADATA_MAX};
use crate::{BitExtent, Error, Result};

/// Puff every deflate block in `br` into `pw`, until the input is exhausted.
pub fn puff_deflate(br: &mut BitReader, pw: &mut PuffWriter) -> Result<()> {
    puff_deflate_impl(br, pw, None)
}

/// Puff and additionally record the bit-extent of each compressed sub-block,
/// stopping after the final block. Mirrors puffin's `deflates != nullptr` path;
/// used to derive patch metadata. Uncompressed blocks are not recorded.
pub fn puff_deflate_record(
    br: &mut BitReader,
    pw: &mut PuffWriter,
    deflates: &mut Vec<BitExtent>,
) -> Result<()> {
    puff_deflate_impl(br, pw, Some(deflates))
}

fn puff_deflate_impl(
    br: &mut BitReader,
    pw: &mut PuffWriter,
    mut deflates: Option<&mut Vec<BitExtent>>,
) -> Result<()> {
    let mut fixed_ht = HuffmanTable::new();
    let mut dyn_ht = HuffmanTable::new();
    let mut fixed_built = false;
    let mut end_loop = false;

    // Minimum deflate block is 8 bits (3-bit header + a 5-bit fixed symbol).
    while !end_loop && br.cache_bits(8) {
        let start_bit_offset = br.offset_in_bits();
        if !br.cache_bits(3) {
            return Err(Error::Corrupt("eof reading block header".into()));
        }
        let final_bit = br.read_bits(1) as u8;
        br.drop_bits(1);
        let btype = br.read_bits(2) as u8;
        br.drop_bits(2);

        // When recording deflate locations, stop after the final block.
        if deflates.is_some() && final_bit != 0 {
            end_loop = true;
        }

        let block_header = (final_bit << 7) | (btype << 5);

        let mut include_deflate = true;
        let use_dynamic;
        match BlockType::from_bits(btype)? {
            BlockType::Uncompressed => {
                let skipped_bits = br.read_boundary_bits();
                br.skip_boundary_bits();
                if !br.cache_bits(32) {
                    return Err(Error::Corrupt("eof reading uncompressed lengths".into()));
                }
                let len = br.read_bits(16);
                br.drop_bits(16);
                let nlen = br.read_bits(16);
                br.drop_bits(16);
                if (len ^ nlen) != 0xFFFF {
                    return Err(Error::Corrupt("bad uncompressed LEN/NLEN".into()));
                }

                let header = block_header | skipped_bits;
                pw.insert(&PuffData::BlockMetadata(&[header]))?;

                let raw = br.get_bytes(len as usize)?;
                pw.insert(&PuffData::Literals(raw))?;
                pw.insert(&PuffData::EndOfBlock)?;
                continue;
            }
            BlockType::Fixed => {
                if !fixed_built {
                    fixed_ht.build_fixed()?;
                    fixed_built = true;
                }
                pw.insert(&PuffData::BlockMetadata(&[block_header]))?;
                use_dynamic = false;
            }
            BlockType::Dynamic => {
                let mut meta = [0u8; BLOCK_METADATA_MAX];
                meta[0] = block_header;
                let written = dyn_ht.build_dynamic_from_deflate(br, &mut meta[1..])?;
                pw.insert(&PuffData::BlockMetadata(&meta[..written + 1]))?;
                use_dynamic = true;
            }
        }

        loop {
            let cur_ht: &HuffmanTable = if use_dynamic { &dyn_ht } else { &fixed_ht };
            let mut max_bits = cur_ht.lit_len_max_bits();
            if !br.cache_bits(max_bits) {
                max_bits = cur_ht.end_of_block_bit_length()?;
            }
            if !br.cache_bits(max_bits) {
                return Err(Error::Corrupt("eof reading lit/len".into()));
            }
            let bits = br.read_bits(max_bits);
            let (lit_len_alphabet, nbits) = cur_ht.lit_len_alphabet(bits)?;
            br.drop_bits(nbits);

            if lit_len_alphabet < 256 {
                pw.insert(&PuffData::Literal(lit_len_alphabet as u8))?;
            } else if lit_len_alphabet == 256 {
                pw.insert(&PuffData::EndOfBlock)?;
                if let Some(v) = deflates.as_mut() {
                    if include_deflate {
                        v.push(BitExtent {
                            offset: start_bit_offset,
                            length: br.offset_in_bits() - start_bit_offset,
                        });
                    }
                }
                break;
            } else {
                if lit_len_alphabet > 285 {
                    return Err(Error::Corrupt("lit/len alphabet > 285".into()));
                }
                let len_code_start = (lit_len_alphabet - 257) as usize;
                let extra_len = LENGTH_EXTRA_BITS[len_code_start] as usize;
                let mut extra_val = 0u32;
                if extra_len != 0 {
                    if !br.cache_bits(extra_len) {
                        return Err(Error::Corrupt("eof reading length extra".into()));
                    }
                    extra_val = br.read_bits(extra_len);
                    br.drop_bits(extra_len);
                }
                let length = LENGTH_BASES[len_code_start] as usize + extra_val as usize;

                let mut bits_to_cache = cur_ht.distance_max_bits();
                if !br.cache_bits(bits_to_cache) {
                    // Rare legacy corner case (crbug.com/915559): not enough
                    // bits for a full-width distance code near the stream end.
                    bits_to_cache = br.bits_remaining() as usize;
                    if !br.cache_bits(bits_to_cache) {
                        return Err(Error::Corrupt("eof reading distance".into()));
                    }
                    // Legacy corner case: exclude this deflate from recording.
                    include_deflate = false;
                }
                let dbits = br.read_bits(bits_to_cache);
                let (distance_alphabet, nbits) = cur_ht.distance_alphabet(dbits)?;
                br.drop_bits(nbits);

                let extra_len = DISTANCE_EXTRA_BITS[distance_alphabet as usize] as usize;
                let mut extra_val = 0u32;
                if extra_len != 0 {
                    if !br.cache_bits(extra_len) {
                        return Err(Error::Corrupt("eof reading distance extra".into()));
                    }
                    extra_val = br.read_bits(extra_len);
                    br.drop_bits(extra_len);
                }
                let distance =
                    DISTANCE_BASES[distance_alphabet as usize] as usize + extra_val as usize;
                pw.insert(&PuffData::LenDist { length, distance })?;
            }
        }
    }
    pw.flush()?;
    Ok(())
}
