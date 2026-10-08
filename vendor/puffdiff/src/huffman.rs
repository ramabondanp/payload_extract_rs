//! RFC1951 Huffman handling, ported from puffin `huffman_table.cc`.
//!
//! Builds canonical decode/encode tables and (de)serializes a dynamic Huffman
//! block header to/from the puff `block_metadata` blob. Byte-for-byte fidelity
//! with puffin is required.

use crate::bit_io::{BitReader, BitWriter};
use crate::{Error, Result};

pub const MAX_HUFFMAN_BITS: usize = 15;

const PERMUTATIONS: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub const LENGTH_BASES: [u16; 30] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0xFFFF,
];

pub const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

pub const DISTANCE_BASES: [u16; 31] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0xFFFF,
];

pub const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

#[derive(Clone, Copy)]
pub enum BlockType {
    Uncompressed,
    Fixed,
    Dynamic,
}

impl BlockType {
    pub fn from_bits(v: u8) -> Result<BlockType> {
        match v {
            0 => Ok(BlockType::Uncompressed),
            1 => Ok(BlockType::Fixed),
            2 => Ok(BlockType::Dynamic),
            _ => Err(Error::Corrupt("invalid block type".into())),
        }
    }
}

/// One (canonical code, alphabet index) pair used while building tables.
#[derive(Clone, Copy)]
struct CodeIndexPair {
    code: u16,
    index: u16,
}

/// Holds the current block's literal/length, distance and code-length tables.
pub struct HuffmanTable {
    lit_len_lens: Vec<u8>,
    lit_len_hcodes: Vec<u16>,
    lit_len_rcodes: Vec<u16>,
    lit_len_max_bits: usize,

    distance_lens: Vec<u8>,
    distance_hcodes: Vec<u16>,
    distance_rcodes: Vec<u16>,
    distance_max_bits: usize,

    code_lens: Vec<u8>,
    code_hcodes: Vec<u16>,
    code_rcodes: Vec<u16>,
    code_max_bits: usize,

    tmp_lens: Vec<u8>,
    pairs: Vec<CodeIndexPair>,
}

impl HuffmanTable {
    pub fn new() -> Self {
        HuffmanTable {
            lit_len_lens: Vec::new(),
            lit_len_hcodes: Vec::new(),
            lit_len_rcodes: Vec::new(),
            lit_len_max_bits: 0,
            distance_lens: Vec::new(),
            distance_hcodes: Vec::new(),
            distance_rcodes: Vec::new(),
            distance_max_bits: 0,
            code_lens: vec![0; 19],
            code_hcodes: Vec::new(),
            code_rcodes: Vec::new(),
            code_max_bits: 0,
            tmp_lens: Vec::new(),
            pairs: Vec::with_capacity(288),
        }
    }

    pub fn lit_len_max_bits(&self) -> usize {
        self.lit_len_max_bits
    }
    pub fn distance_max_bits(&self) -> usize {
        self.distance_max_bits
    }

    /// Decode lookup: map `bits` (max_bits wide) to a lit/len alphabet + code
    /// length. Returns `(alphabet, nbits)`.
    pub fn lit_len_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let hc = self.lit_len_hcodes[bits as usize];
        if hc & 0x8000 == 0 {
            return Err(Error::Corrupt("invalid lit/len code".into()));
        }
        let alphabet = hc & 0x7FFF;
        Ok((alphabet, self.lit_len_lens[alphabet as usize] as usize))
    }

    pub fn distance_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let hc = self.distance_hcodes[bits as usize];
        if hc & 0x8000 == 0 {
            return Err(Error::Corrupt("invalid distance code".into()));
        }
        let alphabet = hc & 0x7FFF;
        Ok((alphabet, self.distance_lens[alphabet as usize] as usize))
    }

    fn code_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let hc = self.code_hcodes[bits as usize];
        if hc & 0x8000 == 0 {
            return Err(Error::Corrupt("invalid code-length code".into()));
        }
        let alphabet = hc & 0x7FFF;
        Ok((alphabet, self.code_lens[alphabet as usize] as usize))
    }

    pub fn end_of_block_bit_length(&self) -> Result<usize> {
        if 256 >= self.lit_len_lens.len() {
            return Err(Error::Corrupt("no end-of-block symbol".into()));
        }
        Ok(self.lit_len_lens[256] as usize)
    }

    /// Encode lookup: alphabet -> (huffman code, nbits).
    pub fn lit_len_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        if (alphabet as usize) >= self.lit_len_lens.len() {
            return Err(Error::Corrupt("lit/len alphabet out of range".into()));
        }
        Ok((
            self.lit_len_rcodes[alphabet as usize],
            self.lit_len_lens[alphabet as usize] as usize,
        ))
    }

    pub fn distance_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        if (alphabet as usize) >= self.distance_lens.len() {
            return Err(Error::Corrupt("distance alphabet out of range".into()));
        }
        Ok((
            self.distance_rcodes[alphabet as usize],
            self.distance_lens[alphabet as usize] as usize,
        ))
    }

    fn code_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        if (alphabet as usize) >= self.code_lens.len() {
            return Err(Error::Corrupt("code alphabet out of range".into()));
        }
        Ok((
            self.code_rcodes[alphabet as usize],
            self.code_lens[alphabet as usize] as usize,
        ))
    }

    /// Compute canonical codes from an array of code lengths, filling `pairs`.
    /// Returns the max code length seen (0 if all lengths are zero).
    fn init_huffman_codes(&mut self, lens: &[u8]) -> Result<usize> {
        let mut len_count = [0u16; MAX_HUFFMAN_BITS + 1];
        for &l in lens {
            len_count[l as usize] += 1;
        }

        let mut max_bits = 0usize;
        for bits in (1..=MAX_HUFFMAN_BITS).rev() {
            if len_count[bits] != 0 {
                max_bits = bits;
                break;
            }
        }

        for idx in 1..=max_bits {
            if len_count[idx] as usize > (1 << idx) {
                return Err(Error::Corrupt("oversubscribed code lengths".into()));
            }
        }

        let mut code = 0u16;
        len_count[0] = 0;
        let mut next_code = [0u16; MAX_HUFFMAN_BITS + 1];
        for bits in 1..=MAX_HUFFMAN_BITS {
            code = (code + len_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        self.pairs.clear();
        for (idx, &len_u8) in lens.iter().enumerate() {
            let len = len_u8 as usize;
            if len == 0 {
                continue;
            }
            // Bit-reverse the canonical code (deflate reads codes MSB-first).
            let mut rev = 0u16;
            let mut tmp = next_code[len];
            for _ in 0..len {
                rev <<= 1;
                rev |= tmp & 1;
                tmp >>= 1;
            }
            self.pairs.push(CodeIndexPair {
                code: rev,
                index: idx as u16,
            });
            next_code[len] += 1;
        }
        Ok(max_bits)
    }

    fn build_huffman_codes(
        lens: &[u8],
        pairs: &mut [CodeIndexPair],
        hcodes: &mut Vec<u16>,
        max_bits: usize,
    ) {
        // Sort descending by code length so shorter codes fill the don't-care
        // slots without overwriting exact matches.
        pairs.sort_by(|a, b| lens[b.index as usize].cmp(&lens[a.index as usize]));
        hcodes.clear();
        hcodes.resize(1 << max_bits, 0);
        for cip in pairs.iter() {
            hcodes[cip.code as usize] = cip.index | 0x8000;
            let code_len = lens[cip.index as usize] as usize;
            let fill_bits = max_bits - code_len;
            for idx in 1..(1usize << fill_bits) {
                let location = (idx << code_len) | cip.code as usize;
                if hcodes[location] & 0x8000 == 0 {
                    hcodes[location] = cip.index | 0x8000;
                }
            }
        }
    }

    fn build_huffman_reverse_codes(
        lens: &[u8],
        pairs: &mut [CodeIndexPair],
        rcodes: &mut Vec<u16>,
    ) {
        pairs.sort_by(|a, b| a.index.cmp(&b.index));
        rcodes.clear();
        rcodes.resize(lens.len(), 0);
        let mut i = 0usize;
        for (idx, slot) in rcodes.iter_mut().enumerate() {
            if i < pairs.len() && idx == pairs[i].index as usize {
                *slot = pairs[i].code;
                i += 1;
            } else {
                *slot = 0;
            }
        }
    }

    pub fn build_fixed(&mut self) -> Result<()> {
        self.lit_len_lens.clear();
        self.lit_len_lens.resize(288, 0);
        let mut i = 0;
        while i < 144 {
            self.lit_len_lens[i] = 8;
            i += 1;
        }
        while i < 256 {
            self.lit_len_lens[i] = 9;
            i += 1;
        }
        while i < 280 {
            self.lit_len_lens[i] = 7;
            i += 1;
        }
        while i < 288 {
            self.lit_len_lens[i] = 8;
            i += 1;
        }
        self.distance_lens.clear();
        self.distance_lens.resize(30, 5);

        let mut pairs;
        {
            self.lit_len_max_bits = self.init_huffman_codes(&self.lit_len_lens.clone())?;
            pairs = std::mem::take(&mut self.pairs);
            Self::build_huffman_codes(
                &self.lit_len_lens,
                &mut pairs,
                &mut self.lit_len_hcodes,
                self.lit_len_max_bits,
            );
            self.pairs = pairs;
        }
        {
            self.distance_max_bits = self.init_huffman_codes(&self.distance_lens.clone())?;
            pairs = std::mem::take(&mut self.pairs);
            Self::build_huffman_codes(
                &self.distance_lens,
                &mut pairs,
                &mut self.distance_hcodes,
                self.distance_max_bits,
            );
            self.pairs = pairs;
        }
        // reverse codes for the encode direction
        {
            let _ = self.init_huffman_codes(&self.lit_len_lens.clone())?;
            pairs = std::mem::take(&mut self.pairs);
            Self::build_huffman_reverse_codes(
                &self.lit_len_lens,
                &mut pairs,
                &mut self.lit_len_rcodes,
            );
            self.pairs = pairs;
        }
        {
            let _ = self.init_huffman_codes(&self.distance_lens.clone())?;
            pairs = std::mem::take(&mut self.pairs);
            Self::build_huffman_reverse_codes(
                &self.distance_lens,
                &mut pairs,
                &mut self.distance_rcodes,
            );
            self.pairs = pairs;
        }
        Ok(())
    }

    fn check_array_lengths(
        num_lit_len: usize,
        num_distance: usize,
        num_codes: usize,
    ) -> Result<()> {
        if num_lit_len > 286 || num_distance > 30 || num_codes > 19 {
            return Err(Error::Corrupt(
                "dynamic huffman array lengths invalid".into(),
            ));
        }
        Ok(())
    }

    /// Read a dynamic Huffman block header from the deflate stream `br`, writing
    /// its puff encoding into `buffer`. Returns bytes written to `buffer`.
    pub fn build_dynamic_from_deflate(
        &mut self,
        br: &mut BitReader,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if buffer.len() < 3 {
            return Err(Error::Corrupt("metadata buffer too small".into()));
        }
        let mut index = 0usize;
        if !br.cache_bits(14) {
            return Err(Error::Corrupt("eof reading dynamic header".into()));
        }
        buffer[index] = br.read_bits(5) as u8;
        let num_lit_len = br.read_bits(5) as usize + 257;
        br.drop_bits(5);
        index += 1;

        buffer[index] = br.read_bits(5) as u8;
        let num_distance = br.read_bits(5) as usize + 1;
        br.drop_bits(5);
        index += 1;

        buffer[index] = br.read_bits(4) as u8;
        let num_codes = br.read_bits(4) as usize + 4;
        br.drop_bits(4);
        index += 1;

        Self::check_array_lengths(num_lit_len, num_distance, num_codes)?;

        let mut checked = false;
        if buffer.len() - index < (num_codes + 1) / 2 {
            return Err(Error::Corrupt("metadata buffer too small for codes".into()));
        }
        let mut idx = 0usize;
        while idx < num_codes {
            if !br.cache_bits(3) {
                return Err(Error::Corrupt("eof reading code lengths".into()));
            }
            self.code_lens[PERMUTATIONS[idx] as usize] = br.read_bits(3) as u8;
            if checked {
                buffer[index] |= br.read_bits(3) as u8;
                index += 1;
            } else {
                buffer[index] = (br.read_bits(3) as u8) << 4;
            }
            checked = !checked;
            br.drop_bits(3);
            idx += 1;
        }
        if checked {
            index += 1;
        }
        while idx < 19 {
            self.code_lens[PERMUTATIONS[idx] as usize] = 0;
            idx += 1;
        }

        self.code_max_bits = self.init_huffman_codes(&self.code_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_codes(
            &self.code_lens,
            &mut pairs,
            &mut self.code_hcodes,
            self.code_max_bits,
        );
        self.pairs = pairs;

        // Read the lit/len + distance code-length arrays (RLE-coded).
        let written = self.read_code_lengths_from_deflate(
            br,
            &mut buffer[index..],
            self.code_max_bits,
            num_lit_len + num_distance,
        )?;
        index += written;

        let tmp = std::mem::take(&mut self.tmp_lens);
        self.lit_len_lens.clear();
        self.lit_len_lens.extend_from_slice(&tmp[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens.extend_from_slice(&tmp[num_lit_len..]);
        self.tmp_lens = tmp;

        self.lit_len_max_bits = self.init_huffman_codes(&self.lit_len_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_codes(
            &self.lit_len_lens,
            &mut pairs,
            &mut self.lit_len_hcodes,
            self.lit_len_max_bits,
        );
        self.pairs = pairs;

        self.distance_max_bits = self.init_huffman_codes(&self.distance_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_codes(
            &self.distance_lens,
            &mut pairs,
            &mut self.distance_hcodes,
            self.distance_max_bits,
        );
        self.pairs = pairs;

        Ok(index)
    }

    fn read_code_lengths_from_deflate(
        &mut self,
        br: &mut BitReader,
        buffer: &mut [u8],
        max_bits: usize,
        num_codes: usize,
    ) -> Result<usize> {
        let mut index = 0usize;
        let mut lens: Vec<u8> = Vec::with_capacity(num_codes);
        let mut idx = 0usize;
        while idx < num_codes {
            if !br.cache_bits(max_bits) {
                return Err(Error::Corrupt("eof reading code length codes".into()));
            }
            let bits = br.read_bits(max_bits);
            let (code, nbits) = self.code_alphabet(bits)?;
            if index >= buffer.len() {
                return Err(Error::Corrupt("code length buffer overflow".into()));
            }
            br.drop_bits(nbits);
            if code < 16 {
                buffer[index] = code as u8;
                index += 1;
                lens.push(code as u8);
                idx += 1;
            } else {
                if code >= 19 {
                    return Err(Error::Corrupt("invalid code-length code".into()));
                }
                let (copy_num, copy_val) = match code {
                    16 => {
                        if idx == 0 {
                            return Err(Error::Corrupt("repeat with no previous length".into()));
                        }
                        if !br.cache_bits(2) {
                            return Err(Error::Corrupt("eof reading repeat".into()));
                        }
                        let n = 3 + br.read_bits(2) as usize;
                        buffer[index] = 16 + br.read_bits(2) as u8;
                        index += 1;
                        let v = lens[idx - 1];
                        br.drop_bits(2);
                        (n, v)
                    }
                    17 => {
                        if !br.cache_bits(3) {
                            return Err(Error::Corrupt("eof reading repeat".into()));
                        }
                        let n = 3 + br.read_bits(3) as usize;
                        buffer[index] = 20 + br.read_bits(3) as u8;
                        index += 1;
                        br.drop_bits(3);
                        (n, 0)
                    }
                    18 => {
                        if !br.cache_bits(7) {
                            return Err(Error::Corrupt("eof reading repeat".into()));
                        }
                        let n = 11 + br.read_bits(7) as usize;
                        buffer[index] = 28 + br.read_bits(7) as u8;
                        index += 1;
                        br.drop_bits(7);
                        (n, 0)
                    }
                    _ => unreachable!(),
                };
                idx += copy_num;
                for _ in 0..copy_num {
                    lens.push(copy_val);
                }
            }
        }
        if lens.len() != num_codes {
            return Err(Error::Corrupt("code length count mismatch".into()));
        }
        self.tmp_lens = lens;
        Ok(index)
    }

    /// Write a dynamic Huffman block header into the deflate stream `bw` from
    /// its puff encoding in `buffer`.
    pub fn build_dynamic_from_puff(&mut self, buffer: &[u8], bw: &mut BitWriter) -> Result<()> {
        if buffer.len() < 3 {
            return Err(Error::Corrupt("metadata buffer too small".into()));
        }
        let mut index = 0usize;
        let num_lit_len = buffer[index] as usize + 257;
        bw.write_bits(5, buffer[index] as u32)?;
        index += 1;

        let num_distance = buffer[index] as usize + 1;
        bw.write_bits(5, buffer[index] as u32)?;
        index += 1;

        let num_codes = buffer[index] as usize + 4;
        bw.write_bits(4, buffer[index] as u32)?;
        index += 1;

        Self::check_array_lengths(num_lit_len, num_distance, num_codes)?;

        if buffer.len() - index < (num_codes + 1) / 2 {
            return Err(Error::Corrupt("metadata truncated".into()));
        }
        let mut checked = false;
        let mut idx = 0usize;
        while idx < num_codes {
            let len = if checked {
                let v = buffer[index] & 0x0F;
                index += 1;
                v
            } else {
                buffer[index] >> 4
            };
            checked = !checked;
            self.code_lens[PERMUTATIONS[idx] as usize] = len;
            bw.write_bits(3, len as u32)?;
            idx += 1;
        }
        if checked {
            index += 1;
        }
        while idx < 19 {
            self.code_lens[PERMUTATIONS[idx] as usize] = 0;
            idx += 1;
        }

        let _ = self.init_huffman_codes(&self.code_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_reverse_codes(&self.code_lens, &mut pairs, &mut self.code_rcodes);
        self.pairs = pairs;

        let read =
            self.write_code_lengths_to_deflate(&buffer[index..], bw, num_lit_len + num_distance)?;
        index += read;

        let tmp = std::mem::take(&mut self.tmp_lens);
        self.lit_len_lens.clear();
        self.lit_len_lens.extend_from_slice(&tmp[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens.extend_from_slice(&tmp[num_lit_len..]);
        self.tmp_lens = tmp;

        let _ = self.init_huffman_codes(&self.lit_len_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_reverse_codes(&self.lit_len_lens, &mut pairs, &mut self.lit_len_rcodes);
        self.pairs = pairs;
        // lit_len_max_bits is unused when encoding, but keep it consistent.
        self.lit_len_max_bits = self.init_huffman_codes(&self.lit_len_lens.clone())?;
        self.pairs.clear();

        let _ = self.init_huffman_codes(&self.distance_lens.clone())?;
        let mut pairs = std::mem::take(&mut self.pairs);
        Self::build_huffman_reverse_codes(
            &self.distance_lens,
            &mut pairs,
            &mut self.distance_rcodes,
        );
        self.pairs = pairs;

        if index != buffer.len() {
            return Err(Error::Corrupt("metadata length mismatch".into()));
        }
        Ok(())
    }

    fn write_code_lengths_to_deflate(
        &mut self,
        buffer: &[u8],
        bw: &mut BitWriter,
        num_codes: usize,
    ) -> Result<usize> {
        let mut lens: Vec<u8> = Vec::with_capacity(num_codes);
        let mut index = 0usize;
        let mut idx = 0usize;
        while idx < num_codes {
            if index >= buffer.len() {
                return Err(Error::Corrupt("code length buffer underflow".into()));
            }
            let pcode = buffer[index];
            index += 1;
            if pcode > 155 {
                return Err(Error::Corrupt("invalid puffed code length".into()));
            }
            let code: u16 = if pcode < 16 {
                pcode as u16
            } else if pcode < 20 {
                16
            } else if pcode < 28 {
                17
            } else {
                18
            };
            let (hcode, nbits) = self.code_huffman(code)?;
            bw.write_bits(nbits, hcode as u32)?;
            if code < 16 {
                lens.push(code as u8);
                idx += 1;
            } else {
                let (copy_num, copy_val) = match code {
                    16 => {
                        if idx == 0 {
                            return Err(Error::Corrupt("repeat with no previous length".into()));
                        }
                        bw.write_bits(2, (pcode - 16) as u32)?;
                        (3 + (pcode - 16) as usize, lens[idx - 1])
                    }
                    17 => {
                        bw.write_bits(3, (pcode - 20) as u32)?;
                        (3 + (pcode - 20) as usize, 0)
                    }
                    18 => {
                        bw.write_bits(7, (pcode - 28) as u32)?;
                        (11 + (pcode - 28) as usize, 0)
                    }
                    _ => unreachable!(),
                };
                idx += copy_num;
                for _ in 0..copy_num {
                    lens.push(copy_val);
                }
            }
        }
        if lens.len() != num_codes {
            return Err(Error::Corrupt("code length count mismatch".into()));
        }
        self.tmp_lens = lens;
        Ok(index)
    }
}
