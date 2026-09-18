//! LSB-first bit reader/writer, ported from puffin `bit_reader.cc` /
//! `bit_writer.cc`. Deflate packs bits least-significant-first within each byte.

use crate::{Error, Result};

/// Reads bits from a byte buffer, LSB-first, exactly like `BufferBitReader`.
pub struct BitReader<'a> {
    buf: &'a [u8],
    index: usize,      // next byte to pull into the cache
    cache: u32,        // pending bits, LSB = next bit to read
    cache_bits: usize, // number of valid bits in `cache`
}

impl<'a> BitReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        BitReader {
            buf,
            index: 0,
            cache: 0,
            cache_bits: 0,
        }
    }

    /// Ensure at least `nbits` bits are cached. Max 32.
    pub fn cache_bits(&mut self, nbits: usize) -> bool {
        if (self.buf.len() - self.index) * 8 + self.cache_bits < nbits {
            return false;
        }
        if nbits > 32 {
            return false;
        }
        while self.cache_bits < nbits {
            self.cache |= (self.buf[self.index] as u32) << self.cache_bits;
            self.index += 1;
            self.cache_bits += 8;
        }
        true
    }

    /// Peek the low `nbits` cached bits (call `cache_bits` first).
    pub fn read_bits(&self, nbits: usize) -> u32 {
        if nbits == 0 {
            return 0;
        }
        if nbits >= 32 {
            return self.cache;
        }
        self.cache & ((1u32 << nbits) - 1)
    }

    pub fn drop_bits(&mut self, nbits: usize) {
        self.cache >>= nbits;
        self.cache_bits -= nbits;
    }

    pub fn read_boundary_bits(&self) -> u8 {
        (self.cache & ((1u32 << (self.cache_bits & 7)) - 1)) as u8
    }

    pub fn skip_boundary_bits(&mut self) -> usize {
        let nbits = self.cache_bits & 7;
        self.cache >>= nbits;
        self.cache_bits -= nbits;
        nbits
    }

    pub fn offset(&self) -> usize {
        self.index - self.cache_bits / 8
    }

    pub fn offset_in_bits(&self) -> u64 {
        (self.index as u64) * 8 - self.cache_bits as u64
    }

    pub fn bits_remaining(&self) -> u64 {
        ((self.buf.len() - self.index) as u64) * 8 + self.cache_bits as u64
    }

    /// Rewind the cache to the current byte boundary and read `count` raw bytes.
    /// Mirrors `GetByteReaderFn`: subsequent bit reads start on a byte boundary.
    pub fn get_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        self.index -= (self.cache_bits + 7) / 8;
        self.cache = 0;
        self.cache_bits = 0;
        if count > self.buf.len() - self.index {
            return Err(Error::Corrupt("get_bytes out of range".into()));
        }
        let slice = &self.buf[self.index..self.index + count];
        self.index += count;
        Ok(slice)
    }
}

/// Writes bits into a fixed-size byte buffer, LSB-first, like `BufferBitWriter`.
pub struct BitWriter<'a> {
    out: &'a mut [u8],
    index: usize,
    holder: u32,
    holder_bits: usize,
}

impl<'a> BitWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        BitWriter {
            out,
            index: 0,
            holder: 0,
            holder_bits: 0,
        }
    }

    pub fn write_bits(&mut self, mut nbits: usize, mut bits: u32) -> Result<()> {
        if ((self.out.len() - self.index) * 8).saturating_sub(self.holder_bits) < nbits {
            return Err(Error::Corrupt("bit writer overflow".into()));
        }
        if nbits > 32 {
            return Err(Error::Corrupt("write_bits > 32".into()));
        }
        while nbits > 0 {
            while self.holder_bits >= 8 {
                self.out[self.index] = (self.holder & 0xFF) as u8;
                self.index += 1;
                self.holder >>= 8;
                self.holder_bits -= 8;
            }
            while self.holder_bits < 24 && nbits > 0 {
                self.holder |= (bits & 0xFF) << self.holder_bits;
                let min = nbits.min(8);
                self.holder_bits += min;
                bits >>= min;
                nbits -= min;
            }
        }
        Ok(())
    }

    /// Write `data` verbatim; requires the writer to be on a byte boundary.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        if ((self.out.len() - self.index) * 8).saturating_sub(self.holder_bits) < data.len() * 8 {
            return Err(Error::Corrupt("bit writer byte overflow".into()));
        }
        if self.holder_bits % 8 != 0 {
            return Err(Error::Corrupt("write_bytes not byte aligned".into()));
        }
        self.flush()?;
        self.out[self.index..self.index + data.len()].copy_from_slice(data);
        self.index += data.len();
        Ok(())
    }

    pub fn write_boundary_bits(&mut self, bits: u8) -> Result<()> {
        self.write_bits((8 - (self.holder_bits & 7)) & 7, bits as u32)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.write_boundary_bits(0)?;
        while self.holder_bits > 0 {
            self.out[self.index] = (self.holder & 0xFF) as u8;
            self.index += 1;
            self.holder >>= 8;
            self.holder_bits -= 8;
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.index
    }
}
