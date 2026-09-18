//! Whole-buffer puff/huff driver, ported from puffin `puffin_stream.cc`.
//!
//! Puffin's `PuffinStream` is a random-access stream that interleaves raw
//! (non-deflate) bytes with puffed deflate regions, handling deflate streams
//! that do not start/end on byte boundaries. We only ever need the whole-buffer
//! case, so this drives a single `Read` (puff) or `Write` (huff) over the full
//! range. The LRU disk cache is omitted (equivalent to `max_cache_size == 0`).

use crate::bit_io::{BitReader, BitWriter};
use crate::huffer::huff_deflate;
use crate::puff_io::{PuffReader, PuffWriter};
use crate::puffer::puff_deflate;
use crate::{BitExtent, ByteExtent, Error, Result};

#[derive(Clone, Copy)]
struct Extent {
    offset: u64,
    length: u64,
}

struct MemStream {
    buf: Vec<u8>,
    pos: usize,
}

impl MemStream {
    fn seek(&mut self, pos: u64) {
        self.pos = pos as usize;
    }

    fn read_into(&mut self, dst: &mut [u8]) -> Result<()> {
        if self.pos + dst.len() > self.buf.len() {
            return Err(Error::Corrupt("read past end of stream".into()));
        }
        dst.copy_from_slice(&self.buf[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }

    fn write(&mut self, src: &[u8]) {
        let end = self.pos + src.len();
        if end > self.buf.len() {
            self.buf.resize(end, 0);
        }
        self.buf[self.pos..end].copy_from_slice(src);
        self.pos = end;
    }
}

struct Driver {
    stream: MemStream,
    deflates: Vec<Extent>, // bits, with sentinel appended
    puffs: Vec<Extent>,    // bytes, with sentinel appended
    upper_bounds: Vec<u64>,
    cur_puff: usize,
    cur_deflate: usize,
    puff_pos: u64,
    skip_bytes: u64,
    deflate_bit_pos: u64,
    last_byte: u32,
    extra_byte: u64,
    max_puff_length: u64,
}

fn check_args(puff_size: u64, deflates: &[Extent], puffs: &[Extent]) -> Result<()> {
    if puffs.len() != deflates.len() {
        return Err(Error::Corrupt("deflates/puffs count mismatch".into()));
    }
    if let Some(last) = puffs.last() {
        if puff_size < last.offset + last.length {
            return Err(Error::Corrupt("puff_size smaller than last puff".into()));
        }
    }
    let overlaps = |v: &[Extent]| {
        v.windows(2)
            .any(|w| w[0].offset + w[0].length > w[1].offset)
    };
    if overlaps(deflates) || overlaps(puffs) {
        return Err(Error::Corrupt("overlapping extents".into()));
    }
    Ok(())
}

impl Driver {
    fn new(
        stream_buf: Vec<u8>,
        puff_size: u64,
        deflates_in: &[Extent],
        puffs_in: &[Extent],
    ) -> Result<Self> {
        check_args(puff_size, deflates_in, puffs_in)?;

        let mut upper_bounds = Vec::with_capacity(puffs_in.len() + 1);
        for p in puffs_in {
            upper_bounds.push(p.offset + p.length);
        }
        upper_bounds.push(puff_size + 1);

        let mut deflate_stream_size = puff_size;
        if let (Some(dl), Some(pl)) = (deflates_in.last(), puffs_in.last()) {
            deflate_stream_size = (dl.offset + dl.length) / 8 + puff_size - (pl.offset + pl.length);
        }

        let mut deflates: Vec<Extent> = deflates_in.to_vec();
        let mut puffs: Vec<Extent> = puffs_in.to_vec();
        deflates.push(Extent {
            offset: deflate_stream_size * 8,
            length: 0,
        });
        puffs.push(Extent {
            offset: puff_size,
            length: 0,
        });

        let max_puff_length = puffs_in.iter().map(|p| p.length).max().unwrap_or(0);

        Ok(Driver {
            stream: MemStream {
                buf: stream_buf,
                pos: 0,
            },
            deflates,
            puffs,
            upper_bounds,
            cur_puff: 0,
            cur_deflate: 0,
            puff_pos: 0,
            skip_bytes: 0,
            deflate_bit_pos: 0,
            last_byte: 0,
            extra_byte: 0,
            max_puff_length,
        })
    }

    fn seek_to_zero(&mut self, is_for_puff: bool) -> Result<()> {
        let offset = 0u64;
        // first upper bound strictly greater than offset
        let idx = self
            .upper_bounds
            .iter()
            .position(|&b| b > offset)
            .ok_or_else(|| Error::Corrupt("seek out of range".into()))?;
        self.cur_puff = idx;
        self.cur_deflate = idx;

        if offset < self.puffs[self.cur_puff].offset {
            self.puff_pos = offset;
            let back_track = self.puffs[self.cur_puff].offset - self.puff_pos;
            self.deflate_bit_pos =
                ((self.deflates[self.cur_deflate].offset + 7) / 8 - back_track) * 8;
            if self.cur_puff != 0 {
                let prev = self.deflates[self.cur_deflate - 1];
                if self.deflate_bit_pos < prev.offset + prev.length {
                    self.deflate_bit_pos = prev.offset + prev.length;
                }
            }
        } else {
            self.puff_pos = self.puffs[self.cur_puff].offset;
            self.deflate_bit_pos = self.deflates[self.cur_deflate].offset;
        }
        self.skip_bytes = offset - self.puff_pos;
        if !is_for_puff {
            self.stream.seek(0);
            self.set_extra_byte()?;
        }
        Ok(())
    }

    fn set_extra_byte(&mut self) -> Result<()> {
        if self.cur_deflate >= self.deflates.len() {
            return Err(Error::Corrupt("set_extra_byte past end".into()));
        }
        if self.cur_deflate + 1 == self.deflates.len() {
            self.extra_byte = 0;
            return Ok(());
        }
        let d = self.deflates[self.cur_deflate];
        let end_bit = d.offset + d.length;
        let next = self.deflates[self.cur_deflate + 1];
        if (end_bit & 7) != 0 && ((end_bit + 7) & !7u64) <= next.offset {
            self.extra_byte = 1;
        } else {
            self.extra_byte = 0;
        }
        Ok(())
    }

    /// Puff: read the whole puff stream into `out`.
    fn run_puff(&mut self, out: &mut [u8]) -> Result<()> {
        let length = out.len();
        let mut bytes_read = 0usize;
        while bytes_read < length {
            if self.puff_pos < self.puffs[self.cur_puff].offset {
                // Raw region between deflates.
                let start_byte = self.deflate_bit_pos / 8;
                let end_byte = (self.deflates[self.cur_deflate].offset + 7) / 8;
                let bytes_to_read =
                    ((length - bytes_read) as u64).min(end_byte - start_byte) as usize;
                if bytes_to_read < 1 {
                    return Err(Error::Corrupt("raw region zero read".into()));
                }
                self.stream.seek(start_byte);
                self.stream
                    .read_into(&mut out[bytes_read..bytes_read + bytes_to_read])?;

                let deflate_off = self.deflates[self.cur_deflate].offset;
                if (start_byte + bytes_to_read as u64) * 8 > deflate_off {
                    let mask = ((1u32 << (deflate_off & 7)) - 1) as u8;
                    out[bytes_read + bytes_to_read - 1] &= mask;
                }
                if start_byte * 8 < self.deflate_bit_pos {
                    out[bytes_read] >>= self.deflate_bit_pos & 7;
                }

                self.deflate_bit_pos -= self.deflate_bit_pos & 7;
                self.deflate_bit_pos += bytes_to_read as u64 * 8;
                if self.deflate_bit_pos > deflate_off {
                    self.deflate_bit_pos = deflate_off;
                }

                bytes_read += bytes_to_read;
                self.puff_pos += bytes_to_read as u64;
                if self.puff_pos > self.puffs[self.cur_puff].offset {
                    return Err(Error::Corrupt("raw region overran puff".into()));
                }
            } else {
                // Deflate region: puff it.
                let d = self.deflates[self.cur_deflate];
                let p = self.puffs[self.cur_puff];
                let start_byte = d.offset / 8;
                let end_byte = (d.offset + d.length + 7) / 8;
                let bytes_to_read = (end_byte - start_byte) as usize;

                let puff_directly =
                    self.skip_bytes == 0 && (length - bytes_read) as u64 >= p.length;

                let mut deflate_buf = vec![0u8; bytes_to_read];
                self.stream.seek(start_byte);
                self.stream.read_into(&mut deflate_buf)?;
                let extra_bits_len = (d.offset & 7) as usize;

                let mut pbuf;
                if puff_directly {
                    let target = &mut out[bytes_read..bytes_read + p.length as usize];
                    let mut br = BitReader::new(&deflate_buf);
                    br.cache_bits(extra_bits_len);
                    br.drop_bits(extra_bits_len);
                    let mut pw = PuffWriter::new(target);
                    if let Err(e) = puff_deflate(&mut br, &mut pw) {
                        eprintln!(
                            "puff_directly failed: deflate idx={}, offset={}, length={}, p.length={}, extra_bits={}, bytes_to_read={}, br.offset={}, pw.size={}, err={e}",
                            self.cur_deflate, d.offset, d.length, p.length, extra_bits_len, bytes_to_read, br.offset(), pw.size(),
                        );
                        return Err(e);
                    }
                    if br.offset() != bytes_to_read || pw.size() as u64 != p.length {
                        eprintln!(
                            "puff_directly size mismatch: br.offset()={}, bytes_to_read={}, pw.size()={}, p.length={}",
                            br.offset(), bytes_to_read, pw.size(), p.length
                        );
                        return Err(Error::Corrupt("puff size mismatch".into()));
                    }
                } else {
                    pbuf = vec![0u8; p.length as usize];
                    let mut br = BitReader::new(&deflate_buf);
                    br.cache_bits(extra_bits_len);
                    br.drop_bits(extra_bits_len);
                    let mut pw = PuffWriter::new(&mut pbuf);
                    if let Err(e) = puff_deflate(&mut br, &mut pw) {
                        eprintln!(
                            "puff indirect failed: deflate idx={}, offset={}, length={}, p.length={}, extra_bits={}, bytes_to_read={}, br.offset={}, pw.size={}, err={e}",
                            self.cur_deflate, d.offset, d.length, p.length, extra_bits_len, bytes_to_read, br.offset(), pw.size(),
                        );
                        return Err(e);
                    }
                    if br.offset() != bytes_to_read || pw.size() as u64 != p.length {
                        eprintln!(
                            "puff indirect size mismatch: br.offset()={}, bytes_to_read={}, pw.size()={}, p.length={}",
                            br.offset(), bytes_to_read, pw.size(), p.length
                        );
                        return Err(Error::Corrupt("puff size mismatch".into()));
                    }
                    let bytes_to_copy =
                        ((length - bytes_read) as u64).min(p.length - self.skip_bytes) as usize;
                    out[bytes_read..bytes_read + bytes_to_copy].copy_from_slice(
                        &pbuf[self.skip_bytes as usize..self.skip_bytes as usize + bytes_to_copy],
                    );
                }

                let bytes_to_copy =
                    ((length - bytes_read) as u64).min(p.length - self.skip_bytes) as usize;
                self.skip_bytes += bytes_to_copy as u64;
                bytes_read += bytes_to_copy;

                if self.puff_pos + self.skip_bytes == p.offset + p.length {
                    self.puff_pos += self.skip_bytes;
                    self.skip_bytes = 0;
                    self.deflate_bit_pos = d.offset + d.length;
                    self.cur_puff += 1;
                    self.cur_deflate += 1;
                    if self.cur_puff == self.puffs.len() {
                        break;
                    }
                }
            }
        }
        if bytes_read != length {
            return Err(Error::Corrupt("puff did not fill output".into()));
        }
        Ok(())
    }

    /// Huff: write the whole puff stream `input` back to deflate, into `stream`.
    fn run_huff(&mut self, input: &[u8]) -> Result<()> {
        let length = input.len();
        let mut puff_buffer = vec![0u8; self.max_puff_length as usize + 1];
        let mut bytes_wrote = 0usize;
        while bytes_wrote < length {
            let d = self.deflates[self.cur_deflate];
            let p = self.puffs[self.cur_puff];
            if self.deflate_bit_pos < (d.offset & !7u64) {
                // Byte-aligned raw region: pass bytes through unchanged.
                if self.deflate_bit_pos & 7 != 0 {
                    return Err(Error::Corrupt("raw write not byte aligned".into()));
                }
                let copy_len = ((d.offset / 8) - (self.deflate_bit_pos / 8))
                    .min((length - bytes_wrote) as u64) as usize;
                self.stream
                    .write(&input[bytes_wrote..bytes_wrote + copy_len]);
                bytes_wrote += copy_len;
                self.puff_pos += copy_len as u64;
                self.deflate_bit_pos += copy_len as u64 * 8;
            } else {
                if self.deflate_bit_pos < d.offset {
                    self.last_byte |= (input[bytes_wrote] as u32) << (self.deflate_bit_pos & 7);
                    bytes_wrote += 1;
                    self.skip_bytes = 0;
                    self.deflate_bit_pos = d.offset;
                    self.puff_pos += 1;
                    if self.puff_pos != p.offset {
                        return Err(Error::Corrupt("puff position mismatch".into()));
                    }
                }

                let copy_len = ((length - bytes_wrote) as u64)
                    .min(p.length + self.extra_byte - self.skip_bytes)
                    as usize;
                if puff_buffer.len() < self.skip_bytes as usize + copy_len {
                    return Err(Error::Corrupt("puff buffer overflow".into()));
                }
                puff_buffer[self.skip_bytes as usize..self.skip_bytes as usize + copy_len]
                    .copy_from_slice(&input[bytes_wrote..bytes_wrote + copy_len]);
                self.skip_bytes += copy_len as u64;
                bytes_wrote += copy_len;

                if self.skip_bytes == p.length + self.extra_byte {
                    let start_byte = d.offset / 8;
                    let end_byte = (d.offset + d.length + 7) / 8;
                    let mut bytes_to_write = (end_byte - start_byte) as usize;

                    let mut deflate_buf = vec![0u8; bytes_to_write];
                    {
                        let mut bw = BitWriter::new(&mut deflate_buf);
                        bw.write_bits((d.offset & 7) as usize, self.last_byte)?;
                        self.last_byte = 0;
                        let mut pr = PuffReader::new(&puff_buffer[..p.length as usize]);
                        if let Err(e) = huff_deflate(&mut pr, &mut bw) {
                            eprintln!(
                                "huff_deflate failed: deflate idx={}, offset={}, length={}, p.length={}, err={e}",
                                self.cur_deflate, d.offset, d.length, p.length
                            );
                            return Err(e);
                        }
                        if bw.size() != bytes_to_write {
                            eprintln!(
                                "huff deflate size mismatch: bw.size()={}, bytes_to_write={}",
                                bw.size(), bytes_to_write
                            );
                            return Err(Error::Corrupt("huff deflate size mismatch".into()));
                        }
                        if pr.bytes_left() != 0 {
                            eprintln!(
                                "huff left puff bytes: left={}",
                                pr.bytes_left()
                            );
                            return Err(Error::Corrupt("huff left puff bytes".into()));
                        }
                    }

                    self.deflate_bit_pos = d.offset + d.length;
                    if self.extra_byte == 1 {
                        deflate_buf[bytes_to_write - 1] |=
                            puff_buffer[p.length as usize] << (self.deflate_bit_pos & 7);
                        self.deflate_bit_pos = (self.deflate_bit_pos + 7) & !7u64;
                    } else if self.deflate_bit_pos & 7 != 0 {
                        self.last_byte = deflate_buf[bytes_to_write - 1] as u32;
                        bytes_to_write -= 1;
                    }

                    self.stream.write(&deflate_buf[..bytes_to_write]);

                    self.puff_pos += self.skip_bytes;
                    self.skip_bytes = 0;
                    self.cur_puff += 1;
                    self.cur_deflate += 1;
                    if self.cur_puff == self.puffs.len() {
                        break;
                    }
                    self.set_extra_byte()?;
                }
            }
        }
        if bytes_wrote != length {
            return Err(Error::Corrupt("huff did not consume input".into()));
        }
        Ok(())
    }
}

fn to_extents_bits(v: &[BitExtent]) -> Vec<Extent> {
    v.iter()
        .map(|e| Extent {
            offset: e.offset,
            length: e.length,
        })
        .collect()
}

fn to_extents_bytes(v: &[ByteExtent]) -> Vec<Extent> {
    v.iter()
        .map(|e| Extent {
            offset: e.offset,
            length: e.length,
        })
        .collect()
}

/// Puff `src` (raw source bytes) into a puff buffer of size `puff_size`.
pub fn puff(
    src: &[u8],
    deflates: &[BitExtent],
    puffs: &[ByteExtent],
    puff_size: u64,
) -> Result<Vec<u8>> {
    let d = to_extents_bits(deflates);
    let p = to_extents_bytes(puffs);
    let mut driver = Driver::new(src.to_vec(), puff_size, &d, &p)?;
    driver.seek_to_zero(true)?;
    let mut out = vec![0u8; puff_size as usize];
    driver.run_puff(&mut out)?;
    Ok(out)
}

/// Huff `puffed` (puff bytes, length `puff_size`) back into a deflate stream.
pub fn huff(
    puffed: &[u8],
    deflates: &[BitExtent],
    puffs: &[ByteExtent],
    puff_size: u64,
) -> Result<Vec<u8>> {
    let d = to_extents_bits(deflates);
    let p = to_extents_bytes(puffs);
    let mut driver = Driver::new(Vec::new(), puff_size, &d, &p)?;
    driver.seek_to_zero(false)?;
    driver.run_huff(puffed)?;
    Ok(driver.stream.buf)
}
