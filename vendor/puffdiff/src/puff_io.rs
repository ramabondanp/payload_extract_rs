//! The "puff" intermediate serialization, ported from puffin `puff_data.h`,
//! `puff_writer.cc` and `puff_reader.cc`.
//!
//! The byte layout produced here must match puffin exactly, because the bsdiff
//! patch inside a PUFFDIFF op is computed against puffin's puffed bytes.

use crate::{Error, Result};

/// Maximum bytes a block-metadata blob can occupy: 1 header + 3 lengths +
/// 286 lit/len code lengths + 30 distance + 19 code-length codes.
pub const BLOCK_METADATA_MAX: usize = 1 + 3 + 286 + 30 + 19;

const LITERALS_HEADER: u8 = 0x00;
const LEN_DIST_HEADER: u8 = 0x80;
const LITERALS_MAX_LENGTH: usize = (1 << 16) + 127; // 65663

/// One decoded token exchanged between puffer/huffer and the puff buffer.
pub enum PuffData<'a> {
    Literal(u8),
    Literals(&'a [u8]),
    LenDist { length: usize, distance: usize },
    BlockMetadata(&'a [u8]),
    EndOfBlock,
}

#[inline]
fn write_u16_be(buf: &mut [u8], value: u16) {
    buf[0] = (value >> 8) as u8;
    buf[1] = (value & 0xFF) as u8;
}

#[inline]
fn read_u16_be(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) | buf[1] as u16
}

#[derive(PartialEq)]
enum WState {
    NonLiteral,
    SmallLiteral,
    LargeLiteral,
}

/// Serializes `PuffData` tokens into the puff byte format.
pub struct PuffWriter<'a> {
    out: &'a mut [u8],
    index: usize,
    state: WState,
    len_index: usize,
    cur_literals_length: usize,
}

impl<'a> PuffWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        PuffWriter {
            out,
            index: 0,
            state: WState::NonLiteral,
            len_index: 0,
            cur_literals_length: 0,
        }
    }

    fn insert_literal_bytes(&mut self, is_single: bool, byte: u8, bytes: &[u8]) -> Result<()> {
        let length = if is_single { 1 } else { bytes.len() };
        if !is_single && length == 0 {
            return Ok(());
        }
        if self.state == WState::NonLiteral {
            self.len_index = self.index;
            self.index += 1;
            self.state = WState::SmallLiteral;
        }
        if self.state == WState::SmallLiteral && (self.cur_literals_length + length) > 127 {
            if self.index + 2 > self.out.len() {
                return Err(Error::Corrupt(format!(
                    "puff writer shift overflow: index {} + 2 > len {}",
                    self.index,
                    self.out.len()
                )));
            }
            // Open two bytes of space for a large-literal length prefix by
            // shifting the already-written literals forward.
            self.out.copy_within(
                self.len_index + 1..self.len_index + 1 + self.cur_literals_length,
                self.len_index + 3,
            );
            self.index += 2;
            self.state = WState::LargeLiteral;
        }

        if self.index + length > self.out.len() {
            return Err(Error::Corrupt("puff writer literal overflow".into()));
        }
        if is_single {
            self.out[self.index] = byte;
        } else {
            self.out[self.index..self.index + length].copy_from_slice(bytes);
        }
        self.index += length;
        self.cur_literals_length += length;

        if self.cur_literals_length == LITERALS_MAX_LENGTH {
            self.flush_literals()?;
        }
        Ok(())
    }

    pub fn insert(&mut self, pd: &PuffData) -> Result<()> {
        match pd {
            PuffData::Literal(b) => self.insert_literal_bytes(true, *b, &[]),
            PuffData::Literals(bytes) => self.insert_literal_bytes(false, 0, bytes),
            PuffData::LenDist { length, distance } => {
                self.flush_literals()?;
                let (length, distance) = (*length, *distance);
                if !(3..=258).contains(&length) || !(1..=32768).contains(&distance) {
                    return Err(Error::Corrupt("len/dist out of range".into()));
                }
                if length < 130 {
                    if self.index + 3 > self.out.len() {
                        return Err(Error::Corrupt(format!(
                            "puff writer len/dist overflow: index {} + 3 > len {}",
                            self.index,
                            self.out.len()
                        )));
                    }
                    self.out[self.index] = LEN_DIST_HEADER | (length - 3) as u8;
                    self.index += 1;
                } else {
                    if self.index + 4 > self.out.len() {
                        return Err(Error::Corrupt(format!(
                            "puff writer len/dist overflow: index {} + 4 > len {}",
                            self.index,
                            self.out.len()
                        )));
                    }
                    self.out[self.index] = LEN_DIST_HEADER | 127;
                    self.index += 1;
                    self.out[self.index] = (length - 3 - 127) as u8;
                    self.index += 1;
                }
                write_u16_be(&mut self.out[self.index..], (distance - 1) as u16);
                self.index += 2;
                self.len_index = self.index;
                self.state = WState::NonLiteral;
                Ok(())
            }
            PuffData::BlockMetadata(meta) => {
                self.flush_literals()?;
                let length = meta.len();
                if length == 0 || length > BLOCK_METADATA_MAX {
                    return Err(Error::Corrupt("block metadata length invalid".into()));
                }
                if self.index + 2 + length > self.out.len() {
                    return Err(Error::Corrupt(format!(
                        "puff writer block metadata overflow: index {} + 2 + {} > len {}",
                        self.index,
                        length,
                        self.out.len()
                    )));
                }
                write_u16_be(&mut self.out[self.index..], (length - 1) as u16);
                self.index += 2;
                self.out[self.index..self.index + length].copy_from_slice(meta);
                self.index += length;
                self.len_index = self.index;
                self.state = WState::NonLiteral;
                Ok(())
            }
            PuffData::EndOfBlock => {
                self.flush_literals()?;
                if self.index + 2 > self.out.len() {
                    return Err(Error::Corrupt(format!(
                        "puff writer end of block overflow: index {} + 2 > len {}",
                        self.index,
                        self.out.len()
                    )));
                }
                self.out[self.index] = LEN_DIST_HEADER | 127;
                self.index += 1;
                self.out[self.index] = (259 - 3 - 127) as u8;
                self.index += 1;
                self.len_index = self.index;
                self.state = WState::NonLiteral;
                Ok(())
            }
        }
    }

    fn flush_literals(&mut self) -> Result<()> {
        if self.cur_literals_length == 0 {
            return Ok(());
        }
        match self.state {
            WState::SmallLiteral => {
                if self.cur_literals_length != self.index - self.len_index - 1 {
                    return Err(Error::Corrupt("small literal length mismatch".into()));
                }
                self.out[self.len_index] = LITERALS_HEADER | (self.cur_literals_length - 1) as u8;
                self.len_index = self.index;
                self.state = WState::NonLiteral;
            }
            WState::LargeLiteral => {
                if self.cur_literals_length != self.index - self.len_index - 3 {
                    return Err(Error::Corrupt("large literal length mismatch".into()));
                }
                self.out[self.len_index] = LITERALS_HEADER | 127;
                write_u16_be(
                    &mut self.out[self.len_index + 1..],
                    (self.cur_literals_length - 127 - 1) as u16,
                );
                self.len_index = self.index;
                self.state = WState::NonLiteral;
            }
            WState::NonLiteral => {}
        }
        self.cur_literals_length = 0;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.flush_literals()
    }

    pub fn size(&self) -> usize {
        self.index
    }
}

enum RState {
    ReadingLenDist,
    ReadingBlockMetadata,
}

/// Deserializes puff bytes back into `PuffData` tokens.
pub struct PuffReader<'a> {
    buf: &'a [u8],
    index: usize,
    state: RState,
}

impl<'a> PuffReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        PuffReader {
            buf,
            index: 0,
            state: RState::ReadingBlockMetadata,
        }
    }

    pub fn bytes_left(&self) -> usize {
        self.buf.len() - self.index
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.index + n > self.buf.len() {
            return Err(Error::Corrupt("puff reader out of range".into()));
        }
        Ok(())
    }

    pub fn get_next(&mut self) -> Result<PuffData<'a>> {
        match self.state {
            RState::ReadingLenDist => {
                self.need(1)?;
                let header = self.buf[self.index];
                if header & 0x80 != 0 {
                    // length/distance (or end of block)
                    let mut length;
                    if (header & 0x7F) < 127 {
                        length = (header & 0x7F) as usize;
                    } else {
                        self.index += 1;
                        self.need(1)?;
                        length = self.buf[self.index] as usize + 127;
                    }
                    length += 3;
                    if length > 259 {
                        return Err(Error::Corrupt("len/dist length too large".into()));
                    }
                    self.index += 1;

                    if length == 259 {
                        self.state = RState::ReadingBlockMetadata;
                        return Ok(PuffData::EndOfBlock);
                    }

                    self.need(2)?;
                    let distance = read_u16_be(&self.buf[self.index..]);
                    if distance >= (1 << 15) {
                        return Err(Error::Corrupt("distance too large".into()));
                    }
                    let distance = distance as usize + 1;
                    self.index += 2;
                    Ok(PuffData::LenDist { length, distance })
                } else {
                    // literals
                    let mut length;
                    if (header & 0x7F) < 127 {
                        length = (header & 0x7F) as usize;
                        self.index += 1;
                    } else {
                        self.index += 1;
                        self.need(2)?;
                        length = read_u16_be(&self.buf[self.index..]) as usize + 127;
                        self.index += 2;
                    }
                    length += 1;
                    self.need(length)?;
                    let slice = &self.buf[self.index..self.index + length];
                    self.index += length;
                    Ok(PuffData::Literals(slice))
                }
            }
            RState::ReadingBlockMetadata => {
                self.need(2)?;
                let length = read_u16_be(&self.buf[self.index..]) as usize + 1;
                self.index += 2;
                self.need(length)?;
                if length > BLOCK_METADATA_MAX {
                    return Err(Error::Corrupt("block metadata too large".into()));
                }
                let slice = &self.buf[self.index..self.index + length];
                self.index += length;
                self.state = RState::ReadingLenDist;
                Ok(PuffData::BlockMetadata(slice))
            }
        }
    }
}
