//! `PUF1` patch container parsing and PUFFDIFF application, ported from puffin
//! `puffpatch.cc`. The embedded protobuf header is parsed by hand (no prost
//! dependency) since it is only a handful of fields.

use crate::stream;
use crate::{BitExtent, ByteExtent, Error, Result};

const MAGIC: &[u8; 4] = b"PUF1";
const PATCH_TYPE_BSDIFF: i64 = 0;

struct StreamInfo {
    deflates: Vec<BitExtent>,
    puffs: Vec<ByteExtent>,
    puff_length: u64,
}

impl StreamInfo {
    fn empty() -> Self {
        StreamInfo {
            deflates: Vec::new(),
            puffs: Vec::new(),
            puff_length: 0,
        }
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() {
                return Err(Error::BadProto("truncated varint".into()));
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            value |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(Error::BadProto("varint too long".into()));
            }
        }
    }

    fn len_delimited(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(Error::BadProto("length-delimited field overruns".into()));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Skip a field whose wire type is `wire`.
    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.pos += 8,
            2 => {
                let _ = self.len_delimited()?;
            }
            5 => self.pos += 4,
            _ => return Err(Error::BadProto(format!("unsupported wire type {wire}"))),
        }
        if self.pos > self.buf.len() {
            return Err(Error::BadProto("field overruns buffer".into()));
        }
        Ok(())
    }
}

fn parse_bit_extent(buf: &[u8]) -> Result<(u64, u64)> {
    let mut c = Cursor::new(buf);
    let mut offset = 0u64;
    let mut length = 0u64;
    while !c.at_end() {
        let key = c.varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        match (field, wire) {
            (1, 0) => offset = c.varint()?,
            (2, 0) => length = c.varint()?,
            _ => c.skip(wire)?,
        }
    }
    Ok((offset, length))
}

fn parse_stream_info(buf: &[u8]) -> Result<StreamInfo> {
    let mut info = StreamInfo::empty();
    let mut c = Cursor::new(buf);
    while !c.at_end() {
        let key = c.varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        match (field, wire) {
            (1, 2) => {
                let (offset, length) = parse_bit_extent(c.len_delimited()?)?;
                info.deflates.push(BitExtent { offset, length });
            }
            (2, 2) => {
                // Puffs are stored in bits in the proto; the stream wants bytes.
                let (offset, length) = parse_bit_extent(c.len_delimited()?)?;
                info.puffs.push(ByteExtent {
                    offset: offset / 8,
                    length: length / 8,
                });
            }
            (3, 0) => info.puff_length = c.varint()?,
            _ => c.skip(wire)?,
        }
    }
    Ok(info)
}

struct PatchHeader {
    src: StreamInfo,
    dst: StreamInfo,
    patch_type: i64,
}

fn parse_header(buf: &[u8]) -> Result<PatchHeader> {
    let mut src = StreamInfo::empty();
    let mut dst = StreamInfo::empty();
    let mut patch_type = PATCH_TYPE_BSDIFF;
    let mut c = Cursor::new(buf);
    while !c.at_end() {
        let key = c.varint()?;
        let field = key >> 3;
        let wire = (key & 7) as u8;
        match (field, wire) {
            (1, 0) => {
                c.varint()?; // version, ignored
            }
            (2, 2) => src = parse_stream_info(c.len_delimited()?)?,
            (3, 2) => dst = parse_stream_info(c.len_delimited()?)?,
            (4, 0) => patch_type = c.varint()? as i64,
            _ => c.skip(wire)?,
        }
    }
    Ok(PatchHeader {
        src,
        dst,
        patch_type,
    })
}

pub fn apply(source: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    if patch.len() < MAGIC.len() + 4 {
        return Err(Error::BadPatchHeader("patch too short".into()));
    }
    if &patch[..4] != MAGIC {
        return Err(Error::BadPatchHeader("missing PUF1 magic".into()));
    }
    let header_size = u32::from_be_bytes([patch[4], patch[5], patch[6], patch[7]]) as usize;
    let header_start = 8;
    let header_end = header_start + header_size;
    if header_end > patch.len() {
        return Err(Error::BadPatchHeader("header size overruns patch".into()));
    }

    let header = parse_header(&patch[header_start..header_end])?;
    if header.patch_type != PATCH_TYPE_BSDIFF {
        return Err(Error::UnsupportedPatchType(header.patch_type as i32));
    }
    let raw_patch = &patch[header_end..];

    // 1. Puff the source into puffin's canonical intermediate representation.
    let puffed_src = stream::puff(
        source,
        &header.src.deflates,
        &header.src.puffs,
        header.src.puff_length,
    )?;

    // 2. Apply the inner bsdiff patch (puffed_src -> puffed_dst).
    let mut puffed_dst = Vec::new();
    bsdiff_android::patch_bsdf2(&puffed_src, raw_patch, &mut puffed_dst)
        .map_err(|e| Error::Bsdiff(e.to_string()))?;

    if puffed_dst.len() as u64 != header.dst.puff_length {
        return Err(Error::SizeMismatch {
            expected: header.dst.puff_length,
            actual: puffed_dst.len() as u64,
        });
    }

    // 3. Huff the puffed destination back into a bit-exact deflate stream.
    let dst = stream::huff(
        &puffed_dst,
        &header.dst.deflates,
        &header.dst.puffs,
        header.dst.puff_length,
    )?;
    Ok(dst)
}
