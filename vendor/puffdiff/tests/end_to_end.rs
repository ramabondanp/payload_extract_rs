//! End-to-end validation: build a genuine `PUF1` PUFFDIFF patch in Rust
//! (mirroring puffin's `puffdiff` creation path), apply it with this crate,
//! and — when the reference `puffin` binary is available — confirm puffin's own
//! applier produces the same destination from the same patch.
#![allow(clippy::type_complexity)]

use std::io::Write;
use std::process::Command;

use bsdiff_android::{diff_bsdf2_uniform, CompressionAlgorithm};
use flate2::{write::DeflateEncoder, Compression};

// ---- protobuf encoding for the PatchHeader (fields we need) -----------------

fn put_varint(v: u64, out: &mut Vec<u8>) {
    let mut v = v;
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn put_key(field: u64, wire: u64, out: &mut Vec<u8>) {
    put_varint((field << 3) | wire, out);
}

fn bit_extent_msg(offset: u64, length: u64) -> Vec<u8> {
    let mut m = Vec::new();
    put_key(1, 0, &mut m);
    put_varint(offset, &mut m);
    put_key(2, 0, &mut m);
    put_varint(length, &mut m);
    m
}

/// (deflate bit extents, puff byte extents, puff length) -> StreamInfo bytes.
fn stream_info(deflates: &[(u64, u64)], puffs: &[(u64, u64)], puff_len: u64) -> Vec<u8> {
    let mut m = Vec::new();
    for &(off, len) in deflates {
        let e = bit_extent_msg(off, len);
        put_key(1, 2, &mut m);
        put_varint(e.len() as u64, &mut m);
        m.extend_from_slice(&e);
    }
    for &(off, len) in puffs {
        // Puffs are stored in bits in the proto (DecodePatch divides by 8).
        let e = bit_extent_msg(off * 8, len * 8);
        put_key(2, 2, &mut m);
        put_varint(e.len() as u64, &mut m);
        m.extend_from_slice(&e);
    }
    put_key(3, 0, &mut m);
    put_varint(puff_len, &mut m);
    m
}

fn patch_header(src_si: &[u8], dst_si: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    put_key(2, 2, &mut m);
    put_varint(src_si.len() as u64, &mut m);
    m.extend_from_slice(src_si);
    put_key(3, 2, &mut m);
    put_varint(dst_si.len() as u64, &mut m);
    m.extend_from_slice(dst_si);
    // type field (4) omitted: BSDIFF == 0 is the proto3 default.
    m
}

// ---- deflate + puff metadata via the crate's debug helpers ------------------

fn raw_deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Compute (deflates_bits, puffs_bytes, puff_len, puff_bytes) for a whole
/// single-region deflate stream, exactly as puffin's puffdiff would.
fn puff_meta(deflate: &[u8]) -> (Vec<(u64, u64)>, Vec<(u64, u64)>, u64, Vec<u8>) {
    let (deflates, puffs, puff_len) = puffdiff::_debug_locate(deflate).unwrap();
    let puffed = puffdiff::_debug_stream_puff(deflate, &deflates, &puffs, puff_len).unwrap();
    assert_eq!(puffed.len() as u64, puff_len);
    (deflates, puffs, puff_len, puffed)
}

fn build_patch(src_deflate: &[u8], dst_deflate: &[u8]) -> Vec<u8> {
    let (s_def, s_puff, s_len, s_puffed) = puff_meta(src_deflate);
    let (d_def, d_puff, d_len, d_puffed) = puff_meta(dst_deflate);

    let mut raw_patch = Vec::new();
    diff_bsdf2_uniform(
        &s_puffed,
        &d_puffed,
        &mut raw_patch,
        CompressionAlgorithm::Bz2,
    )
    .unwrap();

    let src_si = stream_info(&s_def, &s_puff, s_len);
    let dst_si = stream_info(&d_def, &d_puff, d_len);
    let header = patch_header(&src_si, &dst_si);

    let mut patch = Vec::new();
    patch.extend_from_slice(b"PUF1");
    patch.extend_from_slice(&(header.len() as u32).to_be_bytes());
    patch.extend_from_slice(&header);
    patch.extend_from_slice(&raw_patch);
    patch
}

fn cases() -> Vec<(Vec<u8>, Vec<u8>)> {
    let base: Vec<u8> = b"The quick brown fox jumps over the lazy dog. ".repeat(200);
    let mut modified = base.clone();
    for (i, b) in modified.iter_mut().enumerate() {
        if i % 97 == 0 {
            *b = b'X';
        }
    }
    let seq_a: Vec<u8> = (0..15000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let mut seq_b = seq_a.clone();
    seq_b.extend_from_slice(b"appended tail data that changes the stream");

    vec![(base, modified), (seq_a, seq_b)]
}

#[test]
fn my_applier_matches_dst() {
    for (src_data, dst_data) in cases() {
        for level in [1u32, 6, 9] {
            let src_deflate = raw_deflate(&src_data, level);
            let dst_deflate = raw_deflate(&dst_data, level);
            let patch = build_patch(&src_deflate, &dst_deflate);

            let out = puffdiff::puffpatch(&src_deflate, &patch).expect("puffpatch failed");
            assert_eq!(out, dst_deflate, "my applier produced wrong deflate");
        }
    }
}

#[test]
fn cross_check_against_reference_puffin() {
    let puffin = "/Users/ril3y/projects/puffin/puffin";
    if !std::path::Path::new(puffin).exists() {
        eprintln!("skipping: reference puffin not present");
        return;
    }
    let dir = std::env::temp_dir().join("puffdiff_e2e");
    std::fs::create_dir_all(&dir).unwrap();

    for (i, (src_data, dst_data)) in cases().into_iter().enumerate() {
        for level in [1u32, 6, 9] {
            let src_deflate = raw_deflate(&src_data, level);
            let dst_deflate = raw_deflate(&dst_data, level);
            let patch = build_patch(&src_deflate, &dst_deflate);

            let src_path = dir.join(format!("src_{i}_{level}.deflate"));
            let patch_path = dir.join(format!("patch_{i}_{level}.puf"));
            let out_path = dir.join(format!("out_{i}_{level}.deflate"));
            std::fs::write(&src_path, &src_deflate).unwrap();
            std::fs::write(&patch_path, &patch).unwrap();

            let status = Command::new(puffin)
                .arg("--operation=puffpatch")
                .arg(format!("--src_file={}", src_path.display()))
                .arg(format!("--patch_file={}", patch_path.display()))
                .arg(format!("--dst_file={}", out_path.display()))
                .output()
                .expect("failed to run puffin");
            assert!(
                status.status.success(),
                "reference puffin rejected our patch: {}",
                String::from_utf8_lossy(&status.stderr)
            );
            let ref_out = std::fs::read(&out_path).unwrap();
            assert_eq!(
                ref_out, dst_deflate,
                "reference puffin produced wrong deflate from our patch"
            );
        }
    }
}
