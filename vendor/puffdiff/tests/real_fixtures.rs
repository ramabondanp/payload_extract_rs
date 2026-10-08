//! Golden tests against real Motorola PUFFDIFF operations.
//!
//! Each fixture is one PUFFDIFF op extracted from a genuine Motorola incremental
//! OTA (cofud_g S3RWDS32.123-29-8-2-9 -> 8-2-10):
//!   <name>.src  — the op's source extents read from the base image
//!   <name>.puf  — the op's PUF1 patch blob from payload.bin
//!   <name>.dst  — the op's destination extents from the (verified) target image
//! Applying the patch to the source must reproduce the destination exactly.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Discover fixture triples by scanning for `*.puf` files.
fn fixture_names() -> Vec<String> {
    let dir = fixtures_dir();
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) == Some("puf") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

#[test]
fn real_motorola_puffdiff_ops() {
    let dir = fixtures_dir();
    let names = fixture_names();
    if names.is_empty() {
        // The real-data fixtures are extracted from proprietary Motorola
        // firmware and are not distributed with this repo. Drop
        // <name>.{src,puf,dst} triples into tests/fixtures/ to enable this test
        // (see scripts/verify_partition.py and the README).
        eprintln!("no fixtures in {} — skipping real-data test", dir.display());
        return;
    }

    for name in &names {
        let source = std::fs::read(dir.join(format!("{name}.src")))
            .unwrap_or_else(|e| panic!("read {name}.src: {e}"));
        let patch = std::fs::read(dir.join(format!("{name}.puf")))
            .unwrap_or_else(|e| panic!("read {name}.puf: {e}"));
        let expected = std::fs::read(dir.join(format!("{name}.dst")))
            .unwrap_or_else(|e| panic!("read {name}.dst: {e}"));

        assert_eq!(&patch[..4], b"PUF1", "{name}: not a PUF1 patch");

        let out = puffdiff::puffpatch(&source, &patch)
            .unwrap_or_else(|e| panic!("{name}: puffpatch failed: {e}"));

        assert_eq!(
            out.len(),
            expected.len(),
            "{name}: output length {} != expected {}",
            out.len(),
            expected.len()
        );
        assert!(
            out == expected,
            "{name}: output bytes differ from expected destination"
        );
        eprintln!("{name}: OK ({} bytes)", out.len());
    }
}
