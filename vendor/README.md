# Vendored Dependencies

This directory contains vendored third-party dependencies with local patches or fixes.

## `puffdiff`

- **Crate**: [`puffdiff`](https://crates.io/crates/puffdiff) (v0.1.0)
- **Upstream Repository**: [https://github.com/ril3y/puffdiff-rs](https://github.com/ril3y/puffdiff-rs)
- **Author**: ril3y
- **License**: BSD-3-Clause
- **Upstream Git Commit**: `e0d4dcee9991858ebddc1f612bd91cf02cd83c73`

### Reason for Vendoring & Local Modifications

Upstream `puffdiff 0.1.0` is a pure-Rust implementation of Android OTA `PUFFDIFF` (puffin) operations. It is vendored locally with the following patch:

- **Buffer Boundary Safety in `PuffWriter` (`src/puff_io.rs`)**:
  Added explicit bounds checking when writing literals, length/distance codes, block metadata, and EndOfBlock markers. When an input deflate stream contains corrupted or edge-case offsets that would exceed output buffer bounds, `PuffWriter` now safely returns `Err(Error::Corrupt(...))` instead of triggering an out-of-bounds slice indexing panic.
