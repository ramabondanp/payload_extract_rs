# puffdiff-rs

A pure-Rust applier for Android OTA **PUFFDIFF** (puffin) delta operations.

PUFFDIFF is one of the delta operation types in Android A/B OTA `payload.bin`
files. Applying it requires the puffin deflate ⇄ "puff" transform: the source
image's deflate streams are decoded into an intermediate "puffed" form, a bsdiff
patch is applied in puff space, and the result is re-encoded (`huffed`) back into
a **bit-exact** deflate stream. This crate implements that end to end so a
PUFFDIFF op can be applied without shelling out to `puffin` / `puff_stream_tool`.

This is a faithful port of AOSP `external/puffin` (ChromiumOS, BSD-3-Clause):
`bit_reader`/`bit_writer`, `puff_reader`/`puff_writer`, `huffman_table`,
`puffer`, `huffer`, `puffin_stream`, and the `PUF1` patch container.

## Usage

```rust
// `source` = the contiguous bytes of the op's source extents.
// `patch`  = the PUF1 blob from the payload (header + embedded bsdiff patch).
let dst = puffdiff::puffpatch(&source, &patch)?;
```

Only `BSDIFF`-type PUFFDIFF patches are supported. `ZUCCHINI` patches return an
error.

## Scope

This crate only **applies** patches. Computing deflate/puff extents (the
patch-creation side) is out of scope; the extents are read from the `PUF1`
header. The inner bsdiff patch is applied via the `bsdiff-android` crate, the
same one the Rust payload-dumper already uses.

## Validation

`cargo test` runs:

- **Round-trip** (`src/lib.rs`): puff→huff over deflate produced at every zlib
  level (stored, fixed, and dynamic Huffman blocks) reproduces the original
  bytes bit-for-bit.
- **Stream round-trip**: the same through the extent-driven stream driver.
- **End-to-end** (`tests/end_to_end.rs`): builds a genuine `PUF1` patch in Rust
  (mirroring puffin's `puffdiff` creation path) and applies it with this crate.
  When the reference `puffin` binary is present, it also confirms puffin's own
  applier produces the same destination from the *same* patch.
- **Real fixtures** (`tests/real_fixtures.rs`): applies PUFFDIFF operations
  extracted from a genuine Motorola incremental OTA (`cofud_g`
  S3RWDS32.123-29-8-2-9 → 8-2-10) and checks the output byte-for-byte. The
  fixtures are proprietary Motorola firmware fragments and are **not distributed
  with this repo**; the test skips when `tests/fixtures/` is empty. Drop
  `<name>.{src,puf,dst}` triples there to enable it (`scripts/verify_partition.py`
  shows how they were produced).

Two independent anchors establish correctness on real data:

1. This crate's output is **byte-identical to the reference `puffin` binary** on
   every real PUFFDIFF op tested — all 7 ops across the `boot` and `system`
   partitions of the OTA above — and its puffed byte stream matches
   `puffin --operation=puff` exactly for all fixed/dynamic Huffman blocks.
2. Reconstructing the whole `boot` partition from the real base image by
   applying every op — this crate for PUFFDIFF, `bsdiff-android` for
   BSDIFF/BROTLI_BSDIFF — reproduces the payload's declared
   `new_partition_info.hash`, i.e. **Motorola's own SHA-256**. See
   `scripts/verify_partition.py` (needs local multi-GB base images, so it is not
   a committed unit test).

Notably, Motorola's on-device tooling reference (`puff_stream_tool` driven by a
Python harness) produced the *wrong* bytes for these same ops — its `boot`
output did not match the manufacturer hash, while this crate's does.

(The helper script can also reconstruct larger partitions, but full
verification there additionally requires modelling uncovered/zero blocks; `boot`
is the clean end-to-end anchor.)

## License

BSD-3-Clause, matching the upstream puffin sources this is derived from.
