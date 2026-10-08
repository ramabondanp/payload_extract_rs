#!/usr/bin/env python3
"""Ground-truth integration check for the puffdiff crate.

Reconstructs a whole partition from a real Motorola incremental OTA by applying
every install operation to the base image, using the built `apply` example
(this crate) for PUFFDIFF ops, then verifies the result against the payload's
declared `new_partition_info.hash`. This is the strongest possible test: it
confirms the crate matches the manufacturer's own SHA-256.

It is NOT a committed unit test because it needs multi-GB base images. Point the
paths below at a local delta + base image set.

Usage:
    python3 verify_partition.py <payload.bin> <source_dir> <partition> [apply_bin]

`source_dir` holds the base <partition>.img files (build N); `payload.bin` is the
N -> N+1 delta payload. Requires the moto_ota_tool module on PYTHONPATH for the
protobuf definitions and the pure-Python bsdiff/brotli helpers.
"""
import sys, os, hashlib, bz2, lzma, subprocess, tempfile

from moto_ota_tool import (
    PayloadPatcher,
    OP_REPLACE, OP_REPLACE_BZ, OP_REPLACE_XZ, OP_ZERO, OP_DISCARD,
    OP_SOURCE_COPY, OP_SOURCE_BSDIFF, OP_BROTLI_BSDIFF, OP_PUFFDIFF, OP_NAMES,
)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    payload_path, source_dir, target = sys.argv[1:4]
    apply_bin = sys.argv[4] if len(sys.argv) > 4 else \
        os.path.join(os.path.dirname(__file__), "..", "target", "release", "examples", "apply")

    p = PayloadPatcher(payload_path)
    bs = p.block_size
    data_off = p.data_offset

    def read_src(f, extents):
        out = bytearray()
        for e in extents:
            f.seek(e.start_block * bs)
            out += f.read(e.num_blocks * bs)
        return bytes(out)

    def rust_apply(mode, source, patch):
        with tempfile.TemporaryDirectory() as td:
            sp, pp, op = (os.path.join(td, x) for x in ("s", "p", "o"))
            open(sp, "wb").write(source)
            open(pp, "wb").write(patch)
            subprocess.run([apply_bin, mode, sp, pp, op], check=True)
            return open(op, "rb").read()

    part = next(x for x in p.manifest.partitions if x.partition_name == target)
    size = part.new_partition_info.size
    out = bytearray(size)
    payload = open(payload_path, "rb")
    src_f = open(os.path.join(source_dir, f"{target}.img"), "rb")

    counts = {}
    for op in part.operations:
        counts[OP_NAMES.get(op.type, op.type)] = counts.get(OP_NAMES.get(op.type, op.type), 0) + 1
        payload.seek(data_off + op.data_offset)
        data = payload.read(op.data_length)

        def write_dst(buf):
            pos = 0
            for e in op.dst_extents:
                nb = e.num_blocks * bs
                out[e.start_block * bs:e.start_block * bs + nb] = buf[pos:pos + nb]
                pos += nb

        if op.type in (OP_REPLACE, OP_REPLACE_BZ, OP_REPLACE_XZ):
            if op.type == OP_REPLACE_BZ:
                data = bz2.decompress(data)
            elif op.type == OP_REPLACE_XZ:
                data = lzma.decompress(data)
            write_dst(data)
        elif op.type == OP_ZERO:
            for e in op.dst_extents:
                out[e.start_block * bs:e.start_block * bs + e.num_blocks * bs] = b"\x00" * (e.num_blocks * bs)
        elif op.type == OP_DISCARD:
            pass
        elif op.type == OP_SOURCE_COPY:
            write_dst(read_src(src_f, op.src_extents))
        elif op.type in (OP_SOURCE_BSDIFF, OP_BROTLI_BSDIFF):
            # Use the Rust bsdiff-android applier (what payload-dumper uses),
            # not the pure-Python bsdiff, so this checks the real toolchain.
            write_dst(rust_apply("bsdiff", read_src(src_f, op.src_extents), data))
        elif op.type == OP_PUFFDIFF:
            write_dst(rust_apply("puffdiff", read_src(src_f, op.src_extents), data))
        else:
            raise SystemExit(f"unhandled op type {op.type}")

    got = hashlib.sha256(out).hexdigest()
    want = part.new_partition_info.hash.hex()
    print(f"{target}: ops={counts}")
    print(f"  reconstructed = {got}")
    print(f"  expected      = {want}")
    print("  =>", "MATCH" if got == want else "MISMATCH")
    sys.exit(0 if got == want else 1)


if __name__ == "__main__":
    main()
