// Apply one delta op. Modes:
//   apply puffdiff <src> <patch.puf> <out>   -- this crate's PUFFDIFF applier
//   apply bsdiff   <src> <patch>     <out>   -- bsdiff-android BSDF2 (brotli/bz2)
use std::io::Read;

fn read(path: &str) -> Vec<u8> {
    let mut v = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut v)
        .unwrap();
    v
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 {
        eprintln!("usage: apply <puffdiff|bsdiff> <src> <patch> <out>");
        std::process::exit(2);
    }
    let (mode, src, patch, outp) = (&a[1], read(&a[2]), read(&a[3]), &a[4]);
    let out = match mode.as_str() {
        "puffdiff" => puffdiff::puffpatch(&src, &patch).expect("puffpatch failed"),
        "bsdiff" => {
            let mut o = Vec::new();
            bsdiff_android::patch_bsdf2(&src, &patch, &mut o).expect("bsdiff failed");
            o
        }
        _ => {
            eprintln!("unknown mode {mode}");
            std::process::exit(2);
        }
    };
    std::fs::write(outp, &out).unwrap();
}
