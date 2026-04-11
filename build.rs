fn main() -> std::io::Result<()> {
    prost_build::Config::new().compile_protos(
        &[
            "src/proto/update_metadata.proto",
            "src/proto/lz4diff.proto",
        ],
        &["src/proto/"],
    )?;
    Ok(())
}
