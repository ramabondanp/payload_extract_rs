fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();

    match protoc_bin_vendored::protoc_bin_path() {
        Ok(protoc) => {
            config.protoc_executable(protoc);
        }
        Err(err) => {
            eprintln!("WARNING: vendored protoc unavailable: {err}");
            let has_system_protoc = std::env::var("PROTOC").is_ok()
                || std::process::Command::new("protoc")
                    .arg("--version")
                    .output()
                    .is_ok();
            if !has_system_protoc {
                eprintln!("ERROR: no protoc found. Install protoc or set PROTOC env var.");
                return Err("protoc binary not found (set PROTOC or install protobuf-compiler)".into());
            }
        }
    }

    config.compile_protos(
        &[
            "src/proto/update_metadata.proto",
            "src/proto/lz4diff.proto",
            "src/proto/ota_metadata.proto",
        ],
        &["src/proto/"],
    )?;

    Ok(())
}
