use thiserror::Error;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error("invalid magic: expected 'CrAU', got {0:?}")]
    InvalidMagic([u8; 4]),

    #[error("unsupported payload version: {0} (expected 2)")]
    UnsupportedVersion(u64),

    #[error("payload too small: need at least {expected} bytes, got {actual}")]
    PayloadTooSmall { expected: usize, actual: usize },

    #[error("failed to parse manifest: {0}")]
    ManifestParseFailed(#[from] prost::DecodeError),

    #[error("{context}: expected {expected}, got {actual}")]
    HashMismatch {
        context: String,
        expected: String,
        actual: String,
    },

    #[error("unsupported operation type: {0}")]
    UnsupportedOperation(i32),

    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    #[error("payload.bin not found in ZIP archive")]
    PayloadNotFoundInZip,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
}
