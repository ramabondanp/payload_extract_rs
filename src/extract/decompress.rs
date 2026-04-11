use std::io::Read;

use crate::error::PayloadError;

use super::operation::OpType;

/// Decompress data based on operation type.
/// For Replace operations, data is not compressed — the caller should
/// use the zero-copy path instead of calling this function.
pub fn decompress(op_type: OpType, input: &[u8], output: &mut Vec<u8>) -> Result<(), PayloadError> {
    match op_type {
        OpType::Replace => {
            output.extend_from_slice(input);
            Ok(())
        }
        OpType::ReplaceBz => {
            let mut decoder = bzip2::read::BzDecoder::new(input);
            decoder.read_to_end(output).map_err(|e| {
                PayloadError::DecompressionFailed(format!("bzip2: {e}"))
            })?;
            Ok(())
        }
        OpType::ReplaceXz => {
            let mut decoder = xz2::read::XzDecoder::new(input);
            decoder.read_to_end(output).map_err(|e| {
                PayloadError::DecompressionFailed(format!("xz: {e}"))
            })?;
            Ok(())
        }
        OpType::ReplaceZstd => {
            let decompressed = zstd::stream::decode_all(input).map_err(|e| {
                PayloadError::DecompressionFailed(format!("zstd: {e}"))
            })?;
            output.extend_from_slice(&decompressed);
            Ok(())
        }
        OpType::Zero => {
            // Caller handles zero-fill at the writer level
            Ok(())
        }
        OpType::Discard
        | OpType::SourceCopy
        | OpType::SourceBsdiff
        | OpType::BrotliBsdiff
        | OpType::Puffdiff
        | OpType::Zucchini
        | OpType::Lz4diffBsdiff
        | OpType::Lz4diffPuffdiff => {
            // These are handled directly in the extraction orchestrator
            Err(PayloadError::UnsupportedOperation(op_type as i32))
        }
    }
}
