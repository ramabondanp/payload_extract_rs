use crate::proto::install_operation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpType {
    Replace,
    ReplaceBz,
    ReplaceXz,
    BrotliBsdiff,
    Puffdiff,
    Zucchini,
    Lz4diffBsdiff,
    Lz4diffPuffdiff,
    ReplaceZstd,
    Zero,
    Discard,
    SourceCopy,
    SourceBsdiff,
}

impl OpType {
    pub fn from_proto(t: install_operation::Type) -> Result<Self, i32> {
        match t {
            install_operation::Type::Replace => Ok(OpType::Replace),
            install_operation::Type::ReplaceBz => Ok(OpType::ReplaceBz),
            install_operation::Type::ReplaceXz => Ok(OpType::ReplaceXz),
            install_operation::Type::BrotliBsdiff => Ok(OpType::BrotliBsdiff),
            install_operation::Type::Puffdiff => Ok(OpType::Puffdiff),
            install_operation::Type::Zucchini => Ok(OpType::Zucchini),
            install_operation::Type::Lz4diffBsdiff => Ok(OpType::Lz4diffBsdiff),
            install_operation::Type::Lz4diffPuffdiff => Ok(OpType::Lz4diffPuffdiff),
            install_operation::Type::ReplaceZstd => Ok(OpType::ReplaceZstd),
            install_operation::Type::Zero => Ok(OpType::Zero),
            install_operation::Type::Discard => Ok(OpType::Discard),
            install_operation::Type::SourceCopy => Ok(OpType::SourceCopy),
            install_operation::Type::SourceBsdiff => Ok(OpType::SourceBsdiff),
            _ => Err(t as i32),
        }
    }
}

pub struct OperationTask {
    pub op_type: OpType,
    pub data_offset: u64,
    pub data_length: u64,
    pub src_extents: Vec<(u64, u64)>,
    pub dst_extents: Vec<(u64, u64)>,
    pub data_sha256: Option<Vec<u8>>,
    pub src_sha256: Option<Vec<u8>>,
    pub partition_name: String,
}
