use crate::error::PayloadError;

pub const MAGIC: &[u8; 4] = b"CrAU";
pub const SUPPORTED_VERSION: u64 = 2;
pub const HEADER_SIZE: usize = 24; // 4 (magic) + 8 (version) + 8 (manifest_size) + 4 (metadata_sig_size)

#[derive(Debug, Clone)]
pub struct PayloadHeader {
    pub version: u64,
    pub manifest_size: u64,
    pub metadata_signature_size: u32,
}

impl PayloadHeader {
    pub fn parse(data: &[u8]) -> Result<Self, PayloadError> {
        if data.len() < HEADER_SIZE {
            return Err(PayloadError::PayloadTooSmall {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if &magic != MAGIC {
            return Err(PayloadError::InvalidMagic(magic));
        }

        let version = u64::from_be_bytes(data[4..12].try_into().unwrap());
        if version != SUPPORTED_VERSION {
            return Err(PayloadError::UnsupportedVersion(version));
        }

        let manifest_size = u64::from_be_bytes(data[12..20].try_into().unwrap());
        let metadata_signature_size = u32::from_be_bytes(data[20..24].try_into().unwrap());

        Ok(Self {
            version,
            manifest_size,
            metadata_signature_size,
        })
    }

    /// Total size of header + manifest + metadata signature
    pub fn data_offset(&self) -> u64 {
        HEADER_SIZE as u64 + self.manifest_size + self.metadata_signature_size as u64
    }
}
