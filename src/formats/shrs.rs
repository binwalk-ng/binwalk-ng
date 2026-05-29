use crate::signatures::{CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "SHRS encrypted firmware";

/// SHRS firmware images always start with these bytes
pub fn shrs_magic() -> Vec<Vec<u8>> {
    vec![b"SHRS".to_vec()]
}

/// Validates the SHRS header
pub fn shrs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    if let Ok(shrs_header) = parse_shrs_header(&file_data[offset..]) {
        result.size = shrs_header.header_size + shrs_header.data_size as usize;
        result.description = format!(
            "{}, header size: {} bytes, encrypted data size: {} bytes, IV: {}",
            result.description,
            shrs_header.header_size,
            shrs_header.data_size,
            hex::encode(shrs_header.iv),
        );

        if offset == 0 {
            result.confidence = CONFIDENCE_MEDIUM;
        }

        return Ok(result);
    }

    Err(SignatureError)
}

/// Struct to store SHRS firmware header info
#[derive(Debug, Default, Clone)]
pub struct SHRSHeader {
    pub iv: [u8; 16],
    pub data_size: u32,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SHRSHeaderBytes {
    magic: zerocopy::U32<BE>,
    unknown1: zerocopy::U32<BE>,
    encrypted_data_size: zerocopy::U32<BE>,
    iv: [u8; 16],
}

/// Parses an SHRS header
pub fn parse_shrs_header(shrs_data: &[u8]) -> Result<SHRSHeader, StructureError> {
    const HEADER_SIZE: usize = 0x6DC;

    // Parse the header
    let (shrs_header, _) =
        SHRSHeaderBytes::ref_from_prefix(shrs_data).map_err(|_| StructureError)?;

    Ok(SHRSHeader {
        iv: shrs_header.iv,
        data_size: shrs_header.encrypted_data_size.get(),
        header_size: HEADER_SIZE,
    })
}
