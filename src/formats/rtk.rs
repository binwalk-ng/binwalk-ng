use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "RTK firmware header";

/// RTK firmware images always start with these bytes
pub fn rtk_magic() -> Vec<Vec<u8>> {
    vec![b"RTK0".to_vec()]
}

/// Validates the RTK header
pub fn rtk_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Note: magic.rs enforces short=true for this signature, so offset will always be 0
    let available_data = file_data.len() - offset;

    if let Ok(rtk_header) = parse_rtk_header(&file_data[offset..]) {
        // This firmware header is expected to encompass the entirety of the remaining file data
        if rtk_header.image_size == available_data {
            result.size = rtk_header.header_size;
            result.description = format!(
                "{}, header size: {} bytes, image size: {}",
                result.description, rtk_header.header_size, rtk_header.image_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store RTK firmware header info
#[derive(Debug, Default, Clone)]
pub struct RTKHeader {
    pub image_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RTKHeaderBytes {
    magic: zerocopy::U32<LE>,
    image_size: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
    unknown1: [u8; 4],
    header_size: zerocopy::U32<LE>,
    unknown2: [u8; 8],
    identifier: zerocopy::U32<LE>,
}

/// Parses a RTK header
pub fn parse_rtk_header(rtk_data: &[u8]) -> Result<RTKHeader, StructureError> {
    const MAGIC_SIZE: usize = 4;

    // Parse the header
    let (rtk_header, _) = RTKHeaderBytes::ref_from_prefix(rtk_data).map_err(|_| StructureError)?;

    Ok(RTKHeader {
        image_size: rtk_header.image_size.get() as usize,
        header_size: rtk_header.header_size.get() as usize + MAGIC_SIZE,
    })
}
