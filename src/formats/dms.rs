use crate::extractors::swapped::byte_swap;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "DMS firmware image";

/// DMS firmware image magic bytes
pub fn dms_magic() -> Vec<Vec<u8>> {
    vec![b"0><1".to_vec()]
}

/// Validates the DMS header
pub fn dms_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MIN_SIZE: usize = 0x100;
    const BYTE_SWAP_SIZE: usize = 2;
    const MAGIC_OFFSET: usize = 4;

    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // The magic bytes start at offset 4
    if offset >= MAGIC_OFFSET {
        result.offset = offset - MAGIC_OFFSET;

        if let Some(dms_data) = file_data.get(result.offset..result.offset + MIN_SIZE) {
            // DMS firmware images have every 2 bytes swapped
            let swapped_data = byte_swap::<BYTE_SWAP_SIZE>(dms_data);

            // Validate the DMS firmware header
            if let Ok(dms_header) = parse_dms_header(&swapped_data) {
                result.size = dms_header.image_size;
                result.description =
                    format!("{}, total size: {} bytes", result.description, result.size);
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store DMS header info
#[derive(Debug, Default, Clone)]
pub struct DMSHeader {
    pub image_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DMSHeaderBytes {
    unknown1: zerocopy::U16<BE>,
    magic_p1: zerocopy::U16<BE>,
    magic_p2: zerocopy::U32<BE>,
    unknown2: zerocopy::U32<BE>,
    image_size: zerocopy::U32<BE>,
}

/// Parses a DMS header
pub fn parse_dms_header(dms_data: &[u8]) -> Result<DMSHeader, StructureError> {
    const MAGIC_P1: u16 = 0x4D47;
    const MAGIC_P2: u32 = 0x3C31303E;

    // Parse the first half of the header
    let (dms_header, _) = DMSHeaderBytes::ref_from_prefix(dms_data).map_err(|_| StructureError)?;
    if dms_header.magic_p1 == MAGIC_P1 && dms_header.magic_p2 == MAGIC_P2 {
        return Ok(DMSHeader {
            image_size: dms_header.image_size.get() as usize,
        });
    }

    Err(StructureError)
}
