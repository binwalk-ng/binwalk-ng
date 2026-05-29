use crate::common::get_cstring;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "BIN firmware header";

/// BIN header magic bytes
pub fn bin_hdr_magic() -> Vec<Vec<u8>> {
    vec![b"U2ND".to_vec()]
}

/// Validates the BIN header
pub fn bin_hdr_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MAGIC_OFFSET: usize = 14;

    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if offset >= MAGIC_OFFSET {
        result.offset = offset - MAGIC_OFFSET;

        if let Ok(bin_header) = parse_bin_header(&file_data[result.offset..]) {
            result.description = format!(
                "{}, board ID: {}, hardware revision: {}, firmware version: {}.{}",
                result.description,
                bin_header.board_id,
                bin_header.hardware_revision,
                bin_header.firmware_version_major,
                bin_header.firmware_version_minor,
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store BIN header info
pub struct BINHeader {
    pub board_id: String,
    pub hardware_revision: String,
    pub firmware_version_major: u8,
    pub firmware_version_minor: u8,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BINHeaderBytes {
    reserved1: [u8; 4],
    build_date: zerocopy::U32<LE>,
    firmware_version_major: u8,
    firmware_version_minor: u8,
    magic: zerocopy::U32<LE>,
    hardware_id: u8,
    reserved2: [u8; 11],
}

/// Parses a BIN header
pub fn parse_bin_header(bin_hdr_data: &[u8]) -> Result<BINHeader, StructureError> {
    // The data strcuture is preceeded by a 4-byte board ID string
    const STRUCTURE_OFFSET: usize = 4;

    // Parse the header
    if let Some(structure_data) = bin_hdr_data.get(STRUCTURE_OFFSET..) {
        let (header, _) =
            BINHeaderBytes::ref_from_prefix(structure_data).map_err(|_| StructureError)?;
        // Make sure the reserved fields are NULL
        if !header
            .reserved1
            .iter()
            .chain(&header.reserved2)
            .all(|&b| b == 0)
        {
            return Err(StructureError);
        }
        // Make sure the reported hardware ID is valid
        let hardware_id = match header.hardware_id {
            0 => "4702",
            1 => "4712",
            2 => "4712L",
            3 => "4704",
            _ => return Err(StructureError),
        };
        // Get the board ID string, which immediately precedes the data structure
        if let Some(board_id_bytes) = bin_hdr_data.get(0..STRUCTURE_OFFSET) {
            let board_id = get_cstring(board_id_bytes);

            // The board ID string should be 4 bytes in length
            if board_id.len() == STRUCTURE_OFFSET {
                return Ok(BINHeader {
                    board_id,
                    hardware_revision: hardware_id.to_string(),
                    firmware_version_major: header.firmware_version_major,
                    firmware_version_minor: header.firmware_version_minor,
                });
            }
        }
    }

    Err(StructureError)
}
