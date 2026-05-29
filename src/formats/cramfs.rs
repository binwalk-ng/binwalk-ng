use crate::common;
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;

/// Human readable description
pub const DESCRIPTION: &str = "CramFS filesystem";

/// This is technically the CramFS "signature", not the magic bytes, but it's endian-agnostic
pub fn cramfs_magic() -> Vec<Vec<u8>> {
    vec![b"Compressed ROMFS".to_vec()]
}

/// Parse and validate the CramFS header
pub fn cramfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Some constant relative offsets
    const SIGNATURE_OFFSET: usize = 16;
    const CRC_START_OFFSET: usize = 32;
    const CRC_END_OFFSET: usize = 36;

    let mut result = SignatureResult {
        offset: offset - SIGNATURE_OFFSET,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    if let Some(cramfs_header_data) = file_data.get(result.offset..) {
        // Parse the CramFS header; also validates that the reported size is greater than the header size
        if let Ok(cramfs_header) = parse_cramfs_header(cramfs_header_data) {
            // Update the reported size
            result.size = cramfs_header.size;

            if let Some(cramfs_image_data) =
                file_data.get(result.offset..result.offset + result.size)
            {
                /*
                 * Create a copy of the cramfs image; we have to NULL out the checksum field to calculate the CRC.
                 * This typically shouldn't be too bad on performance, CramFS images are usually relatively small.
                 */
                let mut cramfs_image = cramfs_image_data.to_vec();

                // Null out the checksum field
                cramfs_image[CRC_START_OFFSET..CRC_END_OFFSET].fill(0);

                // For displaying an error message in the description
                let mut error_message: &str = "";

                // On CRC error, lower confidence and report the checksum error
                // (have seen partially corrupted images that still extract Ok)
                if common::crc32(&cramfs_image) != cramfs_header.checksum {
                    error_message = " (checksum error)";
                    result.confidence = CONFIDENCE_MEDIUM;
                }

                result.description = format!(
                    "{}, {} endian, {} files, total size: {} bytes{}",
                    result.description,
                    cramfs_header.endianness,
                    cramfs_header.file_count,
                    cramfs_header.size,
                    error_message
                );
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store info about a CramFS header
#[derive(Default, Debug, Clone)]
pub struct CramFSHeader {
    pub size: usize,
    pub checksum: u32,
    pub file_count: usize,
    pub endianness: String,
}

/// Parses a CramFS header
pub fn parse_cramfs_header(cramfs_data: &[u8]) -> Result<CramFSHeader, StructureError> {
    // Endian specific magic bytes
    const BIG_ENDIAN_MAGIC: usize = 0x453DCD28;
    const LITTLE_ENDIAN_MAGIC: usize = 0x28CD3D45;

    let allowed_magics = [BIG_ENDIAN_MAGIC, LITTLE_ENDIAN_MAGIC];

    let cramfs_header_structure = vec![
        ("magic", "u32"),
        ("size", "u32"),
        ("flags", "u32"),
        ("future", "u32"),
        ("signature_p1", "u64"),
        ("signature_p2", "u64"),
        ("checksum", "u32"),
        ("edition", "u32"),
        ("block_count", "u32"),
        ("file_count", "u32"),
    ];

    let mut cramfs_info = CramFSHeader::default();

    let cramfs_structure_size = crate::structures::size(&cramfs_header_structure);

    // Default to little endian
    cramfs_info.endianness = "little".to_string();

    // Parse the CramFS header, try little endian first
    if let Ok(mut cramfs_header) = crate::structures::parse(
        cramfs_data,
        &cramfs_header_structure,
        &cramfs_info.endianness,
    ) {
        // Do the magic bytes match?
        if allowed_magics.contains(&cramfs_header["magic"]) {
            // If the magic bytes endianness don't match what's expected for little endian, switch to big endian
            if cramfs_header["magic"] == BIG_ENDIAN_MAGIC {
                cramfs_info.endianness = "big".to_string();

                // Parse the header again, this time as big endian
                match crate::structures::parse(
                    cramfs_data,
                    &cramfs_header_structure,
                    &cramfs_info.endianness,
                ) {
                    Err(_) => {
                        return Err(StructureError);
                    }
                    Ok(cramfs_be_header) => {
                        cramfs_header = cramfs_be_header.clone();
                    }
                }
            }

            // Reported image size must be larger than the header structure
            if cramfs_header["size"] > cramfs_structure_size {
                // Populate info about the CramFS image
                cramfs_info.size = cramfs_header["size"];
                cramfs_info.checksum = cramfs_header["checksum"] as u32;
                cramfs_info.file_count = cramfs_header["file_count"];

                return Ok(cramfs_info);
            }
        }
    }

    Err(StructureError)
}
