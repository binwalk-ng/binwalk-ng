use crate::signatures::{CONFIDENCE_LOW, SignatureError, SignatureResult};
use crate::structures::StructureError;

/// Human readable description
pub const DESCRIPTION: &str = "SEAMA firmware header";

/// SEAMA magic bytes, big and little endian
pub fn seama_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x5E\xA3\xA4\x17\x00\x00".to_vec(),
        b"\x17\xA4\xA3\x5E\x00\x00".to_vec(),
    ]
}

/// Validate SEAMA signatures
pub fn seama_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    // Parse the header
    if let Ok(seama_header) = parse_seama_header(&file_data[offset..]) {
        let total_size: usize = seama_header.header_size + seama_header.data_size;

        // Sanity check the reported size
        if file_data.len() >= (offset + total_size) {
            result.size = seama_header.header_size;
            result.description = format!(
                "{}, header size: {} bytes, data size: {} bytes",
                result.description, seama_header.header_size, seama_header.data_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store SEAMA firmware header data
pub struct SeamaHeader {
    pub data_size: usize,
    pub header_size: usize,
}

/// Parse a SEAMA firmware header
pub fn parse_seama_header(seama_data: &[u8]) -> Result<SeamaHeader, StructureError> {
    // SEAMA magic
    const MAGIC: usize = 0x5EA3A417;

    let seama_structure = vec![
        ("magic", "u32"),
        ("description_size", "u32"),
        ("data_size", "u32"),
        ("unknown1", "u64"),
        ("unknown2", "u64"),
    ];

    let available_data = seama_data.len();
    let header_size = crate::structures::size(&seama_structure);

    // Parse the header; try little endian first
    if let Ok(mut seama_header) = crate::structures::parse(seama_data, &seama_structure, "little") {
        // If the magic bytes don't match, switch to big endian
        if seama_header["magic"] != MAGIC {
            match crate::structures::parse(seama_data, &seama_structure, "big") {
                Err(_) => {
                    return Err(StructureError);
                }
                Ok(seama_header_be) => {
                    seama_header = seama_header_be;
                }
            }
        }

        // Sanity check on magic bytes
        if seama_header["magic"] == MAGIC {
            let total_header_size = header_size + seama_header["description_size"];

            // Sanity check on total header size
            if total_header_size >= header_size && available_data >= total_header_size {
                return Ok(SeamaHeader {
                    data_size: seama_header["data_size"],
                    header_size: total_header_size,
                });
            }
        }
    }

    Err(StructureError)
}
