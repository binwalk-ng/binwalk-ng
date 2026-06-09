use crate::signatures::{CONFIDENCE_LOW, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SeamaHeaderBytes {
    magic: dyn_endian::U32,
    description_size: dyn_endian::U32,
    data_size: dyn_endian::U32,
    unknown: [u8; 16],
}

/// Parse a SEAMA firmware header
pub fn parse_seama_header(seama_data: &[u8]) -> Result<SeamaHeader, StructureError> {
    const MAGIC: u32 = 0x5EA3A417;
    const LITTLE_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Little);
    const BIG_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Big);

    let available_data = seama_data.len();
    let header_size = std::mem::size_of::<SeamaHeaderBytes>();

    // Parse the header
    let (seama_header, _) =
        SeamaHeaderBytes::ref_from_prefix(seama_data).map_err(|_| StructureError)?;

    let endianness = match seama_header.magic {
        LITTLE_ENDIAN_MAGIC => Endianness::Little,
        BIG_ENDIAN_MAGIC => Endianness::Big,
        _ => return Err(StructureError),
    };

    // Sanity check on magic bytes
    let total_header_size = header_size + seama_header.description_size.get(endianness) as usize;

    // Sanity check on total header size
    if total_header_size >= header_size && available_data >= total_header_size {
        return Ok(SeamaHeader {
            data_size: seama_header.data_size.get(endianness) as usize,
            header_size: total_header_size,
        });
    }

    Err(StructureError)
}
