use crate::common;
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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
                let mut error_message = "";

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
#[derive(Debug, Clone)]
pub struct CramFSHeader {
    pub size: usize,
    pub checksum: u32,
    pub file_count: usize,
    pub endianness: Endianness,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct CramFSHeaderBytes {
    magic: dyn_endian::U32,
    size: dyn_endian::U32,
    flags: dyn_endian::U32,
    future: dyn_endian::U32,
    signature: [u8; 16],
    checksum: dyn_endian::U32,
    edition: dyn_endian::U32,
    block_count: dyn_endian::U32,
    file_count: dyn_endian::U32,
}

/// Parses a CramFS header
pub fn parse_cramfs_header(cramfs_data: &[u8]) -> Result<CramFSHeader, StructureError> {
    const MAGIC: u32 = 0x28CD3D45;
    const LITTLE_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Little);
    const BIG_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Big);

    let cramfs_structure_size = std::mem::size_of::<CramFSHeaderBytes>();

    let (cramfs_header, _) =
        CramFSHeaderBytes::ref_from_prefix(cramfs_data).map_err(|_| StructureError)?;

    let endianness = match cramfs_header.magic {
        LITTLE_ENDIAN_MAGIC => Endianness::Little,
        BIG_ENDIAN_MAGIC => Endianness::Big,
        _ => return Err(StructureError),
    };

    // Reported image size must be larger than the header structure
    if cramfs_header.size.get(endianness) as usize > cramfs_structure_size {
        return Ok(CramFSHeader {
            size: cramfs_header.size.get(endianness) as usize,
            checksum: cramfs_header.checksum.get(endianness),
            file_count: cramfs_header.file_count.get(endianness) as usize,
            endianness,
        });
    }

    Err(StructureError)
}
