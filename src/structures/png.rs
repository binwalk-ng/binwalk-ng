use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Stores info on a PNG chunk header
pub struct PNGChunkHeader {
    pub total_size: usize,
    pub is_last_chunk: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct PNGChunkBytes {
    length: zerocopy::U32<BE>,
    chunk_type: zerocopy::U32<BE>,
}

/// Parse a PNG chunk header
pub fn parse_png_chunk_header(chunk_data: &[u8]) -> Result<PNGChunkHeader, StructureError> {
    // All PNG chunks are followed by a 4-byte CRC
    const CRC_SIZE: usize = 4;

    // The "IEND" chunk is the last chunk in the PNG
    const IEND_CHUNK_TYPE: u32 = 0x49454E44;

    let chunk_structure_size: usize = std::mem::size_of::<PNGChunkBytes>();

    // Parse the chunk header
    let (chunk_header, _) =
        PNGChunkBytes::ref_from_prefix(chunk_data).map_err(|_| StructureError)?;
    Ok(PNGChunkHeader {
        is_last_chunk: chunk_header.chunk_type == IEND_CHUNK_TYPE,
        total_size: chunk_structure_size + chunk_header.length.get() as usize + CRC_SIZE,
    })
}
