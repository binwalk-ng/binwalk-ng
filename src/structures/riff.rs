use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store info from a RIFF header
pub struct RIFFHeader {
    pub size: usize,
    pub chunk_type: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RIFFHeaderBytes {
    magic: zerocopy::U32<LE>,
    file_size: zerocopy::U32<LE>,
    chunk_type: zerocopy::U32<LE>,
}

/// Parse a RIFF image header
pub fn parse_riff_header(riff_data: &[u8]) -> Result<RIFFHeader, StructureError> {
    const MAGIC: u32 = 0x46464952;

    const CHUNK_TYPE_START: usize = 8;
    const CHUNK_TYPE_END: usize = 12;

    const FILE_SIZE_OFFSET: usize = 8;

    let (riff_header, _) =
        RIFFHeaderBytes::ref_from_prefix(riff_data).map_err(|_| StructureError)?;
    if riff_header.magic == MAGIC
        && let Ok(type_string) = // Get the RIFF type string (e.g., "WAVE")
            String::from_utf8(riff_data[CHUNK_TYPE_START..CHUNK_TYPE_END].to_vec())
    {
        return Ok(RIFFHeader {
            size: riff_header.file_size.get() as usize + FILE_SIZE_OFFSET,
            chunk_type: type_string.trim().to_string(),
        });
    }

    Err(StructureError)
}
