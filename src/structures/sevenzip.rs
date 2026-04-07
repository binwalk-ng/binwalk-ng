use crate::common::crc32;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store 7zip header info
#[derive(Debug, Default, Clone)]
pub struct SevenZipHeader {
    pub header_size: usize,
    pub major_version: u8,
    pub minor_version: u8,
    pub next_header_crc: u32,
    pub next_header_size: usize,
    pub next_header_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SevenZipHeaderBytes {
    magic_p1: zerocopy::U16<LE>,
    magic_p2: zerocopy::U32<LE>,
    major_version: u8,
    minor_version: u8,
    header_crc: zerocopy::U32<LE>,
    next_header_offset: zerocopy::U64<LE>,
    next_header_size: zerocopy::U64<LE>,
    next_header_crc: zerocopy::U32<LE>,
}

/// Parse a 7zip header
pub fn parse_7z_header(sevenzip_data: &[u8]) -> Result<SevenZipHeader, StructureError> {
    // Offset & size constants
    const SEVENZIP_CRC_START: usize = 12;
    const SEVENZIP_HEADER_SIZE: usize = 32;

    // Parse the 7zip header
    let (sevenzip_header, _) =
        SevenZipHeaderBytes::ref_from_prefix(sevenzip_data).map_err(|_| StructureError)?;
    // Validate header CRC, which is calculated over the 'next_header_offset', 'next_header_size', and 'next_header_crc' values
    if let Some(crc_data) = sevenzip_data.get(SEVENZIP_CRC_START..SEVENZIP_HEADER_SIZE)
        && crc32(crc_data) == sevenzip_header.header_crc.get()
    {
        return Ok(SevenZipHeader {
            header_size: SEVENZIP_HEADER_SIZE,
            major_version: sevenzip_header.major_version,
            minor_version: sevenzip_header.minor_version,
            next_header_crc: sevenzip_header.next_header_crc.get(),
            next_header_size: sevenzip_header.next_header_size.get() as usize,
            next_header_offset: sevenzip_header.next_header_offset.get() as usize,
        });
    }

    Err(StructureError)
}
