use crate::common::crc32;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct XZHeader {
    magic_p1: zerocopy::U32<LE>,
    magic_p2: zerocopy::U16<LE>,
    flags: zerocopy::U16<LE>,
    header_crc: zerocopy::U32<LE>,
}

/// Parse and validate an XZ header, returns the header size
pub fn parse_xz_header(xz_data: &[u8]) -> Result<usize, StructureError> {
    const XZ_CRC_END: usize = 8;
    const XZ_CRC_START: usize = 6;
    const XZ_HEADER_SIZE: usize = 12;

    let (xz_header, _) = XZHeader::ref_from_prefix(xz_data).map_err(|_| StructureError)?;

    if let Some(crc_data) = xz_data.get(XZ_CRC_START..XZ_CRC_END)
        && xz_header.header_crc == crc32(crc_data)
    {
        return Ok(XZ_HEADER_SIZE);
    }

    Err(StructureError)
}
