use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store RTK firmware header info
#[derive(Debug, Default, Clone)]
pub struct RTKHeader {
    pub image_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RTKHeaderBytes {
    magic: zerocopy::U32<LE>,
    image_size: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
    unknown1: [u8; 4],
    header_size: zerocopy::U32<LE>,
    unknown2: [u8; 8],
    identifier: zerocopy::U32<LE>,
}

/// Parses a RTK header
pub fn parse_rtk_header(rtk_data: &[u8]) -> Result<RTKHeader, StructureError> {
    const MAGIC_SIZE: usize = 4;

    // Parse the header
    let (rtk_header, _) = RTKHeaderBytes::ref_from_prefix(rtk_data).map_err(|_| StructureError)?;

    Ok(RTKHeader {
        image_size: rtk_header.image_size.get() as usize,
        header_size: rtk_header.header_size.get() as usize + MAGIC_SIZE,
    })
}
