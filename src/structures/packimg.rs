use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store PackIMG header info
pub struct PackIMGHeader {
    pub header_size: usize,
    pub data_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct PackIMGHeaderBytes {
    magic: [u8; 12],
    padding: zerocopy::U32<LE>,
    data_size: zerocopy::U32<LE>,
}

/// Parse a PackIMG header
pub fn parse_packimg_header(packimg_data: &[u8]) -> Result<PackIMGHeader, StructureError> {
    // Fixed size header
    const PACKIMG_HEADER_SIZE: usize = 32;

    // Parse the packimg header
    let (packimg_header, _) =
        PackIMGHeaderBytes::ref_from_prefix(packimg_data).map_err(|_| StructureError)?;

    Ok(PackIMGHeader {
        header_size: PACKIMG_HEADER_SIZE,
        data_size: packimg_header.data_size.get() as usize,
    })
}
