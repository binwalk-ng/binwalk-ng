use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Struct to store SHRS firmware header info
#[derive(Debug, Default, Clone)]
pub struct SHRSHeader {
    pub iv: Vec<u8>,
    pub data_size: u32,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SHRSHeaderBytes {
    magic: zerocopy::U32<BE>,
    unknown1: zerocopy::U32<BE>,
    encrypted_data_size: zerocopy::U32<BE>,
    iv: [u8; 16],
}

/// Parses an SHRS header
pub fn parse_shrs_header(shrs_data: &[u8]) -> Result<SHRSHeader, StructureError> {
    const HEADER_SIZE: usize = 0x6DC;

    // Parse the header
    let (shrs_header, _) =
        SHRSHeaderBytes::ref_from_prefix(shrs_data).map_err(|_| StructureError)?;

    Ok(SHRSHeader {
        iv: shrs_header.iv.to_vec(),
        data_size: shrs_header.encrypted_data_size.get(),
        header_size: HEADER_SIZE,
    })
}
