use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};
/// Struct to store WindowsCE header info
#[derive(Debug, Default, Clone)]
pub struct WinCEHeader {
    pub base_address: usize,
    pub image_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct WinCEHeaderBytes {
    magic: [u8; 7],
    image_start: zerocopy::U32<LE>,
    image_size: zerocopy::U32<LE>,
}

/// Parses a Windows CE header
pub fn parse_wince_header(wince_data: &[u8]) -> Result<WinCEHeader, StructureError> {
    // Parse the WinCE header
    let (wince_header, _) =
        WinCEHeaderBytes::ref_from_prefix(wince_data).map_err(|_| StructureError)?;

    Ok(WinCEHeader {
        base_address: wince_header.image_start.get() as usize,
        image_size: wince_header.image_size.get() as usize,
        header_size: std::mem::size_of::<WinCEHeaderBytes>(),
    })
}

/// Struct to store WindowsCE block info
#[derive(Debug, Default, Clone)]
pub struct WinCEBlock {
    pub address: usize,
    pub data_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct WinCEBlockHeaderBytes {
    address: zerocopy::U32<LE>,
    size: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
}

/// Parse a WindowsCE block header
pub fn parse_wince_block_header(block_data: &[u8]) -> Result<WinCEBlock, StructureError> {
    let (block_header, _) =
        WinCEBlockHeaderBytes::ref_from_prefix(block_data).map_err(|_| StructureError)?;
    Ok(WinCEBlock {
        address: block_header.address.get() as usize,
        data_size: block_header.size.get() as usize,
        header_size: std::mem::size_of::<WinCEBlockHeaderBytes>(),
    })
}
