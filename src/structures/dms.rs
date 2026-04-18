use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Struct to store DMS header info
#[derive(Debug, Default, Clone)]
pub struct DMSHeader {
    pub image_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DMSHeaderBytes {
    unknown1: zerocopy::U16<BE>,
    magic_p1: zerocopy::U16<BE>,
    magic_p2: zerocopy::U32<BE>,
    unknown2: zerocopy::U32<BE>,
    image_size: zerocopy::U32<BE>,
}

/// Parses a DMS header
pub fn parse_dms_header(dms_data: &[u8]) -> Result<DMSHeader, StructureError> {
    const MAGIC_P1: u16 = 0x4D47;
    const MAGIC_P2: u32 = 0x3C31303E;

    // Parse the first half of the header
    let (dms_header, _) = DMSHeaderBytes::ref_from_prefix(dms_data).map_err(|_| StructureError)?;
    if dms_header.magic_p1 == MAGIC_P1 && dms_header.magic_p2 == MAGIC_P2 {
        return Ok(DMSHeader {
            image_size: dms_header.image_size.get() as usize,
        });
    }

    Err(StructureError)
}
