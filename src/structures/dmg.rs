use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};
/// Struct to store DMG footer info
#[derive(Debug, Default, Clone)]
pub struct DMGFooter {
    pub footer_size: usize,
    pub data_length: usize,
    pub xml_length: usize,
}

// https://newosxbook.com/DMG.html
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DMGFooterBytes {
    magic: zerocopy::U32<BE>,
    version: zerocopy::U32<BE>,
    header_size: zerocopy::U32<BE>,
    flags: zerocopy::U32<BE>,
    running_data_fork_offset: zerocopy::U64<BE>,
    data_fork_offset: zerocopy::U64<BE>,
    data_fork_length: zerocopy::U64<BE>,
    rsrc_fork_offset: zerocopy::U64<BE>,
    rsrc_fork_length: zerocopy::U64<BE>,
    segment_number: zerocopy::U32<BE>,
    segment_count: zerocopy::U32<BE>,
    segment_id_p1: zerocopy::U64<BE>,
    segment_id_p2: zerocopy::U64<BE>,
    data_checksum_type: zerocopy::U32<BE>,
    data_checksum_size: zerocopy::U32<BE>,
    data_checksum: [u8; 128],
    xml_offset: zerocopy::U64<BE>,
    xml_length: zerocopy::U64<BE>,
    reserved: [u8; 120],
    checksum_type: zerocopy::U32<BE>,
    checksum_size: zerocopy::U32<BE>,
    checksum: [u8; 128],
    image_variant: zerocopy::U32<BE>,
    sector_count: zerocopy::U64<BE>,
    reserved_1: [u8; 12],
}

/// Parses a DMG footer structure
pub fn parse_dmg_footer(dmg_data: &[u8]) -> Result<DMGFooter, StructureError> {
    let structure_size: usize = std::mem::size_of::<DMGFooterBytes>();

    // Parse the DMG footer
    let (dmg_footer, _) = DMGFooterBytes::ref_from_prefix(dmg_data).map_err(|_| StructureError)?;
    // Sanity check, make sure the reported header size is the size of this structure
    if dmg_footer.header_size.get() as usize == structure_size {
        return Ok(DMGFooter {
            data_length: dmg_footer.data_fork_length.get() as usize,
            xml_length: dmg_footer.xml_length.get() as usize,
            footer_size: structure_size,
        });
    }

    Err(StructureError)
}
