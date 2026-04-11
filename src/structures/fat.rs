use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store FAT header info
#[derive(Debug, Default, Clone)]
pub struct FATHeader {
    pub is_fat32: bool,
    pub total_size: usize,
}

// http://elm-chan.org/docs/fat_e.html
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FATBootSectorBytes {
    opcode1: u8,
    opcode2: u8,
    opcode3: u8,
    oem_name: zerocopy::U64<LE>,
    bytes_per_sector: zerocopy::U16<LE>,
    sectors_per_cluster: u8,
    reserved_sectors: zerocopy::U16<LE>,
    fat_count: u8,
    root_entries_count_16: zerocopy::U16<LE>,
    total_sectors_16: zerocopy::U16<LE>,
    media_type: u8,
    fat_size_16: zerocopy::U16<LE>,
    sectors_per_track: zerocopy::U16<LE>,
    number_of_heads: zerocopy::U16<LE>,
    hidden_sectors: zerocopy::U32<LE>,
    total_sectors_32: zerocopy::U32<LE>,
}

/// Parses a FAT header
pub fn parse_fat_header(fat_data: &[u8]) -> Result<FATHeader, StructureError> {
    // Number of FATs could technically be 1 or greater, but *should* be 2
    const EXPECTED_FAT_COUNT: u8 = 2;

    let valid_opcode1 = [0xEB, 0xE9];
    let valid_sector_sizes = [512, 1024, 2048, 4096];
    let valid_sectors_per_cluster = [1, 2, 4, 8, 16, 32, 64, 128];
    let valid_media_types = [0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE];

    // Return value
    let mut result = FATHeader::default();

    // Parse the boot sector header

    let (bs_header, _) =
        FATBootSectorBytes::ref_from_prefix(fat_data).map_err(|_| StructureError)?;
    // Sanity check the first opcode, reported sector size, reported sectors per cluster
    if valid_opcode1.contains(&bs_header.opcode1)
        && valid_sector_sizes.contains(&bs_header.bytes_per_sector.get())
        && valid_sectors_per_cluster.contains(&bs_header.sectors_per_cluster)
    {
        // Reserved sectors must be at least 1
        if bs_header.reserved_sectors > 0 {
            // Sanity check the reported number of FATs, reported media type
            if bs_header.fat_count == EXPECTED_FAT_COUNT
                && valid_media_types.contains(&bs_header.media_type)
            {
                // This field is set to 0 for FAT32, but populated by FAT12/16
                result.is_fat32 = bs_header.fat_size_16 == 0;

                // total_sectors_16 is used for FAT12/16 that have less than 0x10000 sectors
                if bs_header.total_sectors_16 != 0 {
                    result.total_size = (bs_header.total_sectors_16.get() as usize)
                        * (bs_header.bytes_per_sector.get() as usize);
                // Else, total_sectors_32 is used to define the number of sectors
                } else {
                    result.total_size = (bs_header.total_sectors_32.get() as usize)
                        * (bs_header.bytes_per_sector.get() as usize);
                }

                // If both total_sectors_32 and total_sectors_16 is 0, this is not a valid FAT
                if result.total_size > 0 {
                    return Ok(result);
                }
            }
        }
    }

    Err(StructureError)
}
