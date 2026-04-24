use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Expected size of an EXT superblock
pub const SUPERBLOCK_SIZE: usize = 1024;

/// Expected file offset of an EXT superblock
pub const SUPERBLOCK_OFFSET: usize = 1024;

/// Struct to store some useful EXT info
#[derive(Debug, Default, Clone)]
pub struct EXTHeader {
    pub os: String,
    pub block_size: usize,
    pub image_size: usize,
    pub blocks_count: usize,
    pub inodes_count: usize,
    pub free_blocks_count: usize,
    pub reserved_blocks_count: usize,
}

// Partial superblock structure, just enough for validation and size calculation
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EXTSuprtBlockBytes {
    inodes_count: zerocopy::U32<LE>,
    blocks_count: zerocopy::U32<LE>,
    reserved_blocks_count: zerocopy::U32<LE>,
    free_blocks_count: zerocopy::U32<LE>,
    free_inodes_count: zerocopy::U32<LE>,
    first_data_block: zerocopy::U32<LE>,
    log_block_size: zerocopy::U32<LE>,
    log_frag_size: zerocopy::U32<LE>,
    blocks_per_group: zerocopy::U32<LE>,
    frags_per_group: zerocopy::U32<LE>,
    inodes_per_group: zerocopy::U32<LE>,
    modification_time: zerocopy::U32<LE>,
    write_time: zerocopy::U32<LE>,
    mount_count: zerocopy::U16<LE>,
    max_mount_count: zerocopy::U16<LE>,
    magic: zerocopy::U16<LE>,
    state: zerocopy::U16<LE>,
    errors: zerocopy::U16<LE>,
    s_minor_rev_level: zerocopy::U16<LE>,
    last_check: zerocopy::U32<LE>,
    check_interval: zerocopy::U32<LE>,
    creator_os: zerocopy::U32<LE>,
    s_rev_level: zerocopy::U32<LE>,
    resuid: zerocopy::U16<LE>,
    resgid: zerocopy::U16<LE>,
}

/// Partially parses an EXT superblock structure
pub fn parse_ext_header(ext_data: &[u8]) -> Result<EXTHeader, StructureError> {
    // Max value of the EXT log block size
    const MAX_BLOCK_LOG: u32 = 2;

    const ALLOWED_REV_LEVELS: [u32; 2] = [0, 1];
    const ALLOWED_FIRST_DATA_BLOCKS: [u32; 2] = [0, 1];

    // Sanity check the available data
    if ext_data.len() >= (SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE) {
        // Parse the EXT superblock structure
        let (ext_superblock, _) =
            EXTSuprtBlockBytes::ref_from_prefix(&ext_data[SUPERBLOCK_OFFSET..])
                .map_err(|_| StructureError)?;

        // Sanity check the reported OS this EXT image was created on
        let creator_os = match ext_superblock.creator_os.get() {
            0 => "Linux",
            1 => "GNU HURD",
            2 => "MASIX",
            3 => "FreeBSD",
            4 => "Lites",
            _ => return Err(StructureError),
        };
        // Sanity check the s_rev_level field
        if ALLOWED_REV_LEVELS.contains(&ext_superblock.s_rev_level.get()) {
            // Sanity check the first_data_block field, which must be either 0 or 1
            if ALLOWED_FIRST_DATA_BLOCKS.contains(&ext_superblock.first_data_block.get()) {
                // Santiy check the log_block_size
                if ext_superblock.log_block_size.get() <= MAX_BLOCK_LOG {
                    let block_size = 1024 << ext_superblock.log_block_size.get();
                    return Ok(EXTHeader {
                        os: creator_os.to_string(),
                        block_size,
                        image_size: block_size * (ext_superblock.blocks_count.get() as usize),
                        blocks_count: ext_superblock.blocks_count.get() as usize,
                        inodes_count: ext_superblock.inodes_count.get() as usize,
                        free_blocks_count: ext_superblock.free_blocks_count.get() as usize,
                        reserved_blocks_count: ext_superblock.reserved_blocks_count.get() as usize,
                    });
                }
            }
        }
    }

    Err(StructureError)
}
