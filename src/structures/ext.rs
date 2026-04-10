use crate::structures::common::StructureError;
use std::collections::HashMap;
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

    let allowed_rev_levels = [0, 1];
    let allowed_first_data_blocks = [0, 1];

    let supported_os = HashMap::from([
        (0, "Linux"),
        (1, "GNU HURD"),
        (2, "MASIX"),
        (3, "FreeBSD"),
        (4, "Lites"),
    ]);

    let mut ext_header = EXTHeader {
        ..Default::default()
    };

    // Sanity check the available data
    if ext_data.len() >= (SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE) {
        // Parse the EXT superblock structure
        let (ext_superblock, _) =
            EXTSuprtBlockBytes::ref_from_prefix(&ext_data[SUPERBLOCK_OFFSET..])
                .map_err(|_| StructureError)?;

        // Sanity check the reported OS this EXT image was created on
        if let Some(creator_os) = supported_os.get(&ext_superblock.creator_os.get()) {
            // Sanity check the s_rev_level field
            if allowed_rev_levels.contains(&ext_superblock.s_rev_level.get()) {
                // Sanity check the first_data_block field, which must be either 0 or 1
                if allowed_first_data_blocks.contains(&ext_superblock.first_data_block.get()) {
                    // Santiy check the log_block_size
                    if ext_superblock.log_block_size.get() <= MAX_BLOCK_LOG {
                        // Update the reported image info
                        ext_header.blocks_count = ext_superblock.blocks_count.get() as usize;
                        ext_header.inodes_count = ext_superblock.inodes_count.get() as usize;
                        ext_header.block_size = 1024 << ext_superblock.log_block_size.get();
                        ext_header.free_blocks_count =
                            ext_superblock.free_blocks_count.get() as usize;
                        ext_header.os = creator_os.to_string();
                        ext_header.reserved_blocks_count =
                            ext_superblock.reserved_blocks_count.get() as usize;
                        ext_header.image_size =
                            ext_header.block_size * (ext_superblock.blocks_count.get() as usize);

                        return Ok(ext_header);
                    }
                }
            }
        }
    }

    Err(StructureError)
}
