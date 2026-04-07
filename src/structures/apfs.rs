use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Offset of the APFS magic bytes from the start of the APFS image
pub const MAGIC_OFFSET: usize = 0x20;

/// Struct to store APFS header info
#[derive(Debug, Default, Clone)]
pub struct APFSHeader {
    pub block_size: usize,
    pub block_count: usize,
}

// Partial APFS header, just to figure out the size of the image and validate some fields
// https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct APFSHeaderBytes {
    magic: zerocopy::U32<LE>,
    block_size: zerocopy::U32<LE>,
    block_count: zerocopy::U64<LE>,
    nx_features: zerocopy::U64<LE>,
    nx_ro_compat_features: zerocopy::U64<LE>,
    nx_incompat_features: zerocopy::U64<LE>,
    nx_uuid_p1: zerocopy::U64<LE>,
    nx_uuid_p2: zerocopy::U64<LE>,
    nx_next_oid: zerocopy::U64<LE>,
    nx_next_xid: zerocopy::U64<LE>,
    nx_xp_desc_blocks: zerocopy::U32<LE>,
    nx_xp_data_blocks: zerocopy::U32<LE>,
    nx_xp_desc_base: zerocopy::U64<LE>,
    nx_xp_data_base: zerocopy::U64<LE>,
    nx_xp_desc_next: zerocopy::U32<LE>,
    nx_xp_data_next: zerocopy::U32<LE>,
    nx_xp_desc_index: zerocopy::U32<LE>,
    nx_xp_desc_len: zerocopy::U32<LE>,
    nx_xp_data_index: zerocopy::U32<LE>,
    nx_xp_data_len: zerocopy::U32<LE>,
    nx_spaceman_oid: zerocopy::U64<LE>,
    nx_omap_oid: zerocopy::U64<LE>,
    nx_reaper_oid: zerocopy::U64<LE>,
    nx_xp_test_type: zerocopy::U32<LE>,
    nx_xp_max_file_systems: zerocopy::U32<LE>,
}

/// Parses an APFS header
pub fn parse_apfs_header(apfs_data: &[u8]) -> Result<APFSHeader, StructureError> {
    const MAX_FS_COUNT: usize = 100;
    const FS_COUNT_BLOCK_SIZE: usize = 512;

    // Expected values of superblock flag fields
    let allowed_feature_flags = [0, 1, 2, 3];
    let allowed_incompat_flags = [0, 1, 2, 3, 0x100, 0x101, 0x102, 0x103];
    let allowed_ro_compat_flags = [0];

    let apfs_struct_start = MAGIC_OFFSET;
    let apfs_struct_end = apfs_struct_start + std::mem::size_of::<APFSHeaderBytes>();

    // Parse the header
    if let Some(apfs_structure_data) = apfs_data.get(apfs_struct_start..apfs_struct_end) {
        let (apfs_header, _) =
            APFSHeaderBytes::ref_from_prefix(apfs_structure_data).map_err(|_| StructureError)?;
        // Simple sanity check on the reported block data
        if apfs_header.block_size.get() != 0 && apfs_header.block_count.get() != 0 {
            // Sanity check the feature flags
            if allowed_feature_flags.contains(&apfs_header.nx_features.get())
                && allowed_ro_compat_flags.contains(&apfs_header.nx_ro_compat_features.get())
                && allowed_incompat_flags.contains(&apfs_header.nx_incompat_features.get())
            {
                // The test_type field *must* be NULL
                if apfs_header.nx_xp_test_type == 0 {
                    // Calculate the file system count; this is max_file_systems divided by 512, rounded up to nearest whole
                    let fs_count = ((apfs_header.nx_xp_max_file_systems.get() as f32)
                        / (FS_COUNT_BLOCK_SIZE as f32))
                        .ceil() as usize;

                    // Sanity check the file system count
                    if fs_count > 0 && fs_count <= MAX_FS_COUNT {
                        return Ok(APFSHeader {
                            block_size: apfs_header.block_size.get() as usize,
                            block_count: apfs_header.block_count.get() as usize,
                        });
                    }
                }
            }
        }
    }

    Err(StructureError)
}
