use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Offset of the LogFS magic bytes from the start of the file system
pub const LOGFS_MAGIC_OFFSET: usize = 0x18;

/// Struct to store LogFS info
#[derive(Debug, Default, Clone)]
pub struct LogFSSuperBlock {
    pub total_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LogFSSBBytes {
    magic: zerocopy::U64<BE>,
    crc32: zerocopy::U32<BE>,
    ifile_levels: u8,
    iblock_levels: u8,
    data_levels: u8,
    segment_shift: u8,
    block_shift: u8,
    write_shift: u8,
    pad: [u8; 6],
    filesystem_size: zerocopy::U64<BE>,
    segment_size: zerocopy::U32<BE>,
    bad_seg_reserved: zerocopy::U32<BE>,
    feature_incompat: zerocopy::U64<BE>,
    feature_ro_compat: zerocopy::U64<BE>,
    feature_compat: zerocopy::U64<BE>,
    feature_flags: zerocopy::U64<BE>,
    root_reserve: zerocopy::U64<BE>,
    speed_reserve: zerocopy::U64<BE>,
}

/// Parses a LogFS superblock
pub fn parse_logfs_super_block(logfs_data: &[u8]) -> Result<LogFSSuperBlock, StructureError> {
    if let Some(sb_struct_data) = logfs_data.get(LOGFS_MAGIC_OFFSET..) {
        let (super_block, _) =
            LogFSSBBytes::ref_from_prefix(sb_struct_data).map_err(|_| StructureError)?;

        if super_block.pad.iter().all(|&b| b == 0) {
            return Ok(LogFSSuperBlock {
                total_size: super_block.filesystem_size.get() as usize,
            });
        }
    }

    Err(StructureError)
}
