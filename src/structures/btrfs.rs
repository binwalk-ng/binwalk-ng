use crate::structures::common::StructureError;
use crc32c::crc32c;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store BTRFS super block info
#[derive(Debug, Default, Clone)]
pub struct BTRFSHeader {
    pub bytes_used: usize,
    pub total_size: usize,
    pub leaf_size: usize,
    pub node_size: usize,
    pub stripe_size: usize,
    pub sector_size: usize,
}

// Partial BTRFS superblock structure for obtaining image size and CRC validation
// https://archive.kernel.org/oldwiki/btrfs.wiki.kernel.org/index.php/On-disk_Format.html#Superblock
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BTRFSHeaderBytes {
    header_checksum: zerocopy::U32<LE>,
    unused1: [u8; 28],
    uuid_p1: zerocopy::U64<LE>,
    uuid_p2: zerocopy::U64<LE>,
    block_phys_addr: zerocopy::U64<LE>,
    flags: zerocopy::U64<LE>,
    magic: zerocopy::U64<LE>,
    generation: zerocopy::U64<LE>,
    root_tree_address: zerocopy::U64<LE>,
    chunk_tree_address: zerocopy::U64<LE>,
    log_tree_address: zerocopy::U64<LE>,
    log_root_transid: zerocopy::U64<LE>,
    total_bytes: zerocopy::U64<LE>,
    bytes_used: zerocopy::U64<LE>,
    root_dir_objid: zerocopy::U64<LE>,
    num_devices: zerocopy::U64<LE>,
    sector_size: zerocopy::U32<LE>,
    node_size: zerocopy::U32<LE>,
    leaf_size: zerocopy::U32<LE>,
    stripe_size: zerocopy::U32<LE>,
}

/// Parse and validate a BTRFS super block
pub fn parse_btrfs_header(btrfs_data: &[u8]) -> Result<BTRFSHeader, StructureError> {
    const SUPERBLOCK_OFFSET: usize = 0x10000;
    const SUPERBLOCK_END: usize = SUPERBLOCK_OFFSET + 0x1000;
    const CRC_START: usize = 0x20;

    // Parse the header
    if let Some(btrfs_header_data) = btrfs_data.get(SUPERBLOCK_OFFSET..SUPERBLOCK_END) {
        let (btrfs_header, _) =
            BTRFSHeaderBytes::ref_from_prefix(btrfs_header_data).map_err(|_| StructureError)?;

        // Validate the superblock CRC
        if btrfs_header.header_checksum == crc32c(&btrfs_header_data[CRC_START..]) {
            return Ok(BTRFSHeader {
                sector_size: btrfs_header.sector_size.get() as usize,
                node_size: btrfs_header.node_size.get() as usize,
                leaf_size: btrfs_header.leaf_size.get() as usize,
                stripe_size: btrfs_header.stripe_size.get() as usize,
                bytes_used: btrfs_header.bytes_used.get() as usize,
                total_size: btrfs_header.total_bytes.get() as usize,
            });
        }
    }

    Err(StructureError)
}
