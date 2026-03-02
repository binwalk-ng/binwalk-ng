use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};
/// Struct to store NTFS info
#[derive(Debug, Default, Clone)]
pub struct NTFSPartition {
    pub sector_size: u16,
    pub sector_count: u64,
}

// https://en.wikipedia.org/wiki/NTFS
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct NtfsPartitionHeader {
    opcodes: [u8; 3],
    magic: zerocopy::U64<LE>,
    bytes_per_sector: zerocopy::U16<LE>,
    sectors_per_cluster: u8,
    unused1: [u8; 7],
    media_type: u8,
    unused2: [u8; 2],
    sectors_per_track: zerocopy::U16<LE>,
    head_count: zerocopy::U16<LE>,
    hidden_sector_count: zerocopy::U32<LE>,
    unused3: [u8; 4],
    unknown: [u8; 4],
    sector_count: zerocopy::U64<LE>,
}

/// Parses an NTFS partition header
pub fn parse_ntfs_header(ntfs_data: &[u8]) -> Result<NTFSPartition, StructureError> {
    // Parse the NTFS partition header
    let (ntfs_header, _) =
        NtfsPartitionHeader::ref_from_prefix(ntfs_data).map_err(|_| StructureError)?;

    // Sanity check to make sure the unused fields are not used
    if ntfs_header
        .unused1
        .iter()
        .chain(&ntfs_header.unused2)
        .chain(&ntfs_header.unused3)
        .all(|&b| b == 0)
    {
        return Ok(NTFSPartition {
            sector_count: ntfs_header.sector_count.get(),
            sector_size: ntfs_header.bytes_per_sector.get(),
        });
    }

    Err(StructureError)
}
