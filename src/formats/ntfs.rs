use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "NTFS partition";

/// NTFS partitions start with these bytes
pub fn ntfs_magic() -> Vec<Vec<u8>> {
    vec![b"\xEb\x52\x90NTFS\x20\x20\x20\x20".to_vec()]
}

/// Validates the NTFS header
pub fn ntfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(ntfs_header) = parse_ntfs_header(&file_data[offset..]) {
        // The reported sector count does not include the NTFS boot sector itself
        let sector_size = ntfs_header.sector_size as usize;
        result.size = sector_size * (ntfs_header.sector_count as usize + 1);

        // Simple sanity check on the reported total size
        if result.size > sector_size {
            result.description = format!(
                "{}, number of sectors: {}, bytes per sector: {}, total size: {} bytes",
                result.description, ntfs_header.sector_count, ntfs_header.sector_size, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

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
