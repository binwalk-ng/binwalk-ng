use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Stores info on a RAR archive
#[derive(Debug, Default, Clone)]
pub struct RarArchiveHeader {
    pub version: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RarHeaderBytes {
    magic: [u8; 6],
    version: u8,
}

/// Parse a RAR archive header
pub fn parse_rar_archive_header(rar_data: &[u8]) -> Result<RarArchiveHeader, StructureError> {
    let (archive_header, _) =
        RarHeaderBytes::ref_from_prefix(rar_data).map_err(|_| StructureError)?;

    // Make sure the version number is one of the known versions, version field of 0 indicates RARv4; version field of 1 indicates RARv5
    let version = match archive_header.version {
        0 => 4,
        1 => 5,
        _ => return Err(StructureError),
    };

    Ok(RarArchiveHeader { version })
}
