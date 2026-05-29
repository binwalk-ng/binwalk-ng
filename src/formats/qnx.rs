use crate::signatures::{SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const IFS_DESCRIPTION: &str = "QNX IFS image";

/// QNX IFS magic bytes
pub fn qnx_ifs_magic() -> Vec<Vec<u8>> {
    /*
     * Assumes little endian.
     * Includes the magic bytes (u32) and version number (u16), which must be 1.
     */
    vec![b"\xEB\x7E\xFF\x00\x01\x00".to_vec()]
}

/// Validate a QNX IFS signature
pub fn qnx_ifs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: IFS_DESCRIPTION.to_string(),
        ..Default::default()
    };

    let available_data: usize = file_data.len() - offset;

    if let Ok(ifs_header) = parse_ifs_header(&file_data[offset..]) {
        // Set the total size of this signature
        result.size = ifs_header.total_size;

        // Sanity check that the total size doesn't exceed the available data size
        if result.size <= available_data {
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores info on a QNX IFS header
pub struct IFSHeader {
    pub total_size: usize,
}

// https://github.com/askac/dumpifs/blob/master/sys/startup.h
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct IFSHeaderBytes {
    magic: zerocopy::U32<LE>,
    version: zerocopy::U16<LE>,
    flags1: u8,
    flags2: u8,
    header_size: zerocopy::U16<LE>,
    machine: zerocopy::U16<LE>,
    startup_vaddr: zerocopy::U32<LE>,
    paddr_bias: zerocopy::U32<LE>,
    image_paddr: zerocopy::U32<LE>,
    ram_paddr: zerocopy::U32<LE>,
    ram_size: zerocopy::U32<LE>,
    startup_size: zerocopy::U32<LE>,
    stored_size: zerocopy::U32<LE>,
    imagefs_paddr: zerocopy::U32<LE>,
    imagefs_size: zerocopy::U32<LE>,
    preboot_size: zerocopy::U16<LE>,
    zeros: [u8; 14],
}

/// Parse a QNX IFS header
pub fn parse_ifs_header(ifs_data: &[u8]) -> Result<IFSHeader, StructureError> {
    // Parse the IFS header
    let (ifs_header, _) = IFSHeaderBytes::ref_from_prefix(ifs_data).map_err(|_| StructureError)?;
    // The flags2 field is unused and should be 0
    if ifs_header.flags2 == 0 {
        // Verify that all the zero fields are, in fact, zero
        if ifs_header.zeros.iter().all(|&b| b == 0) {
            return Ok(IFSHeader {
                total_size: ifs_header.stored_size.get() as usize,
            });
        }
    }

    Err(StructureError)
}
