use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

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
