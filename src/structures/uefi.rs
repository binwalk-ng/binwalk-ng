use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Stores info about a UEFI volume header
#[derive(Debug, Default, Clone)]
pub struct UEFIVolumeHeader {
    pub header_crc: u16,
    pub header_size: usize,
    pub volume_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UEFIPiHeader {
    volume_size: zerocopy::U64<LE>,
    magic: zerocopy::U32<LE>,
    attributes: zerocopy::U32<LE>,
    header_size: zerocopy::U16<LE>,
    header_crc: zerocopy::U16<LE>,
    extended_header_offset: zerocopy::U16<LE>,
    reserved: u8,
    revision: u8,
}

/// Parse a UEFI volume header
pub fn parse_uefi_volume_header(uefi_data: &[u8]) -> Result<UEFIVolumeHeader, StructureError> {
    // The revision field must be 1 or 2
    let valid_revisions: Vec<u8> = vec![1, 2];

    // Parse the volume header
    let (uefi_volume_header, _) =
        UEFIPiHeader::ref_from_prefix(uefi_data).map_err(|_| StructureError)?;
    // Make sure the header size is sane (must be smaller than the total volume size)
    if (uefi_volume_header.header_size.get() as u64) < uefi_volume_header.volume_size.get() {
        // The reserved field *must* be 0
        if uefi_volume_header.reserved == 0 {
            // The revision number must be 1 or 2
            if valid_revisions.contains(&uefi_volume_header.revision) {
                return Ok(UEFIVolumeHeader {
                    // TODO: Validate UEFI header CRC
                    header_crc: uefi_volume_header.header_crc.get(),
                    header_size: uefi_volume_header.header_size.get() as usize,
                    volume_size: uefi_volume_header.volume_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}

/// Stores info about a UEFI capsule header
#[derive(Debug, Default, Clone)]
pub struct UEFICapsuleHeader {
    pub total_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UEFICapsuleHeaderBytes {
    guid_p1: zerocopy::U64<LE>,
    guid_p2: zerocopy::U64<LE>,
    header_size: zerocopy::U32<LE>,
    flags: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
}

/// Parse  UEFI capsule header
pub fn parse_uefi_capsule_header(uefi_data: &[u8]) -> Result<UEFICapsuleHeader, StructureError> {
    // Parse the capsule header
    let (capsule_header, _) =
        UEFICapsuleHeaderBytes::ref_from_prefix(uefi_data).map_err(|_| StructureError)?;

    // Sanity check on header and total size fields
    if capsule_header.header_size.get() < capsule_header.total_size.get() {
        return Ok(UEFICapsuleHeader {
            total_size: capsule_header.total_size.get() as usize,
            header_size: capsule_header.header_size.get() as usize,
        });
    }

    Err(StructureError)
}
