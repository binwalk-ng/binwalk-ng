use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Stores info about a TP-Link firmware header
#[derive(Debug, Default, Clone)]
pub struct TPLinkFirmwareHeader {
    pub header_size: usize,
    pub kernel_load_address: u32,
    pub kernel_entry_point: u32,
}

// https://github.com/jtreml/firmware-mod-kit/blob/master/src/tpl-tool/doc/Image_layout
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TPLinkHeader {
    product_id: zerocopy::U32<LE>,
    product_version: zerocopy::U32<LE>,
    reserved1: zerocopy::U32<LE>,
    image_checksum_p1: zerocopy::U64<LE>,
    image_checksum_p2: zerocopy::U64<LE>,
    reserved2: zerocopy::U32<LE>,
    kernel_checksum_p1: zerocopy::U64<LE>,
    kernel_checksum_p2: zerocopy::U64<LE>,
    reserved3: zerocopy::U32<LE>,
    kernel_load_address: zerocopy::U32<LE>,
    kernel_entry_point: zerocopy::U32<LE>,
    image_length: zerocopy::U32<LE>,
    kernel_offset: zerocopy::U32<LE>,
    kernel_length: zerocopy::U32<LE>,
    rootfs_offset: zerocopy::U32<LE>,
    rootfs_length: zerocopy::U32<LE>,
    bootloader_offset: zerocopy::U32<LE>,
    bootloader_length: zerocopy::U32<LE>,
    fw_version_major: zerocopy::U16<LE>,
    fw_version_minor: zerocopy::U16<LE>,
    fw_version_patch: zerocopy::U16<LE>,
    reserved4: zerocopy::U32<LE>,
}

/// Pase a TP-Link firmware header
pub fn parse_tplink_header(tplink_data: &[u8]) -> Result<TPLinkFirmwareHeader, StructureError> {
    // Offset of data structure, after firmware signature
    const STRUCTURE_OFFSET: usize = 0x40;

    // Total size of the firmware header
    const HEADER_SIZE: usize = 0x200;

    // Sanity check available data
    if tplink_data.len() >= HEADER_SIZE
        && let Some(structure_data) = tplink_data.get(STRUCTURE_OFFSET..)
    {
        // Parse the header
        let (tplink_header, _) =
            TPLinkHeader::ref_from_prefix(structure_data).map_err(|_| StructureError)?;

        // Make sure the reserved fields are NULL
        if tplink_header.reserved1 == 0
            && tplink_header.reserved2 == 0
            && tplink_header.reserved3 == 0
            && tplink_header.reserved4 == 0
        {
            // Unfortunately, most header fields aren't reliably used; these seem to be, so report them
            return Ok(TPLinkFirmwareHeader {
                header_size: HEADER_SIZE,
                kernel_entry_point: tplink_header.kernel_entry_point.get(),
                kernel_load_address: tplink_header.kernel_load_address.get(),
            });
        }
    }

    Err(StructureError)
}

/// Stores info about a TP-Link RTOS firmware header
#[derive(Debug, Default, Clone)]
pub struct TPLinkRTOSFirmwareHeader {
    pub header_size: usize,
    pub total_size: u32,
    pub model_number: u16,
    pub hardware_rev_major: u8,
    pub hardware_rev_minor: u8,
}

// https://github.com/jtreml/firmware-mod-kit/blob/master/src/tpl-tool/doc/Image_layout
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TPLinkRTOSHeader {
    magic1: zerocopy::U32<BE>,
    unknown1: zerocopy::U64<BE>,
    unknown2: zerocopy::U64<BE>,
    magic2: zerocopy::U32<BE>,
    data_size: zerocopy::U32<BE>,
    model_number: zerocopy::U16<BE>,
    hardware_revision_major: u8,
    hardware_revision_minor: u8,
}

/// Parse a TP-Link RTOS firmware header
pub fn parse_tplink_rtos_header(
    tplink_data: &[u8],
) -> Result<TPLinkRTOSFirmwareHeader, StructureError> {
    const HEADER_SIZE: usize = 0x94;
    const MAGIC2_VALUE: u32 = 0x494D4730;
    const TOTAL_SIZE_OFFSET: u32 = 20;

    let (header, _) = TPLinkRTOSHeader::ref_from_prefix(tplink_data).map_err(|_| StructureError)?;

    if header.magic2.get() != MAGIC2_VALUE {
        return Err(StructureError);
    }

    Ok(TPLinkRTOSFirmwareHeader {
        header_size: HEADER_SIZE,
        total_size: header.data_size.get() + TOTAL_SIZE_OFFSET,
        model_number: header.model_number.get(),
        hardware_rev_major: header.hardware_revision_major,
        hardware_rev_minor: header.hardware_revision_minor,
    })
}
