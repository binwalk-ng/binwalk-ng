use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "TP-Link firmware header";

/// TP-Link firmware headers start with these bytes
pub fn tplink_magic() -> Vec<Vec<u8>> {
    vec![b"\x01\x00\x00\x00TP-LINK Technologies\x00\x00\x00\x00ver. 1.0".to_vec()]
}

/// Validates the TP-Link header
pub fn tplink_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Parse the header
    if let Ok(tplink_header) = parse_tplink_header(&file_data[offset..]) {
        // Fill in size and description
        result.size = tplink_header.header_size;
        result.description = format!(
            "{}, kernel load address: {:#X}, kernel entry point: {:#X}, header size: {} bytes",
            result.description,
            tplink_header.kernel_load_address,
            tplink_header.kernel_entry_point,
            tplink_header.header_size
        );

        return Ok(result);
    }

    Err(SignatureError)
}

/// Human readable description
pub const RTOS_DESCRIPTION: &str = "TP-Link RTOS firmware";

/// TP-Link RTOS firmware start with these magic bytes
pub fn tplink_rtos_magic() -> Vec<Vec<u8>> {
    vec![b"\x00\x14\x2F\xC0".to_vec()]
}

/// Parse and validate TP-Link RTOS firmware header
pub fn tplink_rtos_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: RTOS_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(fw_header) = parse_tplink_rtos_header(&file_data[offset..]) {
        result.description = format!(
            "{}, model number: {:X}, hardware version: {:X}.{:X}, header size: {} bytes, total size: {} bytes",
            result.description,
            fw_header.model_number,
            fw_header.hardware_rev_major,
            fw_header.hardware_rev_minor,
            fw_header.header_size,
            fw_header.total_size,
        );
        return Ok(result);
    }

    Err(SignatureError)
}

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
