use crate::common::{crc32, get_cstring};
use crate::structures::common::StructureError;
use std::collections::HashMap;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store JBOOT ARM firmware image info
#[derive(Debug, Default, Clone)]
pub struct JBOOTArmHeader {
    pub header_size: usize,
    pub data_size: usize,
    pub data_offset: usize,
    pub erase_offset: usize,
    pub erase_size: usize,
    pub rom_id: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ARMImageHeader {
    drange: zerocopy::U16<LE>,
    image_checksum: zerocopy::U16<LE>,
    block_size: zerocopy::U32<LE>,
    reserved1: [u8; 6],
    lpvs: u8,
    mbz: u8,
    timestamp: zerocopy::U32<LE>,
    erase_start: zerocopy::U32<LE>,
    erase_size: zerocopy::U32<LE>,
    data_start: zerocopy::U32<LE>,
    data_size: zerocopy::U32<LE>,
    reserved2: [u8; 16],
    header_id: zerocopy::U16<LE>,
    header_version: zerocopy::U16<LE>,
    reserved3: [u8; 2],
    section_id: u8,
    image_info_type: u8,
    image_info_offset: zerocopy::U32<LE>,
    family: zerocopy::U16<LE>,
    header_checksum: zerocopy::U16<LE>,
}

/// Parses a JBOOT ARM image header
pub fn parse_jboot_arm_header(jboot_data: &[u8]) -> Result<JBOOTArmHeader, StructureError> {
    // Structure starts after 12-byte ROM ID
    const STRUCTURE_OFFSET: usize = 12;

    // Some expected header values
    const LPVS_VALUE: u8 = 1;
    const MBZ_VALUE: u8 = 0;
    const HEADER_ID_VALUE: u16 = 0x4842;
    const HEADER_MAX_VERSION_VALUE: u16 = 4;

    let structure_size: usize = std::mem::size_of::<ARMImageHeader>();
    let header_size: usize = structure_size + STRUCTURE_OFFSET;

    if let Some(header_data) = jboot_data.get(STRUCTURE_OFFSET..) {
        // Parse the header structure
        let (arm_header, _) =
            ARMImageHeader::ref_from_prefix(header_data).map_err(|_| StructureError)?;

        // Make sure the reserved fields are NULL
        if arm_header
            .reserved1
            .iter()
            .chain(&arm_header.reserved2)
            .chain(&arm_header.reserved3)
            .all(|&b| b == 0)
        {
            // Sanity check expected header values
            if arm_header.lpvs == LPVS_VALUE
                && arm_header.mbz == MBZ_VALUE
                && arm_header.header_id == HEADER_ID_VALUE
                && arm_header.header_version <= HEADER_MAX_VERSION_VALUE
            {
                return Ok(JBOOTArmHeader {
                    header_size,
                    rom_id: get_cstring(&jboot_data[0..STRUCTURE_OFFSET]),
                    data_size: arm_header.data_size.get() as usize,
                    data_offset: arm_header.data_start.get() as usize,
                    erase_offset: arm_header.erase_start.get() as usize,
                    erase_size: arm_header.erase_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}

/// Stores info about JBOOT STAG headers
#[derive(Debug, Default, Clone)]
pub struct JBOOTStagHeader {
    pub header_size: usize,
    pub image_size: usize,
    pub is_factory_image: bool,
    pub is_sysupgrade_image: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct STag {
    cmark: u8,
    id: u8,
    magic: zerocopy::U16<LE>,
    timestamp: zerocopy::U32<LE>,
    image_size: zerocopy::U32<LE>,
    image_checksum: zerocopy::U16<LE>,
    header_checksum: zerocopy::U16<LE>,
}

/// Parses a JBOOT STAG header
pub fn parse_jboot_stag_header(jboot_data: &[u8]) -> Result<JBOOTStagHeader, StructureError> {
    // cmark value for factory images; for system upgrade images, cmark must equal id
    const FACTORY_IMAGE_TYPE: u8 = 0xFF;

    let mut result = JBOOTStagHeader::default();

    // Parse the header structure
    let (stag_header, _) = STag::ref_from_prefix(jboot_data).map_err(|_| StructureError)?;
    result.header_size = std::mem::size_of::<STag>();
    result.image_size = stag_header.image_size.get() as usize;

    if result.image_size > result.header_size {
        result.is_factory_image = stag_header.cmark == FACTORY_IMAGE_TYPE;
        result.is_sysupgrade_image = stag_header.cmark == stag_header.id;

        if result.is_factory_image || result.is_sysupgrade_image {
            return Ok(result);
        }
    }

    Err(StructureError)
}

#[derive(Default, Debug, Clone)]
pub struct JBOOTSchHeader {
    pub header_size: usize,
    pub compression: String,
    pub kernel_size: usize,
    pub kernel_entry_point: u32,
    pub kernel_checksum: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SCH2Header {
    magic: zerocopy::U16<LE>,
    compression_type: u8,
    version: u8,
    ram_entry_address: zerocopy::U32<LE>,
    kernel_image_size: zerocopy::U32<LE>,
    kernel_image_crc: zerocopy::U32<LE>,
    ram_start_address: zerocopy::U32<LE>,
    rootfs_flash_address: zerocopy::U32<LE>,
    rootfs_size: zerocopy::U32<LE>,
    rootfs_crc: zerocopy::U32<LE>,
    header_crc: zerocopy::U32<LE>,
    header_size: zerocopy::U16<LE>,
    cmd_line_size: zerocopy::U16<LE>,
}

/// Parses a JBOOT SCH2 header
pub fn parse_jboot_sch2_header(jboot_data: &[u8]) -> Result<JBOOTSchHeader, StructureError> {
    const VERSION_VALUE: u8 = 2;

    let compression_types = HashMap::from([(0, "none"), (1, "jz"), (2, "gzip"), (3, "lzma")]);

    let mut result = JBOOTSchHeader {
        header_size: std::mem::size_of::<SCH2Header>(),
        ..Default::default()
    };

    let (sch2_header, _) = SCH2Header::ref_from_prefix(jboot_data).map_err(|_| StructureError)?;

    // Sanity check some header fields
    if sch2_header.version == VERSION_VALUE
        && sch2_header.header_size.get() as usize == result.header_size
        && let Some(compression_type) = compression_types.get(&sch2_header.compression_type)
    {
        // Validate the header checksum
        if let Some(header_bytes) = jboot_data.get(0..sch2_header.header_size.get() as usize)
            && sch2_header.header_crc == sch2_header_crc(header_bytes)?
        {
            result.compression = compression_type.to_string();
            result.kernel_checksum = sch2_header.kernel_image_crc.get();
            result.kernel_size = sch2_header.kernel_image_size.get() as usize;
            result.kernel_entry_point = sch2_header.ram_entry_address.get();
            return Ok(result);
        }
    }

    Err(StructureError)
}

/// Calculate a JBOOT SCH2 header CRC
fn sch2_header_crc(sch2_header_bytes: &[u8]) -> Result<u32, StructureError> {
    // Start and end offsets of the header CRC field
    const HEADER_CRC_START: usize = 32;
    const HEADER_CRC_END: usize = 36;

    if sch2_header_bytes.len() > HEADER_CRC_END {
        let mut crc_data = sch2_header_bytes.to_vec();

        // Header CRC field has to be NULL'd out
        crc_data[HEADER_CRC_START..HEADER_CRC_END].fill(0);

        return Ok(crc32(&crc_data));
    }

    Err(StructureError)
}
