use crate::common::get_cstring;
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "DKBS firmware header";

/// DKBS firmware magic
pub fn dkbs_magic() -> Vec<Vec<u8>> {
    vec![b"_dkbs_".to_vec()]
}

/// Validates the DKBS header
pub fn dkbs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MAGIC_OFFSET: usize = 7;

    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Sanity check the magic bytes offset
    if offset >= MAGIC_OFFSET {
        // Magic bytes occur 7 bytes into the actual firmware header
        result.offset = offset - MAGIC_OFFSET;

        // Parse the firmware header
        if let Ok(dkbs_header) = parse_dkbs_header(&file_data[result.offset..]) {
            // Calculate the total bytes available after the firmware header
            let available_data: usize = file_data.len() - result.offset;

            // Sanity check on the total reported DKBS firmware size
            if available_data >= (dkbs_header.header_size + dkbs_header.data_size) {
                // If this header starts at the beginning of the file, confidence is high
                if result.offset == 0 {
                    result.confidence = CONFIDENCE_HIGH;
                }

                // Report header size and description
                result.size = dkbs_header.header_size;
                result.description = format!(
                    "{}, board ID: {}, firmware version: {}, boot device: {}, endianness: {}, header size: {} bytes, data size: {}",
                    result.description,
                    dkbs_header.board_id,
                    dkbs_header.version,
                    dkbs_header.boot_device,
                    dkbs_header.endianness,
                    dkbs_header.header_size,
                    dkbs_header.data_size
                );

                // Return OK
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store DKBS header info
#[derive(Debug, Clone)]
pub struct DKBSHeader {
    pub data_size: usize,
    pub header_size: usize,
    pub board_id: String,
    pub version: String,
    pub boot_device: String,
    pub endianness: Endianness,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DataSizeField {
    size: dyn_endian::U32,
}

/// Parses a DKBS header
pub fn parse_dkbs_header(dkbs_data: &[u8]) -> Result<DKBSHeader, StructureError> {
    // Header is a fixed size
    const HEADER_SIZE: usize = 0xA0;

    // Constant offsets for strings and known header fields
    const BOARD_ID_START: usize = 0;
    const BOARD_ID_END: usize = 0x20;
    const VERSION_START: usize = 0x28;
    const VERSION_END: usize = 0x48;
    const BOOT_DEVICE_START: usize = 0x70;
    const BOOT_DEVICE_END: usize = 0x90;
    const DATA_SIZE_START: usize = 0x68;
    const DATA_SIZE_END: usize = DATA_SIZE_START + 4;

    // Available data should be at least big enough for the header to fit
    if dkbs_data.len() >= HEADER_SIZE {
        // Parse the version, board ID, and boot device strings
        let version = get_cstring(&dkbs_data[VERSION_START..VERSION_END]);
        let board_id = get_cstring(&dkbs_data[BOARD_ID_START..BOARD_ID_END]);
        let boot_device = get_cstring(&dkbs_data[BOOT_DEVICE_START..BOOT_DEVICE_END]);

        // Sanity check to make sure the strings were retrieved
        if !version.is_empty()
            && !board_id.is_empty()
            && !boot_device.is_empty()
            && let Some(data_size_bytes) = dkbs_data.get(DATA_SIZE_START..DATA_SIZE_END)
        {
            // Parse the payload size field
            let data_size =
                DataSizeField::ref_from_bytes(data_size_bytes).map_err(|_| StructureError)?;

            let endianness = match data_size.size.get(Endianness::Big) & 0xFF000000 {
                0 => Endianness::Big,
                _ => Endianness::Little,
            };
            let data_size = data_size.size.get(endianness) as usize;

            if data_size != 0 {
                // return Ok(header);
                return Ok(DKBSHeader {
                    data_size,
                    header_size: HEADER_SIZE,
                    board_id,
                    version,
                    boot_device,
                    endianness,
                });
            }
        }
    }

    Err(StructureError)
}
