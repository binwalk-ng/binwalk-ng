use crate::common::get_cstring;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "CHK firmware header";

/// CHK firmware always start with these bytes
pub fn chk_magic() -> Vec<Vec<u8>> {
    vec![b"\x2A\x23\x24\x5E".to_vec()]
}

/// Parse and validate CHK headers
pub fn chk_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Parse the CHK header
    if let Ok(chk_header) = parse_chk_header(&file_data[offset..]) {
        // Calculate reported image size and size of available data
        let available_data: usize = file_data.len() - offset;
        let image_total_size: usize =
            chk_header.header_size + chk_header.kernel_size + chk_header.rootfs_size;

        // Total reported image size should be between the header size and the file size
        if available_data >= image_total_size && image_total_size > chk_header.header_size {
            // Report the size of the header and a brief description
            result.size = chk_header.header_size;
            result.description = format!(
                "{}, board ID: {}, header size: {} bytes, data size: {} bytes",
                result.description,
                chk_header.board_id,
                chk_header.header_size,
                chk_header.kernel_size + chk_header.rootfs_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Storage struct for CHK header info
#[derive(Debug, Clone, Default)]
pub struct CHKHeader {
    pub header_size: usize,
    pub kernel_size: usize,
    pub rootfs_size: usize,
    pub board_id: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct CHKHeaderBytes {
    magic: zerocopy::U32<BE>,
    header_size: zerocopy::U32<BE>,
    unknown: zerocopy::U64<BE>,
    kernel_checksum: zerocopy::U32<BE>,
    rootfs_checksum: zerocopy::U32<BE>,
    rootfs_size: zerocopy::U32<BE>,
    kernel_size: zerocopy::U32<BE>,
    image_checksum: zerocopy::U32<BE>,
    header_checksum: zerocopy::U32<BE>,
    // Board ID string follows
}

/// Parse a CHK firmware header
pub fn parse_chk_header(header_data: &[u8]) -> Result<CHKHeader, StructureError> {
    // Somewhat arbitrarily chosen
    const MAX_EXPECTED_HEADER_SIZE: usize = 100;

    // Size of the fixed-length portion of the header structure
    let struct_size: usize = std::mem::size_of::<CHKHeaderBytes>();

    // Parse the CHK header
    let (chk_header, _) =
        CHKHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    // Validate the reported header size
    let header_size = chk_header.header_size.get() as usize;
    if header_size > struct_size && header_size <= MAX_EXPECTED_HEADER_SIZE {
        // Read in the board ID string which immediately follows the fixed size structure and extends to the end of the header
        let board_id_start = struct_size;
        let board_id_end = header_size;

        if let Some(board_id_raw_bytes) = header_data.get(board_id_start..board_id_end) {
            let board_id_string = get_cstring(board_id_raw_bytes);

            // We expect that there must be a valid board ID string
            if !board_id_string.is_empty() {
                return Ok(CHKHeader {
                    board_id: board_id_string,
                    header_size: chk_header.header_size.get() as usize,
                    kernel_size: chk_header.kernel_size.get() as usize,
                    rootfs_size: chk_header.rootfs_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}
