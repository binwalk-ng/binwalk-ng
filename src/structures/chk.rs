use crate::common::get_cstring;
use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

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
