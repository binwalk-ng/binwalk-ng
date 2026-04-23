use crate::common::get_cstring;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store DLink TLV firmware header info
#[derive(Debug, Default, Clone)]
pub struct DlinkTLVHeader {
    pub model_name: String,
    pub board_id: String,
    pub header_size: usize,
    pub data_size: usize,
    pub data_checksum: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TLVBytes {
    chunk_type: zerocopy::U32<LE>,
    chunk_length: zerocopy::U32<LE>,
    // value immediately follows
}

/// Parses a DLink TLV firmware header
pub fn parse_dlink_tlv_header(tlv_data: &[u8]) -> Result<DlinkTLVHeader, StructureError> {
    const MAX_STRING_LENGTH: usize = 0x20;

    const MODEL_NAME_OFFSET: usize = 4;
    const BOARD_ID_OFFSET: usize = 0x24;
    const MD5_HASH_OFFSET: usize = 0x4C;
    const DATA_TLV_OFFSET: usize = 0x6C;

    const HEADER_SIZE: usize = 0x74;
    const EXPECTED_DATA_TYPE: u32 = 1;

    let mut header = DlinkTLVHeader::default();

    // Get the header data
    if let Some(header_data) = tlv_data.get(0..HEADER_SIZE) {
        // Get the strings from the header
        header.board_id =
            get_cstring(&header_data[BOARD_ID_OFFSET..BOARD_ID_OFFSET + MAX_STRING_LENGTH]);
        header.model_name =
            get_cstring(&header_data[MODEL_NAME_OFFSET..MODEL_NAME_OFFSET + MAX_STRING_LENGTH]);
        header.data_checksum =
            get_cstring(&header_data[MD5_HASH_OFFSET..MD5_HASH_OFFSET + MAX_STRING_LENGTH]);

        // Make sure we got the expected strings OK (checksum is not always included)
        if !header.model_name.is_empty() && !header.board_id.is_empty() {
            // Parse the type and length values that describe the data the follows the header
            let (data_tlv, _) = TLVBytes::ref_from_prefix(&header_data[DATA_TLV_OFFSET..])
                .map_err(|_| StructureError)?;

            // Sanity check the reported type (should be 1)
            if data_tlv.chunk_type == EXPECTED_DATA_TYPE {
                header.data_size = data_tlv.chunk_length.get() as usize;
                header.header_size = HEADER_SIZE;
                return Ok(header);
            }
        }
    }

    Err(StructureError)
}
