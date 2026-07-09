use crate::common::get_cstring;
use crate::formats::openssl::openssl_crypt_parser;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use md5::{Digest, Md5};
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "D-Link TLV firmware";

/// TLV firmware images always start with these bytes
pub fn dlink_tlv_magic() -> Vec<Vec<u8>> {
    vec![b"\x64\x80\x19\x40".to_vec()]
}

/// Validates the TLV header
pub fn dlink_tlv_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Checksum calculation includes the 8-byte header that preceeds the actual payload data
    const CHECKSUM_OFFSET: usize = 8;

    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the header
    if let Ok(tlv_header) = parse_dlink_tlv_header(&file_data[offset..]) {
        // Calculate the start and end offsets for the payload data over which the checksum is calculated
        let data_start = offset + tlv_header.header_size - CHECKSUM_OFFSET;
        let data_end = data_start + tlv_header.data_size + CHECKSUM_OFFSET;

        // Get the payload data and calculate the MD5 hash
        if let Some(payload_data) = file_data.get(data_start..data_end) {
            let payload_md5 = hex::encode(Md5::digest(payload_data));

            // If the MD5 checksum exists, make sure it matches
            if tlv_header.data_checksum.is_empty() || payload_md5 == tlv_header.data_checksum {
                result.size = tlv_header.header_size + tlv_header.data_size;
                result.description = format!(
                    "{}, model name: {}, board ID: {}, header size: {} bytes, data size: {} bytes",
                    result.description,
                    tlv_header.model_name,
                    tlv_header.board_id,
                    tlv_header.header_size,
                    tlv_header.data_size,
                );

                // Check if the firmware data is OpenSSL encrypted
                if let Some(crypt_data) = file_data.get(offset + tlv_header.header_size..)
                    && let Ok(openssl_signature) = openssl_crypt_parser(crypt_data, 0)
                {
                    result.description =
                        format!("{}, {}", result.description, openssl_signature.description);
                }

                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

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
