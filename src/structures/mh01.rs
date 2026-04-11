use crate::common::get_cstring;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store MH01 header info
#[derive(Debug, Default, Clone)]
pub struct MH01Header {
    pub iv: String,
    pub iv_offset: usize,
    pub iv_size: usize,
    pub signature_offset: usize,
    pub signature_size: usize,
    pub encrypted_data_offset: usize,
    pub encrypted_data_size: usize,
    pub total_size: usize,
}

// This structure is actually two MH01 headers, each header is HEADER_SIZE bytes long.
// The first header describes the offset and size of the firmware signature.
// The second header describes the offset and size of the encrypted firmware image.
// The OpenSSL IV is stored as an ASCII hex string between the second header and the encrypted firmware image.
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct MH01HeaderBytes {
    magic1: zerocopy::U32<LE>,
    signature_offset: zerocopy::U32<LE>,
    signature_size: zerocopy::U32<LE>,
    unknown1: zerocopy::U32<LE>,
    magic2: zerocopy::U32<LE>,
    iv_size: zerocopy::U32<LE>,
    encrypted_data_size: zerocopy::U32<LE>,
    unknown2: zerocopy::U32<LE>,
    // IV string of length iv_size immediately follows
}

/// Parses an MH01 header
pub fn parse_mh01_header(mh01_data: &[u8]) -> Result<MH01Header, StructureError> {
    const HEADER_SIZE: usize = 16;

    let mut result = MH01Header::default();

    // Parse the header
    let (header, _) = MH01HeaderBytes::ref_from_prefix(mh01_data).map_err(|_| StructureError)?;
    // Make sure the expected magic bytes match
    if header.magic1 == header.magic2 {
        // IV size is specified in the header and immediately follows the header
        result.iv_size = header.iv_size.get() as usize;
        result.iv_offset = std::mem::size_of::<MH01HeaderBytes>();

        // The encrypted firmware image immediately follows the IV
        result.encrypted_data_size = header.encrypted_data_size.get() as usize;
        result.encrypted_data_offset = result.iv_offset + result.iv_size;

        // The signature should immediately follow the encrypted firmware image
        result.signature_size = header.signature_size.get() as usize;
        result.signature_offset = HEADER_SIZE + header.signature_offset.get() as usize;

        // Calculate the start and end bytes of the IV (ASCII hex)
        let iv_bytes_start = result.iv_offset;
        let iv_bytes_end = result.encrypted_data_offset;

        // Get the payload hash string
        if let Some(iv_bytes) = mh01_data.get(iv_bytes_start..iv_bytes_end) {
            let iv_string = get_cstring(iv_bytes);

            // Make sure we got a string of the expected length
            if iv_string.len() == result.iv_size {
                result.iv = iv_string.trim().to_string();
                result.total_size = result.signature_offset + result.signature_size;
                return Ok(result);
            }
        }
    }

    Err(StructureError)
}
