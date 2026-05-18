use crate::common::get_cstring;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "LUKS header";

/// LUKS Headers start with these bytes
pub fn luks_magic() -> Vec<Vec<u8>> {
    vec![b"LUKS\xBA\xBE".to_vec()]
}

/// Parse and validate the LUKS header
pub fn luks_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful result
    let mut result = SignatureResult {
        offset,
        name: "luks".to_string(),
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // If the header is parsed successfully, consider it valid
    if let Ok(luks_header) = parse_luks_header(&file_data[offset..]) {
        // Version 1 and version 2 have different header fields
        if luks_header.version == 1 {
            result.description = format!(
                "{}, version: {}, cipher algorithm: {}, cipher mode: {}, hash fn: {}",
                result.description,
                luks_header.version,
                luks_header.cipher_algorithm,
                luks_header.cipher_mode,
                luks_header.hashfn
            );
        } else {
            result.description = format!(
                "{}, version: {}, header size: {} bytes, hash fn: {}",
                result.description,
                luks_header.version,
                luks_header.header_size,
                luks_header.hashfn
            );
        }

        return Ok(result);
    }

    Err(SignatureError)
}

/// Struct to store some useful LUKS info
#[derive(Debug, Default, Clone)]
pub struct LUKSHeader {
    pub version: u16,
    pub header_size: usize,
    pub hashfn: String,
    pub cipher_mode: String,
    pub cipher_algorithm: String,
}

// https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup
// https://vhs.codeberg.page/post/external-backup-drive-encryption/assets/luks2_doc_wip.pdf
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LUKSHeaderBytes {
    magic: [u8; 6],
    version: zerocopy::U16<BE>,
    header_size: zerocopy::U64<BE>, // Only available in LUKS2
}

/// Partially parses a LUKS header
pub fn parse_luks_header(luks_data: &[u8]) -> Result<LUKSHeader, StructureError> {
    // Start and end offsets of the cipher algorithm string
    const CIPHER_ALGO_START: usize = 8;
    const CIPHER_ALGO_END: usize = 40;

    // Start and end offsets of the cipher mode string
    const CIPHER_MODE_START: usize = 40;
    const CIPHER_MODE_END: usize = 72;

    // Start and end offsets of the hash function string
    const HASHFN_START: usize = 72;
    const HASHFN_END: usize = 104;

    // Minimum LUKS2 header size (assuming no JSON data)
    const LUKS2_MIN_HEADER_SIZE: usize = 4032;

    let mut luks_hdr_info = LUKSHeader::default();

    let (luks_base, _) = LUKSHeaderBytes::ref_from_prefix(luks_data).map_err(|_| StructureError)?;
    luks_hdr_info.version = luks_base.version.get();

    // Both v1 and v2 include the hash function string at the same offset
    if let Some(hashfn_bytes) = luks_data.get(HASHFN_START..HASHFN_END) {
        luks_hdr_info.hashfn = get_cstring(hashfn_bytes);

        // Make sure there was actually a string at the expected hash function offset
        if !luks_hdr_info.hashfn.is_empty() {
            // Need to process v1 and v2 headers differently
            if luks_hdr_info.version == 1 {
                // Get the cipher algorithm string
                if let Some(cipher_algo_bytes) = luks_data.get(CIPHER_ALGO_START..CIPHER_ALGO_END) {
                    luks_hdr_info.cipher_algorithm = get_cstring(cipher_algo_bytes);

                    // Get the cipher mode string
                    if let Some(cipher_mode_bytes) =
                        luks_data.get(CIPHER_MODE_START..CIPHER_MODE_END)
                    {
                        luks_hdr_info.cipher_mode = get_cstring(cipher_mode_bytes);

                        // Make sure there were valid strings specified for both cipher algo and cipher mode
                        if !luks_hdr_info.cipher_mode.is_empty()
                            && !luks_hdr_info.cipher_algorithm.is_empty()
                        {
                            return Ok(luks_hdr_info);
                        }
                    }
                }
            } else if luks_hdr_info.version == 2 {
                // v2 doesn't have the same string entries, but does include a header size
                luks_hdr_info.header_size = luks_base.header_size.get() as usize;

                // Sanity check the header size
                if luks_hdr_info.header_size > LUKS2_MIN_HEADER_SIZE
                    && luks_hdr_info.header_size < luks_data.len()
                {
                    return Ok(luks_hdr_info);
                }
            }
        }
    }

    Err(StructureError)
}
