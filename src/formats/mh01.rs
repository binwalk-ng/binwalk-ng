use crate::common::get_cstring;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::formats::openssl::openssl_crypt_parser;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "D-Link MH01 firmware image";

/// MH01 firmware images always start with these bytes
pub fn mh01_magic() -> Vec<Vec<u8>> {
    vec![b"MH01".to_vec()]
}

/// Validates the MH01 header
pub fn mh01_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the firmware header
    if let Ok(mh01_header) = parse_mh01_header(&file_data[offset..]) {
        // The encrypted data is expected to be in OpenSSL file format, so parse that too
        if let Some(crypt_data) = file_data.get(offset + mh01_header.encrypted_data_offset..)
            && let Ok(openssl_signature) = openssl_crypt_parser(crypt_data, 0)
        {
            result.size = mh01_header.total_size;
            result.description = format!(
                "{}, signed, encrypted with {}, IV: {}, total size: {} bytes",
                result.description,
                openssl_signature.description,
                mh01_header.iv,
                mh01_header.total_size,
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

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

/// Defines the internal extractor function for carving out MH01 firmware images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::mh01::mh01_extractor;
///
/// match mh01_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn mh01_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_mh01_image),
        ..Default::default()
    }
}

/// Internal extractor for carve pieces of MH01 images to disk
pub fn extract_mh01_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // File names for the three portions of the MH01 firmware image
    const IV_FILE_NAME: &str = "iv.bin";
    const SIGNATURE_FILE_NAME: &str = "signature.bin";
    const ENCRYPTED_DATA_FILE_NAME: &str = "encrypted.bin";
    const DECRYPTED_DATA_FILE_NAME: &str = "decrypted.bin";

    let mut result = ExtractionResult::default();

    // Get the MH01 image data
    if let Some(mh01_data) = file_data.get(offset..) {
        // Parse the MH01 header
        if let Ok(mh01_header) = parse_mh01_header(mh01_data) {
            result.size = Some(mh01_header.total_size);

            // If extraction was requested, do it
            if let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);

                // Try to decrypt the firmware
                match delink::mh01::decrypt(mh01_data) {
                    Ok(decrypted_data) => {
                        // Write decrypted data to disk
                        result.success =
                            chroot.create_file(DECRYPTED_DATA_FILE_NAME, &decrypted_data);
                    }
                    Err(_) => {
                        // Decryption failture; extract each part of the firmware image, ensuring that each one extracts without error
                        result.success = chroot.carve_file(
                            IV_FILE_NAME,
                            mh01_data,
                            mh01_header.iv_offset,
                            mh01_header.iv_size,
                        ) && chroot.carve_file(
                            SIGNATURE_FILE_NAME,
                            mh01_data,
                            mh01_header.signature_offset,
                            mh01_header.signature_size,
                        ) && chroot.carve_file(
                            ENCRYPTED_DATA_FILE_NAME,
                            mh01_data,
                            mh01_header.encrypted_data_offset,
                            mh01_header.encrypted_data_size,
                        );
                    }
                }
            // No extraction requested, just return success
            } else {
                result.success = true;
            }
        }
    }

    result
}
