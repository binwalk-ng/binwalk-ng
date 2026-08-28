use crate::extractors::inflate;
use crate::extractors::{ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use std::path::Path;

/// Human readable description
pub const DESCRIPTION: &str = "Zlib compressed file";

/// Zlib magic bytes
pub fn zlib_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x78\x9c".to_vec(),
        b"\x78\xDA".to_vec(),
        b"\x78\x5E".to_vec(),
    ]
}

/// Validate a zlib signature
pub fn zlib_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_HIGH,
        description: DESCRIPTION.to_string(),
        ..Default::default()
    };

    // Decompress the zlib; no output directory specified, dry run only.
    let decompression_dry_run = zlib_decompress(file_data, offset, None);

    // If the decompression dry run was a success, this signature is almost certianly valid
    if decompression_dry_run.success
        && let Some(zlib_file_size) = decompression_dry_run.size
    {
        result.size = zlib_file_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Size of the checksum that follows the ZLIB deflate data stream
pub const CHECKSUM_SIZE: usize = 4;

/// Defines the internal extractor function for decompressing zlib data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::zlib::zlib_extractor;
///
/// match zlib_extractor().utility {
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
pub fn zlib_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(zlib_decompress),
        ..Default::default()
    }
}

/// Internal extractor for decompressing ZLIB data
pub fn zlib_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // Size of the zlib header
    const HEADER_SIZE: usize = 2;

    let mut exresult = ExtractionResult::default();

    // Do the decompression, ignoring the ZLIB header
    let Some(data_offset) = offset.checked_add(HEADER_SIZE) else {
        return exresult;
    };
    let inflate_result = inflate::inflate_decompressor(file_data, data_offset, output_directory);

    // Check that the data decompressed OK
    if inflate_result.success {
        // Calculate the ZLIB checksum offsets
        let Some(checksum_start) = offset
            .checked_add(HEADER_SIZE)
            .and_then(|v| v.checked_add(inflate_result.size))
        else {
            return exresult;
        };
        let Some(checksum_end) = checksum_start.checked_add(CHECKSUM_SIZE) else {
            return exresult;
        };

        // Get the ZLIB checksum
        if let Some(adler32_checksum_bytes) = file_data.get(checksum_start..checksum_end) {
            let reported_checksum = u32::from_be_bytes(adler32_checksum_bytes.try_into().unwrap());

            // Make sure the checksum matches
            if reported_checksum == inflate_result.adler32 {
                let Some(total_size) = HEADER_SIZE
                    .checked_add(inflate_result.size)
                    .and_then(|v| v.checked_add(CHECKSUM_SIZE))
                else {
                    return exresult;
                };
                exresult.success = true;
                exresult.size = Some(total_size);
            }
        }
    }

    exresult
}
