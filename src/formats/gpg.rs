use crate::extractors::inflate;
use crate::extractors::{ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use std::path::Path;

/// Human readable description
pub const GPG_SIGNED_DESCRIPTION: &str = "GPG signed file";

/// GPG signed files start with these two bytes
pub fn gpg_signed_magic() -> Vec<Vec<u8>> {
    vec![b"\xA3\x01".to_vec()]
}

/// Validates GPG signatures
pub fn gpg_signed_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Success result; confidence is high since this signature is only reported what it starts at the beginning of a file
    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_HIGH,
        description: GPG_SIGNED_DESCRIPTION.to_string(),
        ..Default::default()
    };

    /*
     * GPG signed files are just zlib compressed files with the zlib magic bytes replaced with the GPG magic bytes.
     * Decompress the signed file; no output directory specified, dry run only.
     */
    let decompression_dry_run = gpg_decompress(file_data, offset, None);

    // If the decompression dry run was a success, this signature is almost certianly valid
    if decompression_dry_run.success
        && let Some(total_size) = decompression_dry_run.size
    {
        result.size = total_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Defines the internal extractor function for decompressing signed GPG data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::gpg::gpg_extractor;
///
/// match gpg_extractor().utility {
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
pub fn gpg_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(gpg_decompress),
        ..Default::default()
    }
}

/// Internal extractor for decompressing signed GPG data
pub fn gpg_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // Size of the GPG header
    const HEADER_SIZE: usize = 2;

    let mut exresult = ExtractionResult::default();

    // Do the decompression, ignoring the GPG header
    let inflate_result =
        inflate::inflate_decompressor(file_data, offset + HEADER_SIZE, output_directory);

    // Check that the data decompressed OK
    if inflate_result.success {
        exresult.success = true;
        exresult.size = Some(HEADER_SIZE + inflate_result.size);
    }

    exresult
}
