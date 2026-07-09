use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use std::collections::HashMap;
use std::path::Path;

/// Known encrypted firmware magics and their associated make/model
fn encfw_known_firmware() -> HashMap<Vec<u8>, String> {
    HashMap::from([
        (
            b"\xdf\x8c\x39\x0d".to_vec(),
            "D-Link DIR-822 rev C".to_string(),
        ),
        (b"\x35\x66\x6f\x68".to_vec(), "D-Link DAP-1665".to_string()),
        (
            b"\xf5\x2a\xa0\xb4".to_vec(),
            "D-Link DIR-842 rev C".to_string(),
        ),
        (
            b"\xe3\x13\x00\x5b".to_vec(),
            "D-Link DIR-850 rev A".to_string(),
        ),
        (
            b"\x0a\x14\xe4\x24".to_vec(),
            "D-Link DIR-850 rev B".to_string(),
        ),
    ])
}

/// Human readable description
pub const DESCRIPTION: &str = "Known encrypted firmware";

/// Known encrypted firmware magic bytes
pub fn encfw_magic() -> Vec<Vec<u8>> {
    encfw_known_firmware().keys().cloned().collect()
}

/// Parse the magic signature match
pub fn encfw_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MAGIC_LEN: usize = 4;

    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Some(magic_bytes) = file_data.get(offset..offset + MAGIC_LEN)
        && encfw_known_firmware().contains_key(magic_bytes)
    {
        if result.offset != 0 {
            result.confidence = CONFIDENCE_LOW;
        }

        result.description = format!(
            "{}, {}",
            result.description,
            encfw_known_firmware()[magic_bytes]
        );

        return Ok(result);
    }

    Err(SignatureError)
}

/// Defines the internal extractor function for decrypting known encrypted firmware
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::encfw::encfw_extractor;
///
/// match encfw_extractor().utility {
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
pub fn encfw_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(encfw_decrypt),
        ..Default::default()
    }
}

/// Attempts to decrypt known encrypted firmware images
pub fn encfw_decrypt(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decrypted.bin";

    let mut result = ExtractionResult::default();
    if let Ok(decrypted_data) = delink::decrypt(&file_data[offset..]) {
        result.success = true;

        // Write to file, if requested
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success = chroot.create_file(OUTPUT_FILE_NAME, &decrypted_data);
        }
    }

    result
}
