use crate::extractors::{ExtractionResult, Extractor, ExtractorType};
use crate::formats::lzma::lzma_decompress;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use std::path::Path;

/// Human readable description
pub const DESCRIPTION: &str = "Arcadyan obfuscated LZMA";

/// Obfuscated Arcadyan LZMA magic bytes
pub fn obfuscated_lzma_magic() -> Vec<Vec<u8>> {
    vec![b"\x00\xD5\x08\x00".to_vec()]
}

/// Parses obfuscated Arcadyan LZMA data
pub fn obfuscated_lzma_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Magic bytes are 0x68 bytes into the actual file
    const MAGIC_OFFSET: usize = 0x68;

    // Success return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Sanity check on the reported offset; must be at least MAGIC_OFFSET bytes into the file
    if offset >= MAGIC_OFFSET {
        // Actual start of the Arcadyan data in the file
        let start_offset: usize = offset - MAGIC_OFFSET;

        // Do an extraction dry-run
        let dry_run = extract_obfuscated_lzma(file_data, start_offset, None);

        // If dry-run was successful, return success
        if dry_run.success {
            // Report the actual start of file data
            result.offset = start_offset;
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Defines the internal extractor for Arcadyn Obfuscated LZMA
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::arcadyan::obfuscated_lzma_extractor;
///
/// match obfuscated_lzma_extractor().utility {
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
pub fn obfuscated_lzma_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_obfuscated_lzma),
        ..Default::default()
    }
}

/// Internal extractor for Arcadyn Obfuscated LZMA
pub fn extract_obfuscated_lzma(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const LZMA_DATA_OFFSET: usize = 4;
    const MIN_DATA_SIZE: usize = 0x100;
    const MAX_DATA_SIZE: usize = 0x1B0000;

    let Some(available_data) = file_data.len().checked_sub(offset) else {
        return ExtractionResult::default();
    };

    // Sanity check data size
    if available_data <= MAX_DATA_SIZE && available_data > MIN_DATA_SIZE {
        // De-obfuscate the LZMA data
        let Some(file_slice) = file_data.get(offset..) else {
            return ExtractionResult::default();
        };
        let Some(deobfuscated_data) = arcadyan_deobfuscator(file_slice) else {
            return ExtractionResult::default();
        };

        // Do a decompression on the LZMA data (actual LZMA data starts 4 bytes into the deobfuscated data)
        return lzma_decompress(&deobfuscated_data, LZMA_DATA_OFFSET, output_directory);
    }

    ExtractionResult::default()
}

fn arcadyan_deobfuscator(obfuscated_data: &[u8]) -> Option<Vec<u8>> {
    const BLOCK_SIZE: usize = 32;

    const P1_START: usize = 0;
    const P1_END: usize = 4;

    const BLOCK1_START: usize = P1_END;
    const BLOCK1_END: usize = BLOCK1_START + BLOCK_SIZE;

    const P2_START: usize = BLOCK1_END;
    const P2_END: usize = 0x68;

    const BLOCK2_START: usize = P2_END;
    const BLOCK2_END: usize = BLOCK2_START + BLOCK_SIZE;

    const P3_START: usize = BLOCK2_END;

    let mut deobfuscated_data: Vec<u8> = Vec::with_capacity(obfuscated_data.len());

    // Get the "parts" and "blocks" of the obfuscated header
    let p1 = obfuscated_data.get(P1_START..P1_END)?;
    let b1 = obfuscated_data.get(BLOCK1_START..BLOCK1_END)?;
    let p2 = obfuscated_data.get(P2_START..P2_END)?;
    let b2 = obfuscated_data.get(BLOCK2_START..BLOCK2_END)?;
    let p3 = obfuscated_data.get(P3_START..)?;

    // Swap "block1" and "block2"
    deobfuscated_data.extend_from_slice(p1);
    deobfuscated_data.extend_from_slice(b2);
    deobfuscated_data.extend_from_slice(p2);
    deobfuscated_data.extend_from_slice(b1);
    deobfuscated_data.extend_from_slice(p3);

    // Swap nibbles and pairs of bytes in what is now block 1
    let block_slice = deobfuscated_data.get_mut(BLOCK1_START..BLOCK1_END)?;
    for chunk in block_slice.as_chunks_mut::<2>().0 {
        let orig_0 = chunk[0];
        chunk[0] = chunk[1].rotate_left(4);
        chunk[1] = orig_0.rotate_left(4);
    }

    Some(deobfuscated_data)
}
