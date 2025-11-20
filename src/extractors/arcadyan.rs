use std::path::Path;

use crate::extractors::common::{ExtractionResult, Extractor, ExtractorType};
use crate::extractors::lzma::lzma_decompress;

/// Defines the internal extractor for Arcadyn Obfuscated LZMA
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::common::ExtractorType;
/// use binwalk_ng::extractors::arcadyan::obfuscated_lzma_extractor;
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

    let mut result = ExtractionResult {
        ..Default::default()
    };
    let available_data: usize = file_data.len() - offset;

    // Sanity check data size
    if available_data <= MAX_DATA_SIZE && available_data > MIN_DATA_SIZE {
        // De-obfuscate the LZMA data
        let deobfuscated_data = arcadyan_deobfuscator(&file_data[offset..]);

        // Do a decompression on the LZMA data (actual LZMA data starts 4 bytes into the deobfuscated data)
        result = lzma_decompress(&deobfuscated_data, LZMA_DATA_OFFSET, output_directory);
    }

    result
}

fn arcadyan_deobfuscator(obfuscated_data: &[u8]) -> Vec<u8> {
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
    let p1 = &obfuscated_data[P1_START..P1_END];
    let b1 = &obfuscated_data[BLOCK1_START..BLOCK1_END];
    let p2 = &obfuscated_data[P2_START..P2_END];
    let b2 = &obfuscated_data[BLOCK2_START..BLOCK2_END];
    let p3 = &obfuscated_data[P3_START..];

    // Swap "block1" and "block2"
    deobfuscated_data.extend_from_slice(p1);
    deobfuscated_data.extend_from_slice(b2);
    deobfuscated_data.extend_from_slice(p2);
    deobfuscated_data.extend_from_slice(b1);
    deobfuscated_data.extend_from_slice(p3);

    // Swap nibbles and pairs of bytes in what is now block 1
    for chunk in deobfuscated_data[BLOCK1_START..BLOCK1_END].chunks_exact_mut(2) {
        let orig_0 = chunk[0];
        chunk[0] = chunk[1].rotate_left(4);
        chunk[1] = orig_0.rotate_left(4);
    }

    deobfuscated_data
}
