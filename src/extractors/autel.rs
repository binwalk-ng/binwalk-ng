use std::path::Path;

use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::autel::parse_autel_header;

const BLOCK_SIZE: usize = 256;

/// Defines the internal extractor function for deobfuscating Autel firmware
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::common::ExtractorType;
/// use binwalk_ng::extractors::autel::autel_extractor;
///
/// match autel_extractor().utility {
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
pub fn autel_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(autel_deobfuscate),
        ..Default::default()
    }
}

/// Internal extractor for obfuscated Autel firmware
/// https://gist.github.com/sector7-nl/3fc815cd2497817ad461bfbd393294cb
pub fn autel_deobfuscate(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "autel.decoded";

    let mut result = ExtractionResult {
        ..Default::default()
    };

    let data = &file_data[offset..];
    let Ok(autel_header) = parse_autel_header(data) else {
        return result;
    };

    let data_start = autel_header.header_size;

    // Get the encoded data
    let Some(autel_data) = data.get(data_start..) else {
        return result;
    };
    let Some(autel_data) = autel_data.get(..autel_header.data_size) else {
        return result;
    };
    // Iterate through each block of the encoded data
    for chunk in autel_data.chunks(BLOCK_SIZE) {
        let decoded_block = decode_autel_block(chunk);

        // Write to file, if requested
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            if !chroot.append_to_file(OUTPUT_FILE_NAME, &decoded_block) {
                return result;
            }
        }
    }
    result.size = Some(autel_header.data_size);
    result.success = true;
    result
}

/// Block decoder for autel encoded firmware.
/// block_data *must* be 256 bytes in size, or less.
fn decode_autel_block(block_data: &[u8]) -> Vec<u8> {
    // Lookup table for encoding/decoding bytes
    const ADDS: [u8; BLOCK_SIZE] = [
        54, 96, 59, 191, 45, 96, 27, 152, 44, 118, 115, 210, 13, 27, 20, 139, 28, 17, 19, 224, 20,
        145, 14, 12, 18, 17, 29, 246, 115, 28, 155, 12, 31, 20, 27, 142, 96, 18, 145, 23, 13, 13,
        23, 19, 27, 83, 146, 145, 18, 96, 13, 159, 96, 20, 20, 27, 9, 96, 13, 159, 96, 142, 31,
        155, 7, 224, 20, 27, 28, 17, 19, 96, 76, 208, 80, 78, 96, 27, 24, 140, 96, 17, 12, 224, 14,
        17, 151, 14, 16, 96, 13, 155, 20, 29, 23, 24, 27, 10, 96, 140, 14, 17, 16, 144, 11, 13, 96,
        17, 12, 96, 28, 27, 27, 18, 96, 31, 96, 13, 23, 224, 27, 142, 27, 24, 12, 96, 84, 14, 27,
        10, 155, 9, 17, 56, 96, 82, 13, 27, 20, 139, 28, 145, 19, 118, 115, 20, 145, 14, 12, 146,
        17, 29, 96, 28, 27, 140, 31, 148, 27, 14, 83, 18, 17, 23, 13, 13, 151, 147, 27, 96, 19,
        159, 14, 25, 17, 142, 16, 27, 14, 224, 17, 12, 224, 28, 27, 13, 11, 96, 27, 30, 224, 146,
        31, 29, 96, 140, 31, 24, 140, 96, 27, 29, 31, 154, 14, 27, 140, 18, 23, 96, 21, 14, 17, 9,
        12, 155, 18, 96, 27, 148, 29, 23, 24, 155, 10, 96, 28, 14, 31, 28, 18, 31, 12, 13, 96, 31,
        96, 13, 27, 18, 23, 26, 27, 156, 96, 79, 211, 76, 77, 75, 206, 182, 96, 59, 191, 173,
    ];

    const XORS: [u8; BLOCK_SIZE] = [
        147, 129, 193, 0, 130, 144, 129, 0, 180, 141, 129, 0, 164, 133, 192, 0, 166, 133, 193, 0,
        161, 0, 193, 132, 161, 140, 192, 0, 178, 132, 0, 132, 165, 136, 193, 0, 164, 133, 0, 132,
        165, 148, 193, 132, 178, 137, 0, 0, 166, 148, 193, 0, 166, 129, 193, 132, 160, 148, 192, 0,
        180, 0, 193, 0, 166, 0, 192, 132, 160, 149, 193, 132, 164, 0, 192, 132, 160, 144, 193, 0,
        178, 141, 193, 0, 161, 141, 0, 132, 165, 137, 193, 0, 161, 141, 192, 132, 178, 133, 192, 0,
        180, 133, 192, 0, 163, 141, 192, 132, 178, 141, 192, 132, 130, 141, 193, 132, 181, 140,
        193, 0, 166, 0, 192, 132, 183, 133, 192, 132, 178, 140, 0, 132, 160, 133, 192, 132, 160,
        137, 193, 0, 161, 0, 192, 132, 165, 132, 0, 132, 167, 0, 193, 132, 176, 144, 193, 0, 180,
        0, 192, 132, 160, 137, 193, 132, 165, 145, 0, 0, 178, 137, 193, 0, 160, 148, 193, 0, 180,
        136, 193, 0, 178, 144, 0, 132, 160, 141, 193, 132, 165, 140, 0, 0, 165, 129, 192, 0, 161,
        145, 0, 132, 165, 140, 192, 0, 161, 145, 0, 132, 167, 140, 129, 132, 165, 137, 193, 0, 161,
        141, 192, 0, 178, 133, 192, 0, 180, 133, 192, 132, 130, 129, 193, 132, 180, 144, 193, 132,
        160, 141, 193, 132, 181, 140, 193, 0, 166, 141, 0, 132, 160, 133, 0, 0, 129, 133, 0, 0,
    ];

    assert!(block_data.len() <= BLOCK_SIZE);

    let decoded_block: Vec<u8> = block_data
        .iter()
        .enumerate()
        .map(|(i, &byte)| {
            let add = ADDS[i];
            let xor = XORS[i];
            (byte.wrapping_add(add)) ^ xor
        })
        .collect();

    decoded_block
}
