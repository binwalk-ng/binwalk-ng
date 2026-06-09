use crate::common::crc32;
use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "7-zip archive data";

/// 7zip magic bytes
pub fn sevenzip_magic() -> Vec<Vec<u8>> {
    vec![b"7z\xbc\xaf\x27\x1c".to_vec()]
}

/// Validates 7zip signatures
pub fn sevenzip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Parse the 7z header
    if let Ok(sevenzip_header) = parse_7z_header(&file_data[offset..]) {
        // Calculate the start and end offsets that the next header CRC was calculated over
        let next_crc_start: usize =
            offset + sevenzip_header.header_size + sevenzip_header.next_header_offset;
        let next_crc_end: usize = next_crc_start + sevenzip_header.next_header_size;

        if let Some(crc_data) = file_data.get(next_crc_start..next_crc_end) {
            // Calculate the next_header CRC
            let calculated_next_crc = crc32(crc_data);

            // Validate the next_header CRC
            if calculated_next_crc == sevenzip_header.next_header_crc {
                // Calculate total size of the 7zip archive
                let total_size: usize = sevenzip_header.header_size
                    + sevenzip_header.next_header_offset
                    + sevenzip_header.next_header_size;

                // Report signature result
                return Ok(SignatureResult {
                    offset,
                    size: total_size,
                    confidence: CONFIDENCE_HIGH,
                    description: format!(
                        "{}, version {}.{}, total size: {} bytes",
                        DESCRIPTION,
                        sevenzip_header.major_version,
                        sevenzip_header.minor_version,
                        total_size
                    ),
                    ..Default::default()
                });
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store 7zip header info
#[derive(Debug, Default, Clone)]
pub struct SevenZipHeader {
    pub header_size: usize,
    pub major_version: u8,
    pub minor_version: u8,
    pub next_header_crc: u32,
    pub next_header_size: usize,
    pub next_header_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SevenZipHeaderBytes {
    magic_p1: zerocopy::U16<LE>,
    magic_p2: zerocopy::U32<LE>,
    major_version: u8,
    minor_version: u8,
    header_crc: zerocopy::U32<LE>,
    next_header_offset: zerocopy::U64<LE>,
    next_header_size: zerocopy::U64<LE>,
    next_header_crc: zerocopy::U32<LE>,
}

/// Parse a 7zip header
pub fn parse_7z_header(sevenzip_data: &[u8]) -> Result<SevenZipHeader, StructureError> {
    // Offset & size constants
    const SEVENZIP_CRC_START: usize = 12;
    const SEVENZIP_HEADER_SIZE: usize = 32;

    // Parse the 7zip header
    let (sevenzip_header, _) =
        SevenZipHeaderBytes::ref_from_prefix(sevenzip_data).map_err(|_| StructureError)?;
    // Validate header CRC, which is calculated over the 'next_header_offset', 'next_header_size', and 'next_header_crc' values
    if let Some(crc_data) = sevenzip_data.get(SEVENZIP_CRC_START..SEVENZIP_HEADER_SIZE)
        && crc32(crc_data) == sevenzip_header.header_crc.get()
    {
        return Ok(SevenZipHeader {
            header_size: SEVENZIP_HEADER_SIZE,
            major_version: sevenzip_header.major_version,
            minor_version: sevenzip_header.minor_version,
            next_header_crc: sevenzip_header.next_header_crc.get(),
            next_header_size: sevenzip_header.next_header_size.get() as usize,
            next_header_offset: sevenzip_header.next_header_offset.get() as usize,
        });
    }

    Err(StructureError)
}

/// Describes how to run the 7z utility, supports multiple file formats
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::sevenzip::sevenzip_extractor;
///
/// match sevenzip_extractor().utility {
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
pub fn sevenzip_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("7z".to_string()),
        extension: "bin".to_string(),
        arguments: vec![
            "x".to_string(),    // Perform extraction
            "-y".to_string(),   // Assume Yes to all questions
            "-o.".to_string(),  // Output to current working directory
            "-p''".to_string(), // Blank password to prevent hangs if archives are password protected
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        // If there is trailing data after the compressed data, extraction will happen but exit code will be 2
        exit_codes: vec![0, 2],
        ..Default::default()
    }
}
