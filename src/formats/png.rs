use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "PNG image";

/// PNG magic bytes
pub fn png_magic() -> Vec<Vec<u8>> {
    /*
     * PNG magic, followed by chunk size and IHDR chunk type.
     * IHDR must be the first chunk type, and it is a fixed size of 0x0000000D bytes.
     */
    vec![b"\x89PNG\x0D\x0A\x1A\x0A\x00\x00\x00\x0DIHDR".to_vec()]
}

/// Validate a PNG signature
pub fn png_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Perform an extraction dry-run
    let dry_run = extract_png_image(file_data, offset, None);

    // If the dry-run was a success, this is almost certainly a valid PNG
    if dry_run.success {
        // Get the total size of the PNG
        if let Some(png_size) = dry_run.size {
            // If the start of a file PNG, there's no need to extract it
            if offset == 0 {
                result.extraction_declined = true;
            }

            // Report signature result
            result.size = png_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores info on a PNG chunk header
pub struct PNGChunkHeader {
    pub total_size: usize,
    pub is_last_chunk: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct PNGChunkBytes {
    length: zerocopy::U32<BE>,
    chunk_type: zerocopy::U32<BE>,
}

/// Parse a PNG chunk header
pub fn parse_png_chunk_header(chunk_data: &[u8]) -> Result<PNGChunkHeader, StructureError> {
    // All PNG chunks are followed by a 4-byte CRC
    const CRC_SIZE: usize = 4;

    // The "IEND" chunk is the last chunk in the PNG
    const IEND_CHUNK_TYPE: u32 = 0x49454E44;

    let chunk_structure_size: usize = std::mem::size_of::<PNGChunkBytes>();

    // Parse the chunk header
    let (chunk_header, _) =
        PNGChunkBytes::ref_from_prefix(chunk_data).map_err(|_| StructureError)?;
    Ok(PNGChunkHeader {
        is_last_chunk: chunk_header.chunk_type == IEND_CHUNK_TYPE,
        total_size: chunk_structure_size + chunk_header.length.get() as usize + CRC_SIZE,
    })
}

/// Defines the internal extractor function for carving out PNG images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::png::png_extractor;
///
/// match png_extractor().utility {
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
pub fn png_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_png_image),
        ..Default::default()
    }
}

/// Internal extractor for carving PNG files to disk
pub fn extract_png_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const PNG_HEADER_LEN: usize = 8;
    const OUTFILE_NAME: &str = "image.png";

    let mut result = ExtractionResult::default();

    // Parse all the PNG chunks to determine the size of PNG data; first chunk starts immediately after the 8-byte PNG header
    if let Some(png_data) = file_data.get(offset + PNG_HEADER_LEN..)
        && let Some(png_data_size) = get_png_data_size(png_data)
    {
        // Total size is the size of the header plus the size of the data
        result.size = Some(png_data_size + PNG_HEADER_LEN);
        result.success = true;

        // If extraction was requested, extract the PNG
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success =
                chroot.carve_file(OUTFILE_NAME, file_data, offset, result.size.unwrap());
        }
    }

    result
}

fn get_png_data_size(png_chunk_data: &[u8]) -> Option<usize> {
    let available_data = png_chunk_data.len();
    let mut png_chunk_offset: usize = 0;
    let mut previous_png_chunk_offset = None;

    // Loop until we run out of data
    while is_offset_safe(available_data, png_chunk_offset, previous_png_chunk_offset) {
        // Parse this PNG chunk header
        match parse_png_chunk_header(&png_chunk_data[png_chunk_offset..]) {
            Ok(chunk_header) => {
                // The next chunk header will start immediately after this chunk
                previous_png_chunk_offset = Some(png_chunk_offset);
                png_chunk_offset += chunk_header.total_size;

                // If this was the last chunk, then png_chunk_offset is the total size of the PNG data
                if chunk_header.is_last_chunk {
                    return Some(png_chunk_offset);
                }
            }
            Err(_) => break,
        }
    }

    None
}
