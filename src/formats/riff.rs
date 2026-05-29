use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "RIFF image";

/// RIFF file magic bytes
pub fn riff_magic() -> Vec<Vec<u8>> {
    vec![b"RIFF".to_vec()]
}

/// Validate RIFF signatures
pub fn riff_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Parse the RIFF header
    if let Ok(riff_header) = parse_riff_header(&file_data[offset..]) {
        // No sense in extracting an image if the entire file is just the image itself
        if offset == 0 && riff_header.size == file_data.len() {
            result.extraction_declined = true;
        }

        result.size = riff_header.size;
        result.description = format!(
            "{}, encoding type: {}, total size: {} bytes",
            result.description, riff_header.chunk_type, result.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Struct to store info from a RIFF header
pub struct RIFFHeader {
    pub size: usize,
    pub chunk_type: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RIFFHeaderBytes {
    magic: zerocopy::U32<LE>,
    file_size: zerocopy::U32<LE>,
    chunk_type: zerocopy::U32<LE>,
}

/// Parse a RIFF image header
pub fn parse_riff_header(riff_data: &[u8]) -> Result<RIFFHeader, StructureError> {
    const MAGIC: u32 = 0x46464952;

    const CHUNK_TYPE_START: usize = 8;
    const CHUNK_TYPE_END: usize = 12;

    const FILE_SIZE_OFFSET: usize = 8;

    let (riff_header, _) =
        RIFFHeaderBytes::ref_from_prefix(riff_data).map_err(|_| StructureError)?;
    if riff_header.magic == MAGIC
        && let Ok(type_string) = // Get the RIFF type string (e.g., "WAVE")
            String::from_utf8(riff_data[CHUNK_TYPE_START..CHUNK_TYPE_END].to_vec())
    {
        return Ok(RIFFHeader {
            size: riff_header.file_size.get() as usize + FILE_SIZE_OFFSET,
            chunk_type: type_string.trim().to_string(),
        });
    }

    Err(StructureError)
}

/// Describes the internal RIFF image extactor
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::riff::riff_extractor;
///
/// match riff_extractor().utility {
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
pub fn riff_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_riff_image),
        do_not_recurse: true,
        ..Default::default()
    }
}

/// Internal extractor for carving RIFF files to disk
pub fn extract_riff_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "image.riff";
    const WAV_OUTFILE_NAME: &str = "video.wav";
    const WAV_TYPE: &str = "WAVE";

    let mut result = ExtractionResult::default();

    if let Ok(riff_header) = parse_riff_header(&file_data[offset..]) {
        result.size = Some(riff_header.size);
        result.success = true;

        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);

            let file_path: String = if riff_header.chunk_type == WAV_TYPE {
                WAV_OUTFILE_NAME.to_string()
            } else {
                OUTFILE_NAME.to_string()
            };

            result.success = chroot.carve_file(file_path, file_data, offset, result.size.unwrap());
        }
    }

    result
}
