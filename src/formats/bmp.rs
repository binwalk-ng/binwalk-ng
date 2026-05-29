use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "BMP image (Bitmap)";

// BMPs start with these bytes
// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
// "The file type; must be 0x4d42 (the ASCII string "BM")"
pub fn bmp_magic() -> Vec<Vec<u8>> {
    vec![b"BM".to_vec()]
}

// Validates BMP header
pub fn bmp_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        name: "bmp".to_string(),
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Extraction dry-run to validate the image
    let dry_run = extract_bmp_image(file_data, offset, None);

    // If it was successful, inform the user
    if dry_run.success {
        // Retrieve total file size and report it to the user
        if let Some(total_size) = dry_run.size {
            result.description = format!("BMP image, total size: {total_size}");
            result.size = total_size;
            return Ok(result);
        }
    }

    Err(SignatureError)
}

#[derive(Debug, Default, Clone)]
pub struct BMPFileHeader {
    pub size: usize,
    pub bitmap_bits_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RawHeader {
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
    bf_type: zerocopy::U16<LE>,
    bf_size: zerocopy::U32<LE>,
    bf_reserved1: zerocopy::U16<LE>,
    bf_reserved2: zerocopy::U16<LE>,
    bf_off_bits: zerocopy::U32<LE>,
}

pub fn parse_bmp_file_header(bmp_data: &[u8]) -> Result<BMPFileHeader, StructureError> {
    let (raw_header, _rest) = RawHeader::ref_from_prefix(bmp_data).map_err(|_| StructureError)?;
    let bmp_data_size = bmp_data.len();

    let bf_size = raw_header.bf_size.get() as usize;
    let bf_off_bits = raw_header.bf_off_bits.get() as usize;

    // The BMP file size cannot be bigger than bmp_data
    if bmp_data_size < bf_size {
        return Err(StructureError);
    }

    // The file size cannot be 0
    if bf_size == 0 {
        return Err(StructureError);
    }

    // The offset cannot be 0
    if bf_off_bits == 0 {
        return Err(StructureError);
    }

    // The offset cannot be bigger than the file
    if bf_off_bits > bmp_data_size {
        return Err(StructureError);
    }

    // If everything is Ok so far, return a BMPFileHeader
    Ok(BMPFileHeader {
        size: bf_size,
        bitmap_bits_offset: bf_off_bits,
    })
}

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapv5header
// "The number of bytes required by the structure. Applications should use this member to determine which bitmap information header structure is being used."
pub fn get_dib_header_size(bmp_data: &[u8]) -> Result<usize, StructureError> {
    let valid_header_sizes = [
        12,  // BITMAPCOREHEADER
        40,  // BITMAPINFOHEADER
        108, // BITMAPV4HEADER
        124,
    ];

    let header_size = u32::from_le_bytes(bmp_data[..4].try_into().unwrap());

    if !valid_header_sizes.contains(&header_size) {
        return Err(StructureError);
    }

    Ok(header_size as usize)
}

/// Defines the internal extractor function for carving out GIF images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::bmp::bmp_extractor;
///
/// match bmp_extractor().utility {
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
pub fn bmp_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(extract_bmp_image),
        ..Default::default()
    }
}

pub fn extract_bmp_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "image.bmp";

    let mut result = ExtractionResult::default();

    // Parse the bmp_file_header
    if let Ok(bmp_file_header) = parse_bmp_file_header(&file_data[offset..]) {
        // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
        // The size of the BMP file header
        const BMP_FILE_HEADER_SIZE: usize = 14;

        // Retrieve the size of the header following the BMP file header
        if let Ok(bmp_header_size) =
            get_dib_header_size(&file_data[(offset + BMP_FILE_HEADER_SIZE)..])
        {
            // The offset that points to the image data cannot point into the second header
            if bmp_file_header.bitmap_bits_offset >= (BMP_FILE_HEADER_SIZE + bmp_header_size) {
                // If it was parsed successfully, get the file size
                result.size = Some(bmp_file_header.size);
                result.success = true;

                if let Some(output_directory) = output_directory {
                    let chroot = Chroot::new(output_directory);
                    result.success =
                        chroot.carve_file(OUTFILE_NAME, file_data, offset, bmp_file_header.size);
                }
            }
        }
    }

    result
}
