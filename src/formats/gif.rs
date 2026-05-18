use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "GIF image";

/// GIF images always start with these bytes
pub fn gif_magic() -> Vec<Vec<u8>> {
    // https://giflib.sourceforge.net/whatsinagif/bits_and_bytes.html
    vec![b"GIF87a".to_vec(), b"GIF89a".to_vec()]
}

/// Validates the GIF header
pub fn gif_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run to validate the GIF image
    let dry_run = extract_gif_image(file_data, offset, None);

    if dry_run.success
        && let Some(total_size) = dry_run.size
    {
        // Everything looks ok, parse the GIF header to report some info to the user
        if let Ok(gif_header) = parse_gif_header(&file_data[offset..]) {
            // No sense in extracting a GIF from a file if the GIF data starts at offset 0
            if offset == 0 {
                result.extraction_declined = true;
            }

            result.size = total_size;
            result.description = format!(
                "{}, {}x{} pixels, total size: {} bytes",
                result.description, gif_header.image_width, gif_header.image_height, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store GIF header info
#[derive(Debug, Default, Clone)]
pub struct GIFHeader {
    pub size: usize,
    pub image_width: usize,
    pub image_height: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GIFHeaderBytes {
    magic: [u8; 6],
    image_width: zerocopy::U16<LE>,
    image_height: zerocopy::U16<LE>,
    flags: u8,
    bg_color_index: u8,
    aspect_ratio: u8,
}

/// Parses a GIF header
pub fn parse_gif_header(gif_data: &[u8]) -> Result<GIFHeader, StructureError> {
    // Parse the header
    let (gif_header, _) = GIFHeaderBytes::ref_from_prefix(gif_data).map_err(|_| StructureError)?;
    // Parse the flags to determine if a global color table is included in the header
    let flags = parse_gif_flags(gif_header.flags);

    Ok(GIFHeader {
        size: std::mem::size_of::<GIFHeaderBytes>() + flags.color_table_size,
        image_width: gif_header.image_width.get() as usize,
        image_height: gif_header.image_height.get() as usize,
    })
}

/// Struct to store GIF flags info
#[derive(Debug, Default, Clone)]
pub struct GIFFlags {
    /// Actual size of the color table, in bytes
    pub color_table_size: usize,
}

/// Parses a GIF flag byte to determine the size of a color table, if any
fn parse_gif_flags(flags: u8) -> GIFFlags {
    const HAS_COLOR_TABLE: u8 = 0x80;
    const COLOR_TABLE_SIZE_MASK: u8 = 0b111;

    let mut retval = GIFFlags::default();

    if (flags & HAS_COLOR_TABLE) != 0 {
        let encoded_table_size = ((flags & COLOR_TABLE_SIZE_MASK) + 1) as u32;
        retval.color_table_size = 3 * usize::pow(2, encoded_table_size);
    }

    retval
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GIFImgDescBytes {
    magic: u8,
    image_left: zerocopy::U16<LE>,
    image_top: zerocopy::U16<LE>,
    image_width: zerocopy::U16<LE>,
    image_height: zerocopy::U16<LE>,
    flags: u8,
}

/// Parses an image descriptor; returns the total size of the descriptor and following image data
pub fn parse_gif_image_descriptor(gif_data: &[u8]) -> Result<usize, StructureError> {
    const LZW_CODE_SIZE: usize = 1;

    // Parse the image descriptor header
    let (desc_header, _) =
        GIFImgDescBytes::ref_from_prefix(gif_data).map_err(|_| StructureError)?;

    // Parse the flags field to determine if a local color table follows the header
    let flags = parse_gif_flags(desc_header.flags);
    let mut total_size: usize = std::mem::size_of::<GIFImgDescBytes>() + flags.color_table_size;

    // After the header and optional color table will be a single-byte value representing the minimum LZW code size.
    total_size += LZW_CODE_SIZE;

    // An unspecified number of data sub-blocks follow.
    if let Some(image_sub_blocks) = gif_data.get(total_size..) {
        // Parse all sub-blocks to determine the total size of sub-blocks
        if let Ok(sub_blocks_size) = parse_gif_sub_blocks(image_sub_blocks) {
            total_size += sub_blocks_size;
            return Ok(total_size);
        }
    }

    Err(StructureError)
}

/// Parses all data sub blocks until a sub-block terminator byte is found.
/// Returns the size, in bytes, of all sub-block data.
fn parse_gif_sub_blocks(sub_block_data: &[u8]) -> Result<usize, StructureError> {
    const SUB_BLOCK_TERMINATOR: u8 = 0;

    let available_data = sub_block_data.len();
    let mut next_offset = 0;
    let mut previous_offset = None;

    // Sub-blocks are just <u8 size of sub-block data><sub-block data>
    while is_offset_safe(available_data, next_offset, previous_offset) {
        match sub_block_data.get(next_offset) {
            None => break,
            Some(sub_block_size) => {
                if *sub_block_size == SUB_BLOCK_TERMINATOR {
                    return Ok(next_offset + 1);
                } else {
                    previous_offset = Some(next_offset);
                    next_offset += (*sub_block_size as usize) + 1;
                }
            }
        }
    }

    Err(StructureError)
}

// Some extensions do not include the sub_block_offset field;
// this field is always parsed here, but only used if applicable.
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GIFExtensionHeaderBytes {
    magic: u8,
    extension_type: u8,
    sub_block_offset: u8,
}

/// Parses a GIF extension block, returns the size of the extension block, in bytes.
pub fn parse_gif_extension(extension_data: &[u8]) -> Result<usize, StructureError> {
    const PLAIN_TEXT: u8 = 1;
    const APPLICATION: u8 = 0xFF;
    const HEADER_SIZE: usize = 2;

    // Parse the extension header to get the extension sub-type
    let (extension_header, _) =
        GIFExtensionHeaderBytes::ref_from_prefix(extension_data).map_err(|_| StructureError)?;
    let ext_type = extension_header.extension_type;
    let mut sub_blocks_offset: usize = HEADER_SIZE;

    // These extensions have some extra data before the sub-blocks; all other extensions are just a 2-byte header followed by sub-blocks
    if ext_type == APPLICATION || ext_type == PLAIN_TEXT {
        sub_blocks_offset += extension_header.sub_block_offset as usize + 1;
    }

    // Parse all sub-block data to determine the total size of this extension block
    if let Some(sub_block_data) = extension_data.get(sub_blocks_offset..)
        && let Ok(sub_blocks_size) = parse_gif_sub_blocks(sub_block_data)
    {
        return Ok(sub_blocks_offset + sub_blocks_size);
    }

    Err(StructureError)
}

/// Defines the internal extractor function for carving out GIF images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::gif::gif_extractor;
///
/// match gif_extractor().utility {
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
pub fn gif_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(extract_gif_image),
        ..Default::default()
    }
}

/// Parses and carves a GIF image from a file
pub fn extract_gif_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "image.gif";

    let mut result = ExtractionResult::default();

    // Parse the GIF header
    if let Ok(gif_header) = parse_gif_header(&file_data[offset..]) {
        // GIF data follows the gif header
        if let Some(gif_image_data) = file_data.get(offset + gif_header.size..) {
            // Determine the size of the GIF image data
            if let Some(gif_data_size) = get_gif_data_size(gif_image_data) {
                // Report success
                result.size = Some(gif_header.size + gif_data_size);
                result.success = true;

                // Do extraction, if requested
                if let Some(output_directory) = output_directory {
                    let chroot = Chroot::new(output_directory);
                    result.success =
                        chroot.carve_file(OUTFILE_NAME, file_data, offset, result.size.unwrap());
                }
            }
        }
    }

    result
}

/// Returns the size of the GIF data that follows the GIF header
fn get_gif_data_size(gif_data: &[u8]) -> Option<usize> {
    // GIF block types
    const EXTENSION: u8 = 0x21;
    const TERMINATOR: u8 = 0x3B;
    const IMAGE_DESCRIPTOR: u8 = 0x2C;

    let mut next_offset: usize = 0;
    let mut previous_offset = None;
    let available_data = gif_data.len();

    // Loop through all GIF data blocks
    while is_offset_safe(available_data, next_offset, previous_offset) {
        let block_size = match gif_data.get(next_offset) {
            Some(&IMAGE_DESCRIPTOR) => parse_gif_image_descriptor(&gif_data[next_offset..]),
            Some(&EXTENSION) => parse_gif_extension(&gif_data[next_offset..]),
            Some(&TERMINATOR) => {
                return Some(next_offset + 1);
            }
            // This covers both None and any byte that doesn't match our constants
            _ => break,
        };

        // Check if the block was parsed successfully
        match block_size {
            Err(_) => break,
            Ok(this_block_size) => {
                // Everything looks OK, go to the next block
                previous_offset = Some(next_offset);
                next_offset += this_block_size;
            }
        }
    }

    // Something went wrong, failure
    None
}
