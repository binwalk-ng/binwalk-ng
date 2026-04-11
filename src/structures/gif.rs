use crate::common::is_offset_safe;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

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
