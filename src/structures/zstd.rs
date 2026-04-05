use crate::structures::common::StructureError;
use u24::u24;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Stores info about a ZSTD file header
#[derive(Debug, Default, Clone)]
pub struct ZSTDHeader {
    pub fixed_header_size: usize,
    pub dictionary_id_flag: u8,
    pub content_checksum_present: bool,
    pub single_segment_flag: bool,
    pub frame_content_flag: u8,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ZstdHeaderBytes {
    magic: [u8; 4],
    frame_header_descriptor: u8,
}

/// Parse a ZSTD file header
pub fn parse_zstd_header(zstd_data: &[u8]) -> Result<ZSTDHeader, StructureError> {
    // Mask and shift bits
    const FRAME_UNUSED_BITS_MASK: u8 = 0b00011000;
    const DICTIONARY_ID_MASK: u8 = 0b11;
    const CONTENT_CHECKSUM_MASK: u8 = 0b100;
    const SINGLE_SEGMENT_MASK: u8 = 0b100000;
    const FRAME_CONTENT_MASK: u8 = 0b11000000;
    const FRAME_CONTENT_SHIFT: u8 = 6;

    let mut zstd_info = ZSTDHeader {
        fixed_header_size: std::mem::size_of::<ZstdHeaderBytes>(),
        ..Default::default()
    };

    // Parse the ZSTD header
    let (zstd_header, _) =
        ZstdHeaderBytes::ref_from_prefix(zstd_data).map_err(|_| StructureError)?;

    // Unused bits should be unused
    if (zstd_header.frame_header_descriptor & FRAME_UNUSED_BITS_MASK) == 0 {
        // Indicates if a dictionary ID field is present, and if so, how big it is
        zstd_info.dictionary_id_flag = zstd_header.frame_header_descriptor & DICTIONARY_ID_MASK;

        // Indicates if there is a 4-byte checksum present at the end of the compressed block stream
        zstd_info.content_checksum_present =
            (zstd_header.frame_header_descriptor & CONTENT_CHECKSUM_MASK) != 0;

        // If this flag is set, then the window descriptor byte is not present
        zstd_info.single_segment_flag =
            (zstd_header.frame_header_descriptor & SINGLE_SEGMENT_MASK) != 0;

        // Indicates if the frame content field is present, and if so, how big it is
        zstd_info.frame_content_flag =
            (zstd_header.frame_header_descriptor & FRAME_CONTENT_MASK) >> FRAME_CONTENT_SHIFT;

        return Ok(zstd_info);
    }

    Err(StructureError)
}

/// Stores info about a ZSTD block header
#[derive(Debug, Default, Clone)]
pub struct ZSTDBlockHeader {
    pub header_size: usize,
    pub block_type: u32,
    pub block_size: usize,
    pub last_block: bool,
}

/// Parse a ZSTD block header
pub fn parse_block_header(block_data: &[u8]) -> Result<ZSTDBlockHeader, StructureError> {
    // Bit mask constants
    const ZSTD_BLOCK_TYPE_MASK: u32 = 0b110;
    const ZSTD_BLOCK_TYPE_SHIFT: u32 = 1;
    const ZSTD_RLE_BLOCK_TYPE: u32 = 1;
    const ZSTD_RESERVED_BLOCK_TYPE: u32 = 3;
    const ZSTD_LAST_BLOCK_MASK: u32 = 0b1;
    const ZSTD_BLOCK_SIZE_MASK: u32 = 0b1111_1111_1111_1111_1111_1000;
    const ZSTD_BLOCK_SIZE_SHIFT: u32 = 3;

    let mut block_info = ZSTDBlockHeader {
        header_size: std::mem::size_of::<u24>(),
        ..Default::default()
    };

    // Parse the block header
    let bytes: [u8; 3] = block_data[0..3].try_into().map_err(|_| StructureError)?;
    let info_bits = u24::from_le_bytes(bytes).into_u32();

    // Interpret the bit fields of the block header, which indicate the type of block, the size of the block, and if this is the last block
    block_info.last_block = (info_bits & ZSTD_LAST_BLOCK_MASK) != 0;
    block_info.block_type = (info_bits & ZSTD_BLOCK_TYPE_MASK) >> ZSTD_BLOCK_TYPE_SHIFT;
    block_info.block_size = ((info_bits & ZSTD_BLOCK_SIZE_MASK) >> ZSTD_BLOCK_SIZE_SHIFT) as usize;

    /*
     * An RLE block consists of a single byte of raw block data, which when decompressed must be repeased block_size times.
     * We're not decompressing, just want to know the size of the raw data so we can check the next block header.
     *
     * Reserved block types should not be encountered, and are considered an error during decompression.
     */
    if block_info.block_type == ZSTD_RLE_BLOCK_TYPE {
        block_info.block_size = 1;
    }

    // Block type is invalid if set to the reserved block type
    if block_info.block_type != ZSTD_RESERVED_BLOCK_TYPE {
        return Ok(block_info);
    }

    Err(StructureError)
}
