use std::io::Read;
use std::path::Path;

use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::debug;
use u24::U24;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "ZSTD compressed data";

/// ZSTD magic bytes
pub fn zstd_magic() -> Vec<Vec<u8>> {
    vec![b"\x28\xb5\x2f\xfd".to_vec()]
}

/// Validate a ZSTD signature
pub fn zstd_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Size of checksum value at EOF
    const EOF_CHECKSUM_SIZE: usize = 4;

    // More or less arbitrarily chosen
    const MIN_BLOCK_COUNT: usize = 2;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.len();

    // Parse the ZSTD header; this should be safe as the ZSTD magic bytes wouldn't have matched at this offset if nothing was there...
    if let Ok(zstd_header) = parse_zstd_header(&file_data[offset..]) {
        /*
         * The first block header starts immediately after the ZSTD header, BUT there may be optional header fields present.
         * Must parse the frame header descriptor bit fields to determine total size of the header.
         */
        let mut next_block_header_start = offset + zstd_header.fixed_header_size;
        let mut previous_block_header_start = None;

        // If single segment flag is not set, then window descriptor byte is present in the header
        if !zstd_header.single_segment_flag {
            next_block_header_start += 1;
        }

        // If the dictionary ID flag is non-zero, its value represents the size of the dictionary ID field; else, this field does not exist
        next_block_header_start += match zstd_header.dictionary_id_flag {
            1 => 1,
            2 => 2,
            3 => 4,
            _ => 0,
        };

        /*
         * If the frame content flag is 0 and the single segment flag is set, then the frame content header field is 1 byte in length;
         * else, the frame content flag indicates the size of the grame content header field.
         */
        next_block_header_start += match zstd_header.frame_content_flag {
            0 if zstd_header.single_segment_flag => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => 0,
        };

        // Keep a count of how many blocks we've processed
        let mut block_count: usize = 0;

        // We now know where the first block header starts, loop through all the blocks to determine where the ZSTD data ends
        while is_offset_safe(
            available_data,
            next_block_header_start,
            previous_block_header_start,
        ) {
            // Parse the block header
            match parse_block_header(&file_data[next_block_header_start..]) {
                Err(_) => {
                    break;
                }

                Ok(block_header) => {
                    // Block header looks valid, increment block counter
                    block_count += 1;

                    // The next block header should start at the end of this block; note that the reported block size does not include the size of the block header
                    previous_block_header_start = Some(next_block_header_start);
                    next_block_header_start += block_header.header_size + block_header.block_size;

                    // Was this the last block?
                    if block_header.last_block {
                        // Update the total size, which is the difference between the end of the last block and the start of the ZSTD header
                        result.size = next_block_header_start - offset;

                        // If a checksum is included at the end of the block stream, add the checksum size to the total size
                        if zstd_header.content_checksum_present {
                            result.size += EOF_CHECKSUM_SIZE;
                        }

                        // Make sure we've processed more than one block; if so, return Ok, else break and return Err below
                        if block_count >= MIN_BLOCK_COUNT {
                            result.description = format!(
                                "{}, total size: {} bytes",
                                result.description, result.size
                            );
                            return Ok(result);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    Err(SignatureError)
}

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

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ZstdBlockHeaderBytes {
    info_bits: U24<LE>,
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
        header_size: std::mem::size_of::<ZstdBlockHeaderBytes>(),
        ..Default::default()
    };

    // Parse the block header
    let (block_header, _) =
        ZstdBlockHeaderBytes::ref_from_prefix(block_data).map_err(|_| StructureError)?;
    let info_bits = block_header.info_bits.get().into_u32();

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

/// Defines the internal extractor function for decompressing Zstandard data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::zstd::zstd_extractor;
///
/// match zstd_extractor().utility {
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
pub fn zstd_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(zstd_decompress),
        ..Default::default()
    }
}

/// Internal extractor for Zstandard compressed data
fn zstd_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";
    let mut result = ExtractionResult::default();

    let Some(data) = file_data.get(offset..) else {
        return result;
    };

    match zstd::stream::Decoder::with_buffer(data) {
        Ok(mut decoder) => {
            let mut decompressed = Vec::new();
            match decoder.read_to_end(&mut decompressed) {
                Ok(0) => debug!("ZSTD decompression produced no output"),
                Ok(_) => {
                    result.success = true;
                    let remaining = decoder.finish();
                    result.size = Some(data.len() - remaining.len());
                    if let Some(output_directory) = output_directory {
                        let chroot = Chroot::new(output_directory);
                        result.success = chroot.create_file(OUTPUT_FILE_NAME, &decompressed);
                    }
                }
                Err(e) => debug!("ZSTD decompression failed: {e}"),
            }
        }
        Err(e) => debug!("ZSTD decoder initialization failed: {e}"),
    }

    result
}
