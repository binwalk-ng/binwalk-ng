use std::io::Read;
use std::path::Path;

use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::debug;
use lz4_flex::frame::FrameDecoder;
use xxhash_rust::xxh32;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "LZ4 compressed data";

/// LZ4 files start with these magic bytes
pub fn lz4_magic() -> Vec<Vec<u8>> {
    vec![b"\x04\x22\x4D\x18".to_vec()]
}

/// Validate a LZ4 signature
pub fn lz4_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Checksums are 4 bytes in length
    const CONTENT_CHECKSUM_LEN: usize = 4;

    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_MEDIUM,
        description: DESCRIPTION.to_string(),
        ..Default::default()
    };

    // Sanity check the size of available data
    if let Ok(lz4_file_header) = parse_lz4_file_header(&file_data[offset..]) {
        // LZ4 data starts immediately after the LZ4 header
        if let Some(lz4_data) = file_data.get(offset + lz4_file_header.header_size..) {
            // Determine the size of the actual LZ4 data by processing the data blocks that immediately follow the file header
            if let Ok(lz4_data_size) =
                get_lz4_data_size(lz4_data, lz4_file_header.block_checksum_present)
            {
                // Set the size of the header and the LZ4 data
                result.size = lz4_file_header.header_size + lz4_data_size;

                // If this flag is set, an additional 4-byte checksum will be present at the end of the LZ4 data
                if lz4_file_header.content_checksum_present {
                    result.size += CONTENT_CHECKSUM_LEN;
                }

                // Update description
                result.description =
                    format!("{}, total size: {} bytes", result.description, result.size);

                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Processes the LZ4 data blocks and returns the size of the raw LZ4 data
fn get_lz4_data_size(lz4_data: &[u8], checksum_present: bool) -> Result<usize, SignatureError> {
    let mut lz4_data_size: usize = 0;
    let mut last_lz4_data_size = None;
    let available_data = lz4_data.len();

    // Loop while there is still data and while the offsets are sane
    while is_offset_safe(available_data, lz4_data_size, last_lz4_data_size) {
        // Get the next block's data
        match lz4_data.get(lz4_data_size..) {
            None => {
                break;
            }
            Some(lz4_block_data) => {
                // Parse the next block's data
                match parse_lz4_block_header(lz4_block_data, checksum_present) {
                    Err(_) => {
                        break;
                    }
                    Ok(block_header) => {
                        // Update offsets
                        last_lz4_data_size = Some(lz4_data_size);
                        lz4_data_size += block_header.header_size
                            + block_header.data_size
                            + block_header.checksum_size;

                        // Only return success if a last block header is found
                        if block_header.last_block {
                            return Ok(lz4_data_size);
                        }
                    }
                }
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store LZ4 file header info
#[derive(Debug, Default, Clone)]
pub struct LZ4FileHeader {
    pub header_size: usize,
    pub block_checksum_present: bool,
    pub content_checksum_present: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZ4HeaderBytes {
    magic: zerocopy::U32<LE>,
    flags: u8,
    bd: u8,
}

/// Parse an LZ4 file header
pub fn parse_lz4_file_header(lz4_data: &[u8]) -> Result<LZ4FileHeader, StructureError> {
    // Fixed size constants
    const MAGIC_SIZE: usize = 4;
    const LZ4_STRUCT_SIZE: usize = 6;

    const BD_RESERVED_MASK: u8 = 0b10001111;
    const FLAGS_RESERVED_MASK: u8 = 0b00000010;

    const FLAG_DICTIONARY_PRESENT: u8 = 0b00000001;
    const FLAG_CONTENT_SIZE_PRESENT: u8 = 0b00001000;
    const FLAG_BLOCK_CHECKSUM_PRESENT: u8 = 0b00010000;
    const FLAG_CONTENT_CHECKSUM_PRESENT: u8 = 0b00000100;

    const DICTIONARY_LEN: usize = 4;
    const CONTENT_SIZE_LEN: usize = 8;

    let mut lz4_hdr_info = LZ4FileHeader::default();

    // Parse the header
    let (lz4_header, _) = LZ4HeaderBytes::ref_from_prefix(lz4_data).map_err(|_| StructureError)?;

    // Make sure the reserved bits aren't set
    if (lz4_header.flags & FLAGS_RESERVED_MASK) != 0 || (lz4_header.bd & BD_RESERVED_MASK) != 0 {
        return Err(StructureError);
    }
    /*
     * Calculate the start and end of data used to calculate the header CRC.
     * CRC is calculated over the entire descriptor frame, including optional fields,
     * but does not include the magic bytes.
     */
    let crc_data_start: usize = MAGIC_SIZE;
    let mut crc_data_end: usize = crc_data_start + (LZ4_STRUCT_SIZE - MAGIC_SIZE);

    // If the optional content size field is present, the CRC field is pushed back after the content size field
    if (lz4_header.flags & FLAG_CONTENT_SIZE_PRESENT) != 0 {
        crc_data_end += CONTENT_SIZE_LEN;
    }

    // If the optional dictionary ID field is present, the CRC field is pushed back after the dictionary ID field
    if (lz4_header.flags & FLAG_DICTIONARY_PRESENT) != 0 {
        crc_data_end += DICTIONARY_LEN;
    }

    // Get the data over which the CRC is calculated
    if let Some(crc_data) = lz4_data.get(crc_data_start..crc_data_end) {
        // Grab the header CRC value stored in the file header (one byte only)
        if let Some(actual_crc) = lz4_data.get(crc_data_end) {
            // Calculate the header CRC, which is the second byte of the xxh32 hash. It is calculated over the header, excluding the magic bytes.
            let calculated_crc: u8 = ((xxh32::xxh32(crc_data, 0) >> 8) & 0xFF) as u8;

            // Make sure the CRC's match
            if *actual_crc == calculated_crc {
                // Data blocks start immediately after the header checksum byte
                lz4_hdr_info.header_size = crc_data_end + 1;
                lz4_hdr_info.block_checksum_present =
                    (lz4_header.flags & FLAG_BLOCK_CHECKSUM_PRESENT) != 0;
                lz4_hdr_info.content_checksum_present =
                    (lz4_header.flags & FLAG_CONTENT_CHECKSUM_PRESENT) != 0;

                return Ok(lz4_hdr_info);
            }
        }
    }

    Err(StructureError)
}

/// Struct to store LZ4 block header info
#[derive(Debug, Default, Clone)]
pub struct LZ4BlockHeader {
    pub data_size: usize,
    pub header_size: usize,
    pub checksum_size: usize,
    pub last_block: bool,
}

/// Parse an LZ4 block header
pub fn parse_lz4_block_header(
    lz4_block_data: &[u8],
    checksum_present: bool,
) -> Result<LZ4BlockHeader, StructureError> {
    // Useful constants
    const SIZE_MASK: u32 = 0x7FFFFFFF;
    const END_MARKER: u32 = 0;
    const CHECKSUM_SIZE: usize = 4;
    const BLOCK_STRUCT_SIZE: usize = 4;

    let mut lz4_block = LZ4BlockHeader::default();

    // Parse the block header block size
    let (block_size, _) =
        zerocopy::U32::<LE>::ref_from_prefix(lz4_block_data).map_err(|_| StructureError)?;

    // Header size is always 4 bytes
    lz4_block.header_size = BLOCK_STRUCT_SIZE;

    // If file size is 0, this is the end of the LZ4 data
    lz4_block.last_block = *block_size == END_MARKER;

    // If a checksum is present, it will be an extra 4 bytes at the end of the block
    if checksum_present {
        lz4_block.checksum_size = CHECKSUM_SIZE;
    }

    // The high bit of the reported block size is not part of the actual block size
    lz4_block.data_size = (block_size.get() & SIZE_MASK) as usize;

    Ok(lz4_block)
}

/// Defines the internal extractor function for decompressing LZ4 data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::lz4::lz4_extractor;
///
/// match lz4_extractor().utility {
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
pub fn lz4_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(lz4_decompress),
        ..Default::default()
    }
}

/// Internal extractor for LZ4 compressed data
fn lz4_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";
    let mut result = ExtractionResult::default();

    let Some(data) = file_data.get(offset..) else {
        return result;
    };
    let mut decoder = FrameDecoder::new(data);
    let mut decompressed = Vec::new();

    match decoder.read_to_end(&mut decompressed) {
        Ok(0) => debug!("LZ4 decompression produced no output"),
        Ok(_) => {
            result.success = true;
            let remaining = decoder.into_inner();
            result.size = Some(data.len() - remaining.len());
            if let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);
                result.success = chroot.create_file(OUTPUT_FILE_NAME, &decompressed);
            }
        }
        Err(e) => debug!("LZ4 decompression failed: {e}"),
    }

    result
}
