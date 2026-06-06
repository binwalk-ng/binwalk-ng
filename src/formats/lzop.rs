use crate::common::is_offset_safe;
use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "LZO compressed data";

/// LZOP magic bytes
pub fn lzop_magic() -> Vec<Vec<u8>> {
    vec![b"\x89LZO\x00\x0D\x0A\x1A\x0A".to_vec()]
}

/// Validate an LZOP signature
pub fn lzop_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success retrun value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the LZOP file header
    if let Ok(lzop_header) = parse_lzop_file_header(&file_data[offset..])
        && let Some(lzop_data) = file_data.get(offset + lzop_header.header_size..)
    {
        // Get the size of the compressed LZO data
        if let Ok(data_size) = get_lzo_data_size(lzop_data, lzop_header.block_checksum_present) {
            // Update the total size to include the LZO data
            result.size = lzop_header.header_size + data_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

// Parse the LZO blocks to determine the size of the compressed data, including the terminating EOF marker
fn get_lzo_data_size(
    lzo_data: &[u8],
    compressed_checksum_present: bool,
) -> Result<usize, SignatureError> {
    // Technially LZOP could have one block, but this would seem uncommon
    const MIN_BLOCK_COUNT: usize = 2;

    let available_data = lzo_data.len();
    let mut last_offset = None;
    let mut data_size: usize = 0;
    let mut block_count: usize = 0;

    // Loop until we run out of data or an invalid block header is encountered
    while is_offset_safe(available_data, data_size, last_offset) {
        // Parse the next block header
        match parse_lzop_block_header(&lzo_data[data_size..], compressed_checksum_present) {
            Err(_) => {
                break;
            }

            Ok(block_header) => {
                // Update block count, offset, and size
                block_count += 1;
                last_offset = Some(data_size);
                data_size += block_header.header_size
                    + block_header.compressed_size
                    + block_header.checksum_size;
            }
        }
    }

    // As a sanity check, make sure we processed some number of data blocks
    if block_count >= MIN_BLOCK_COUNT {
        // Process the EOF marker that should come at the end of the data blocks
        if let Some(eof_marker_data) = lzo_data.get(data_size..)
            && let Ok(eof_marker_size) = parse_lzop_eof_marker(eof_marker_data)
        {
            data_size += eof_marker_size;
            return Ok(data_size);
        }
    }

    Err(SignatureError)
}

/// LZO checksums are 4-bytes long
const LZO_CHECKSUM_SIZE: usize = 4;

/// Struct to store LZOP file header info
#[derive(Debug, Default, Clone)]
pub struct LZOPFileHeader {
    pub header_size: usize,
    pub block_checksum_present: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOHeaderP1 {
    magic_p1: u8,
    magic_p2: zerocopy::U64<BE>,
    version: zerocopy::U16<BE>,
    lib_version: zerocopy::U16<BE>,
    version_needed: zerocopy::U16<BE>,
    method: u8,
    level: u8,
    flags: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOHeaderP2 {
    mode: zerocopy::U32<BE>,
    mtime: zerocopy::U32<BE>,
    gmt_diff: zerocopy::U32<BE>,
    file_name_length: u8,
}

/// Parse an LZOP file header
pub fn parse_lzop_file_header(lzop_data: &[u8]) -> Result<LZOPFileHeader, StructureError> {
    // Max supported LZO version
    const LZO_MAX_VERSION: u16 = 0x1040;

    const LZO_HEADER_SIZE_P1: usize = 21;
    const LZO_HEADER_SIZE_P2: usize = 13;

    const FILTER_SIZE: usize = 4;

    const FLAG_FILTER: u32 = 0x000_00800;
    //const FLAG_CRC32_D: usize = 0x0000_0100;
    const FLAG_CRC32_C: u32 = 0x0000_0200;
    //const FLAG_ADLER32_D: usize = 0x0000_0001;
    const FLAG_ADLER32_C: u32 = 0x0000_0002;

    let allowed_methods = [1, 2, 3];

    let mut lzop_info = LZOPFileHeader::default();

    // Parse the first part of the header
    let (lzo_header_p1, _) = LZOHeaderP1::ref_from_prefix(lzop_data).map_err(|_| StructureError)?;
    // Sanity check the methods field
    if allowed_methods.contains(&lzo_header_p1.method) {
        // Sanity check the header version numbers
        if lzo_header_p1.version <= LZO_MAX_VERSION
            && lzo_header_p1.version >= lzo_header_p1.version_needed
        {
            // Unless the optional filter field is included, start of the second part of the header is at the end of the first
            let mut header_p2_start: usize = LZO_HEADER_SIZE_P1;

            // Next part of the header may or may not have an optional filter field
            if (lzo_header_p1.flags & FLAG_FILTER) != 0 {
                header_p2_start += FILTER_SIZE;
            }

            // Calculate the end of the second part of the header
            let header_p2_end: usize = header_p2_start + LZO_HEADER_SIZE_P2;

            if let Some(header_p2_data) = lzop_data.get(header_p2_start..header_p2_end) {
                // Parse the second part of the header
                let (lzo_header_p2, _) =
                    LZOHeaderP2::ref_from_prefix(header_p2_data).map_err(|_| StructureError)?;

                // Calculate the total header size; compressed data blocks will immediately follow
                lzop_info.header_size =
                    header_p2_end + lzo_header_p2.file_name_length as usize + LZO_CHECKSUM_SIZE;

                // Check if block headers include an optional compressed data checksum field
                lzop_info.block_checksum_present =
                    (lzo_header_p1.flags & (FLAG_ADLER32_C | FLAG_CRC32_C)) != 0;

                // Sanity check on the calculated header size
                if lzop_info.header_size <= lzop_data.len() {
                    return Ok(lzop_info);
                }
            }
        }
    }

    Err(StructureError)
}

/// Struct to store info on LZOP block headers
#[derive(Debug, Default, Clone)]
pub struct LZOPBlockHeader {
    pub header_size: usize,
    pub compressed_size: usize,
    pub checksum_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOPBlockHeaderBytes {
    uncompressed_size: zerocopy::U32<BE>,
    compressed_size: zerocopy::U32<BE>,
    uncompressed_checksum: zerocopy::U32<BE>,
}

/// Parse an LZO block header
pub fn parse_lzop_block_header(
    lzo_data: &[u8],
    compressed_checksum_present: bool,
) -> Result<LZOPBlockHeader, StructureError> {
    const BLOCK_HEADER_SIZE: usize = 12;
    const MAX_UNCOMPRESSED_BLOCK_SIZE: u32 = 64 * 1024 * 1024;

    let (block_header, _) =
        LZOPBlockHeaderBytes::ref_from_prefix(lzo_data).map_err(|_| StructureError)?;
    // Basic sanity check on the block header values
    if block_header.compressed_size != 0
        && block_header.uncompressed_size != 0
        && block_header.uncompressed_checksum != 0
        && block_header.uncompressed_size <= MAX_UNCOMPRESSED_BLOCK_SIZE
    {
        let mut block_hdr_info = LZOPBlockHeader {
            header_size: BLOCK_HEADER_SIZE,
            compressed_size: block_header.compressed_size.get() as usize,
            ..Default::default()
        };

        // Checksum field is optional
        if compressed_checksum_present {
            block_hdr_info.checksum_size = LZO_CHECKSUM_SIZE;
        }

        return Ok(block_hdr_info);
    }

    Err(StructureError)
}

/// Parse an LZOP EOF marker, returns the size of the EOF marker (always 4 bytes)
pub fn parse_lzop_eof_marker(eof_data: &[u8]) -> Result<usize, StructureError> {
    const EOF_MARKER: u32 = 0;
    /*
     * It is unclear, but observed, that LZOP files end with 0x00000000; this is assumed to be an EOF marker,
     * as other similar compression file formats use that. This assumption could be incorrect.
     */
    let (eof_marker, _) =
        zerocopy::U32::<BE>::ref_from_prefix(eof_data).map_err(|_| StructureError)?;

    match eof_marker.get() {
        EOF_MARKER => Ok(std::mem::size_of::<zerocopy::U32<BE>>()),
        _ => Err(StructureError),
    }
}

/// Describes how to run the lzop utility to extract LZO compressed files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::lzop::lzop_extractor;
///
/// match lzop_extractor().utility {
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
pub fn lzop_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("lzop".to_string()),
        extension: "lzo".to_string(),
        arguments: vec![
            "-p".to_string(), // Output to the current directory
            "-N".to_string(), // Restore original file name
            "-d".to_string(), // Perform a decompression
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        exit_codes: vec![0],
        ..Default::default()
    }
}
