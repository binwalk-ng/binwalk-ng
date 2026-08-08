use crate::common::{crc32, is_offset_safe};
use crate::extractors::{self, Chroot, ExtractionResult, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use adler2::Adler32;
use log::debug;
use std::ffi::OsStr;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "LZO compressed data";

/// LZOP magic bytes
pub fn lzop_magic() -> Vec<Vec<u8>> {
    vec![b"\x89LZO\x00\x0D\x0A\x1A\x0A".to_vec()]
}

/// Validate an LZOP signature
pub fn lzop_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
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
        if let Ok(data_size) = get_lzo_data_size(lzop_data, lzop_header.flags) {
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
fn get_lzo_data_size(lzo_data: &[u8], flags: u32) -> Result<usize, SignatureError> {
    const MIN_BLOCK_COUNT: usize = 1;

    let available_data = lzo_data.len();
    let mut last_offset = None;
    let mut data_size: usize = 0;
    let mut block_count: usize = 0;

    // Loop until we run out of data or an invalid block header is encountered
    while is_offset_safe(available_data, data_size, last_offset) {
        // Parse the next block header
        match parse_lzop_block_header(&lzo_data[data_size..], flags) {
            Err(_) => {
                break;
            }

            Ok(block_header) => {
                // Update block count, offset, and size
                block_count += 1;
                last_offset = Some(data_size);
                let compressed_checksum_size = if block_header.compressed_checksum_present {
                    LZO_CHECKSUM_SIZE
                } else {
                    0
                };
                data_size += block_header.header_size
                    + compressed_checksum_size
                    + block_header.compressed_size;
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

const FLAG_ADLER32_D: u32 = 0x0000_0001;
const FLAG_ADLER32_C: u32 = 0x0000_0002;
const FLAG_CRC32_D: u32 = 0x0000_0100;
const FLAG_CRC32_C: u32 = 0x0000_0200;
const FLAG_FILTER: u32 = 0x0000_0800;

/// Struct to store LZOP file header info
#[derive(Debug, Default, Clone)]
pub struct LZOPFileHeader {
    pub header_size: usize,
    pub flags: u32,
    pub filter_id: u32,
    pub original_filename: Option<String>,
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
                if let Some(filter_data) =
                    lzop_data.get(LZO_HEADER_SIZE_P1..LZO_HEADER_SIZE_P1 + FILTER_SIZE)
                {
                    let (filter_id_field, _) = zerocopy::U32::<BE>::ref_from_prefix(filter_data)
                        .map_err(|_| StructureError)?;
                    lzop_info.filter_id = filter_id_field.get();
                }
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

                // Extract the original filename stored in the header
                let filename_start = header_p2_end;
                let filename_end = filename_start + lzo_header_p2.file_name_length as usize;
                if let Some(filename_bytes) = lzop_data.get(filename_start..filename_end)
                    && !filename_bytes.is_empty()
                {
                    lzop_info.original_filename = Some(crate::common::get_cstring(filename_bytes));
                }

                // Determine checksum types
                lzop_info.flags = lzo_header_p1.flags.get();

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
    pub uncompressed_size: usize,
    pub uncompressed_checksum: u32,
    pub compressed_checksum: u32,
    pub compressed_checksum_present: bool,
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
    flags: u32,
) -> Result<LZOPBlockHeader, StructureError> {
    const MAX_UNCOMPRESSED_BLOCK_SIZE: u32 = 64 * 1024 * 1024;

    let (fields, _) =
        LZOPBlockHeaderBytes::ref_from_prefix(lzo_data).map_err(|_| StructureError)?;
    let uncompressed = fields.uncompressed_size.get();
    let compressed = fields.compressed_size.get();

    if uncompressed == 0 || uncompressed > MAX_UNCOMPRESSED_BLOCK_SIZE {
        return Err(StructureError);
    }
    if compressed == 0 || compressed > uncompressed {
        return Err(StructureError);
    }

    let has_uncompressed_checksum = (flags & (FLAG_ADLER32_D | FLAG_CRC32_D)) != 0;
    let header_size = if has_uncompressed_checksum { 12 } else { 8 };

    let uncompressed_checksum = if has_uncompressed_checksum {
        fields.uncompressed_checksum.get()
    } else {
        0
    };

    let is_stored = compressed == uncompressed;
    let compressed_checksum_present = !is_stored && (flags & (FLAG_ADLER32_C | FLAG_CRC32_C)) != 0;

    let compressed_checksum = if compressed_checksum_present {
        let remaining = lzo_data.get(header_size..).ok_or(StructureError)?;
        let (checksum, _) =
            zerocopy::U32::<BE>::ref_from_prefix(remaining).map_err(|_| StructureError)?;
        checksum.get()
    } else {
        0
    };

    Ok(LZOPBlockHeader {
        header_size,
        compressed_size: compressed as usize,
        uncompressed_size: uncompressed as usize,
        uncompressed_checksum,
        compressed_checksum,
        compressed_checksum_present,
    })
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

/// Internal extractor for LZOP compressed data
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::lzop::lzop_extractor;
///
/// match lzop_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => panic!("Unexpected external extractor '{}'", cmd),
/// }
/// ```
pub fn lzop_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: ExtractorType::Internal(extract_lzo_data),
        ..Default::default()
    }
}

/// Internal extractor for LZO compressed files
pub fn extract_lzo_data(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    // Parse the LZOP header
    let lzop_header = match parse_lzop_file_header(&file_data[offset..]) {
        Ok(h) => h,
        Err(_) => return result,
    };

    let Some(lzo_data) = file_data.get(offset + lzop_header.header_size..) else {
        return result;
    };

    // Iterate through blocks and decompress each one
    let mut data_offset: usize = 0;
    let mut block_count: usize = 0;
    let mut decompressed = Vec::new();
    let has_filter = (lzop_header.flags & FLAG_FILTER) != 0;

    while let Some(block_data) = lzo_data.get(data_offset..) {
        let block_header = match parse_lzop_block_header(block_data, lzop_header.flags) {
            Ok(h) => h,
            Err(_) => break,
        };

        block_count += 1;

        let compressed_checksum_size = if block_header.compressed_checksum_present {
            LZO_CHECKSUM_SIZE
        } else {
            0
        };
        let compressed_start = data_offset + block_header.header_size + compressed_checksum_size;
        let compressed_end = compressed_start + block_header.compressed_size;

        let Some(compressed_block) = lzo_data.get(compressed_start..compressed_end) else {
            break;
        };

        let uncompressed_size = block_header.uncompressed_size;

        // Validate compressed data checksum if present (stored before the data in the stream)
        if block_header.compressed_checksum_present {
            if (lzop_header.flags & FLAG_CRC32_C) != 0
                && crc32(compressed_block) != block_header.compressed_checksum
            {
                debug!("LZOP block {} compressed CRC32 mismatch", block_count);
                return result;
            }
            if (lzop_header.flags & FLAG_ADLER32_C) != 0 {
                let mut hasher = Adler32::new();
                hasher.write_slice(compressed_block);
                if hasher.checksum() != block_header.compressed_checksum {
                    debug!("LZOP block {} compressed Adler32 mismatch", block_count);
                    return result;
                }
            }
        }

        let block_data = if block_header.compressed_size == uncompressed_size {
            let mut buf = compressed_block.to_vec();
            if has_filter {
                reverse_filter_block(&mut buf, lzop_header.filter_id);
            }
            if (lzop_header.flags & FLAG_CRC32_D) != 0
                && crc32(&buf) != block_header.uncompressed_checksum
            {
                debug!("LZOP block {} uncompressed CRC32 mismatch", block_count);
                return result;
            }
            if (lzop_header.flags & FLAG_ADLER32_D) != 0 {
                let mut hasher = Adler32::new();
                hasher.write_slice(&buf);
                if hasher.checksum() != block_header.uncompressed_checksum {
                    debug!("LZOP block {} uncompressed Adler32 mismatch", block_count);
                    return result;
                }
            }
            buf
        } else {
            let mut out_buf = vec![0u8; uncompressed_size];
            match lzo::decompress_into(compressed_block, &mut out_buf) {
                Ok(n) => {
                    let buf = &mut out_buf[..n];
                    if has_filter {
                        reverse_filter_block(buf, lzop_header.filter_id);
                    }
                    if (lzop_header.flags & FLAG_CRC32_D) != 0
                        && crc32(buf) != block_header.uncompressed_checksum
                    {
                        debug!("LZOP block {} uncompressed CRC32 mismatch", block_count);
                        return result;
                    }
                    if (lzop_header.flags & FLAG_ADLER32_D) != 0 {
                        let mut hasher = Adler32::new();
                        hasher.write_slice(buf);
                        if hasher.checksum() != block_header.uncompressed_checksum {
                            debug!("LZOP block {} uncompressed Adler32 mismatch", block_count);
                            return result;
                        }
                    }
                    out_buf[..n].to_vec()
                }
                Err(e) => {
                    debug!("LZO block {} decompression failed: {e:?}", block_count);
                    return result;
                }
            }
        };

        decompressed.extend_from_slice(&block_data);
        data_offset = compressed_end;
    }

    if block_count == 0 {
        debug!("LZOP: no valid blocks found");
        return result;
    }

    // Validate the EOF marker to confirm clean termination
    let eof_offset = data_offset;
    let eof_size = match parse_lzop_eof_marker(lzo_data.get(eof_offset..).unwrap_or_default()) {
        Ok(s) => s,
        Err(_) => {
            debug!(
                "LZOP: invalid or missing EOF marker (offset={}, remaining={})",
                eof_offset,
                lzo_data.len().saturating_sub(eof_offset)
            );
            return result;
        }
    };

    result.success = true;
    result.size = Some(lzop_header.header_size + eof_offset + eof_size);
    if let Some(chroot) = output_directory.map(Chroot::new) {
        const OUTPUT_FILE_NAME: &str = "decompressed.bin";
        let output_name = lzop_header
            .original_filename
            .as_deref()
            .and_then(|name| Path::new(name).file_name())
            .unwrap_or_else(|| OsStr::new(OUTPUT_FILE_NAME));
        result.success = chroot.create_file(output_name, &decompressed);
    }

    result
}

/// Reverse the LZOP pre-compression filter on one block of decompressed data.
/// Each block was independently filtered during compression and must be
/// independently reversed with a fresh initial state.
/// Filter ID 0 = no-op (passthrough). Filter ID 1 = UR filter. Unknown
/// filter IDs are treated as a no-op.
fn reverse_filter_block(data: &mut [u8], filter_id: u32) {
    match filter_id {
        0 => {}
        1 => {
            // t_add1: cumulative sum (applied during decompression to undo t_sub1)
            let mut b: u8 = 0;
            for byte in data.iter_mut() {
                b = b.wrapping_add(*byte);
                *byte = b;
            }
        }
        2..=16 => {
            // t_add: multi-byte delta decoding (applied during decompression to undo t_sub)
            let n = filter_id as usize;
            if data.len() <= n {
                return;
            }
            let mut circ = vec![0u8; n];
            let mut i = n - 1;
            for byte in data.iter_mut() {
                circ[i] = circ[i].wrapping_add(*byte);
                *byte = circ[i];
                if i == 0 {
                    i = n - 1;
                } else {
                    i -= 1;
                }
            }
        }
        _ => {}
    }
}
