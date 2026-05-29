use crate::common::{crc32, is_offset_safe};
use crate::formats::lzma::lzma_decompress;
use crate::formats::sevenzip::sevenzip_extractor;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "XZ compressed data";

/// XZ magic bytes
pub fn xz_magic() -> Vec<Vec<u8>> {
    vec![b"\xFD\x37\x7a\x58\x5a\x00".to_vec()]
}

/// Validates XZ signatures
pub fn xz_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let mut next_offset = offset;
    let mut previous_offset = None;
    let mut stream_header_count = 0;
    let available_data = file_data.len() - offset;

    // XZ streams can be concatenated together, need to process them all to determine the size of an XZ file
    while is_offset_safe(available_data, next_offset, previous_offset) {
        // Parse the next XZ header to validate the header CRC
        match parse_xz_header(&file_data[next_offset..]) {
            Err(_) => break,
            Ok(_) => {
                // Header is valid
                stream_header_count += 1;

                // Do an extraction dry-run to make sure the data decompresses correctly
                let dry_run = lzma_decompress(file_data, next_offset, None);

                // If dry run was a success, update the offset and size fields
                if dry_run.success
                    && let Some(size) = dry_run.size
                {
                    previous_offset = Some(next_offset);
                    next_offset += size;
                    result.size += size;
                // Else, report that the data is malformed and stop processing XZ streams
                } else {
                    // 7z may be able to at least partially extract malformed data streams
                    result.preferred_extractor = Some(sevenzip_extractor());
                    result.description = format!(
                        "{}, valid header with malformed data stream",
                        result.description
                    );
                    break;
                }
            }
        }
    }

    // Return success if at least one valid XZ stream header was found
    if stream_header_count > 0 {
        // Only report the total size if we were able to determine the total size
        if result.size > 0 {
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
        }
        return Ok(result);
    }

    Err(SignatureError)
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct XZHeader {
    magic_p1: zerocopy::U32<LE>,
    magic_p2: zerocopy::U16<LE>,
    flags: zerocopy::U16<LE>,
    header_crc: zerocopy::U32<LE>,
}

/// Parse and validate an XZ header, returns the header size
pub fn parse_xz_header(xz_data: &[u8]) -> Result<usize, StructureError> {
    const XZ_CRC_END: usize = 8;
    const XZ_CRC_START: usize = 6;
    const XZ_HEADER_SIZE: usize = 12;

    let (xz_header, _) = XZHeader::ref_from_prefix(xz_data).map_err(|_| StructureError)?;

    if let Some(crc_data) = xz_data.get(XZ_CRC_START..XZ_CRC_END)
        && xz_header.header_crc == crc32(crc_data)
    {
        return Ok(XZ_HEADER_SIZE);
    }

    Err(StructureError)
}
