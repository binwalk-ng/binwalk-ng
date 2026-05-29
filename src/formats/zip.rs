use crate::common::is_offset_safe;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use aho_corasick::AhoCorasick;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "ZIP archive";

/// ZIP file entry magic bytes
pub fn zip_magic() -> Vec<Vec<u8>> {
    vec![b"PK\x03\x04".to_vec()]
}

/// Validates a ZIP file entry signature
pub fn zip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the ZIP file header
    if let Ok(zip_file_header) = parse_zip_header(&file_data[offset..]) {
        // Locate the end-of-central-directory header, which must come after the zip local file entries
        match find_zip_eof(file_data, offset) {
            Ok(zip_info) => {
                result.size = zip_info.eof - offset;
                result.description = format!(
                    "{}, version: {}.{}, file count: {}, total size: {} bytes",
                    result.description,
                    zip_file_header.version_major,
                    zip_file_header.version_minor,
                    zip_info.file_count,
                    result.size
                );
            }
            // If the ZIP file is corrupted and no EOCD header exists, attempt to parse all the individual ZIP file headers
            Err(_) => {
                let available_data = file_data.len() - offset;
                let mut previous_file_header_offset = None;
                let mut next_file_header_offset = offset + zip_file_header.total_size;

                while is_offset_safe(
                    available_data,
                    next_file_header_offset,
                    previous_file_header_offset,
                ) {
                    match parse_zip_header(&file_data[next_file_header_offset..]) {
                        Ok(zip_header) => {
                            previous_file_header_offset = Some(next_file_header_offset);
                            next_file_header_offset += zip_header.total_size;
                        }
                        Err(_) => {
                            result.size = next_file_header_offset - offset;
                            result.description = format!(
                                "{}, version: {}.{}, missing end-of-central-directory header, total size: {} bytes",
                                result.description,
                                zip_file_header.version_major,
                                zip_file_header.version_minor,
                                result.size
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Only return success if the ZIP file size was identified
        if result.size > 0 {
            return Ok(result);
        }
    }

    Err(SignatureError)
}

pub struct ZipEOCDInfo {
    pub eof: usize,
    pub file_count: usize,
}

/// Need to grep the rest of the file data to locate the end-of-central-directory header, which tells us where the ZIP file ends.
pub fn find_zip_eof(file_data: &[u8], offset: usize) -> Result<ZipEOCDInfo, SignatureError> {
    // This magic string assumes that the disk_number and central_directory_disk_number are 0
    const ZIP_EOCD_MAGIC: &[u8; 8] = b"PK\x05\x06\x00\x00\x00\x00";

    // Instatiate AhoCorasick search with the ZIP EOCD magic bytes
    let grep = AhoCorasick::new(vec![ZIP_EOCD_MAGIC]).unwrap();

    // Find all matching ZIP EOCD patterns
    for eocd_match in grep.find_overlapping_iter(&file_data[offset..]) {
        // Calculate the start and end of the fixed-size portion of the ZIP EOCD header in the file data
        let eocd_start: usize = eocd_match.start() + offset;

        // Parse the end-of-central-directory header
        if let Some(eocd_data) = file_data.get(eocd_start..)
            && let Ok(eocd_header) = parse_eocd_header(eocd_data)
        {
            return Ok(ZipEOCDInfo {
                eof: eocd_start + eocd_header.size,
                file_count: eocd_header.file_count,
            });
        }
    }

    // No valid EOCD record found :(
    Err(SignatureError)
}

#[derive(Debug, Default, Clone)]
pub struct ZipFileHeader {
    pub data_size: usize,
    pub header_size: usize,
    pub total_size: usize,
    pub version_major: u16,
    pub version_minor: u8,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ZipHeaderBytes {
    magic: zerocopy::U32<LE>,
    version: zerocopy::U16<LE>,
    flags: zerocopy::U16<LE>,
    compression: zerocopy::U16<LE>,
    modification_time: zerocopy::U16<LE>,
    modification_date: zerocopy::U16<LE>,
    crc: zerocopy::U32<LE>,
    compressed_size: zerocopy::U32<LE>,
    uncompressed_size: zerocopy::U32<LE>,
    file_name_len: zerocopy::U16<LE>,
    extra_field_len: zerocopy::U16<LE>,
}

/// Validate a ZIP file header
pub fn parse_zip_header(zip_data: &[u8]) -> Result<ZipFileHeader, StructureError> {
    // Unused flag bits
    const UNUSED_FLAGS_MASK: u16 = 0b11010111_10000000;

    // Encrypted compression type
    const COMPRESSION_ENCRYPTED: u16 = 99;

    let allowed_compression_methods = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        8,
        9,
        10,
        12,
        14,
        18,
        19,
        20,
        93,
        94,
        95,
        96,
        97,
        98,
        COMPRESSION_ENCRYPTED,
    ];

    let mut result = ZipFileHeader::default();

    // Parse the ZIP local file structure
    let (zip_local_file_header, _) =
        ZipHeaderBytes::ref_from_prefix(zip_data).map_err(|_| StructureError)?;

    // Unused/reserved flag bits should be 0
    if (zip_local_file_header.flags & UNUSED_FLAGS_MASK) == 0 {
        // Specified compression method should be one of the defined ZIP compression methods
        if allowed_compression_methods.contains(&zip_local_file_header.compression.get()) {
            result.version_major = zip_local_file_header.version.get() / 10;
            result.version_minor = (zip_local_file_header.version.get() % 10) as u8;
            result.header_size = std::mem::size_of::<ZipHeaderBytes>()
                + zip_local_file_header.file_name_len.get() as usize
                + zip_local_file_header.extra_field_len.get() as usize;
            result.data_size = if zip_local_file_header.compressed_size > 0 {
                zip_local_file_header.compressed_size.get() as usize
            } else {
                zip_local_file_header.uncompressed_size.get() as usize
            };
            result.total_size = result.header_size + result.data_size;
            return Ok(result);
        }
    }

    Err(StructureError)
}

/// Stores info about a ZIP end-of-central-directory header
#[derive(Debug, Default, Clone)]
pub struct ZipEOCDHeader {
    pub size: usize,
    pub file_count: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ZipEOCDHeaderBytes {
    magic: zerocopy::U32<LE>,
    disk_number: zerocopy::U16<LE>,
    central_directory_disk_number: zerocopy::U16<LE>,
    central_directory_disk_entries: zerocopy::U16<LE>,
    central_directory_total_entries: zerocopy::U16<LE>,
    central_directory_size: zerocopy::U32<LE>,
    central_directory_offset: zerocopy::U32<LE>,
    comment_length: zerocopy::U16<LE>,
}

/// Parse a ZIP end-of-central-directory header
pub fn parse_eocd_header(eocd_data: &[u8]) -> Result<ZipEOCDHeader, StructureError> {
    // Parse the EOCD header
    let (zip_eocd_header, _) =
        ZipEOCDHeaderBytes::ref_from_prefix(eocd_data).map_err(|_| StructureError)?;

    // Assume there is only one "disk", so disk entries and total entries should be the same, and the ZIP archive should contain at least one file
    if zip_eocd_header.central_directory_disk_entries
        == zip_eocd_header.central_directory_total_entries
        && zip_eocd_header.central_directory_total_entries > 0
    {
        // An optional comment may follow the EOCD header; include the comment length in the offset of the ZIP EOF offset
        let zip_eof: usize = std::mem::size_of::<ZipEOCDHeaderBytes>()
            + zip_eocd_header.comment_length.get() as usize;

        return Ok(ZipEOCDHeader {
            size: zip_eof,
            file_count: zip_eocd_header.central_directory_total_entries.get() as usize,
        });
    }

    Err(StructureError)
}
