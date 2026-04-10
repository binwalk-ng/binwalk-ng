use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

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
