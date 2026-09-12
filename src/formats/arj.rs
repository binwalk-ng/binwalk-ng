use crate::common::{crc32, epoch_to_string, get_cstring};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

pub const DESCRIPTION: &str = "ARJ archive data";
pub fn arj_magic() -> Vec<Vec<u8>> {
    vec![b"\x60\xea".to_vec()]
}

pub fn arj_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let arj_header = match parse_arj_header(&file_data[offset..]) {
        Ok(h) => h,
        Err(_) => return Err(SignatureError),
    };

    let available_data = file_data.len() - offset;
    if arj_header.header_size > available_data {
        return Err(SignatureError);
    }

    // Verify the header CRC
    let data = &file_data[offset..];
    let header_data = &data[HDR_DATA_OFFSET..HDR_DATA_OFFSET + arj_header.basic_hdr_size];
    if crc32(header_data) != arj_header.header_crc {
        return Err(SignatureError);
    }

    Ok(SignatureResult {
        description: format!(
            "{}, header size: {}, version {}, minimum version to extract: {}, flags: {}, compression method: {}, file type: {}, original name: {}, original file date: {}, compressed file size: {}, uncompressed file size: {}, os: {}",
            DESCRIPTION,
            arj_header.header_size,
            arj_header.version,
            arj_header.min_version,
            arj_header.flags,
            arj_header.compression_method,
            arj_header.file_type,
            arj_header.original_name,
            arj_header.original_file_date,
            arj_header.compressed_file_size,
            arj_header.uncompressed_file_size,
            arj_header.host_os,
        ),
        offset,
        size: arj_header.header_size,
        confidence: CONFIDENCE_HIGH,
        extraction_declined: arj_header.file_type != *"comment header",
        ..Default::default()
    })
}

#[derive(Debug, Default, Clone)]
pub struct ARJHeader {
    pub header_size: usize,
    pub version: u8,
    pub min_version: u8,
    pub flags: String,
    pub host_os: String,
    pub compression_method: String,
    pub file_type: String,
    pub original_name: String,
    pub original_file_date: String,
    pub compressed_file_size: usize,
    pub uncompressed_file_size: usize,
    pub basic_hdr_size: usize,
    pub header_crc: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ARJHeaderBytes {
    magic: zerocopy::U16<LE>,
    basic_hdr_size: zerocopy::U16<LE>,
    first_hdr_size: u8,
    archiver_version: u8,
    min_version: u8,
    host_os: u8,
    internal_flags: u8,
    compression_method: u8,
    file_type: u8,
    password_modifier: u8,
    datetime_file: zerocopy::U32<LE>,
    compressed_filesize: zerocopy::I32<LE>,
    original_filesize: zerocopy::I32<LE>,
    original_file_crc32: zerocopy::U32<LE>,
    entry_pos: zerocopy::U16<LE>,
    file_attributes: zerocopy::U16<LE>,
    ext_flags: u8,
    chapter_number: u8,
}

const HDR_DATA_OFFSET: usize = std::mem::offset_of!(ARJHeaderBytes, first_hdr_size);

pub fn parse_arj_header(arj_data: &[u8]) -> Result<ARJHeader, StructureError> {
    let (arj_header, _) = ARJHeaderBytes::ref_from_prefix(arj_data).map_err(|_| StructureError)?;

    let basic_hdr_size = arj_header.basic_hdr_size.get() as usize;

    // Minimum header data block size (excluding magic + basic_hdr_size)
    const MIN_HDR_SIZE: usize = std::mem::size_of::<ARJHeaderBytes>() - HDR_DATA_OFFSET;
    const CRC_SIZE: usize = std::mem::size_of::<u32>();

    if basic_hdr_size < MIN_HDR_SIZE || HDR_DATA_OFFSET + basic_hdr_size + CRC_SIZE > arj_data.len()
    {
        return Err(StructureError);
    }

    // Header CRC is stored after the variable-length header data block, so it can't be part of the fixed-size struct
    let crc_start = HDR_DATA_OFFSET + basic_hdr_size;
    let header_crc = u32::from_le_bytes(
        arj_data[crc_start..crc_start + CRC_SIZE]
            .try_into()
            .expect("bad slice"),
    );

    // Validate version range
    if !(1..=16).contains(&arj_header.archiver_version)
        || !(1..=16).contains(&arj_header.min_version)
        || arj_header.archiver_version < arj_header.min_version
    {
        return Err(StructureError);
    }

    let mut flags = match arj_header.internal_flags & 0x01 {
        0 => "no password".to_string(),
        _ => "password".to_string(),
    };
    if arj_header.internal_flags & 0x04 != 0 {
        flags = format!("{flags}|multi-volume");
    }

    if arj_header.internal_flags & 0x10 != 0 {
        flags = format!("{flags}|slash-switched");
    }
    if arj_header.internal_flags & 0x20 != 0 {
        flags = format!("{flags}|backup");
    }

    let host_os = match arj_header.host_os {
        0 => "MS-DOS",
        1 => "PRIMOS",
        2 => "UNIX",
        3 => "AMIGA",
        4 => "MAC-OS",
        5 => "OS/2",
        6 => "APPLE GS",
        7 => "ATARI ST",
        8 => "NeXT",
        9 => "VAX VMS",
        10 => "WIN95",
        11 => "WINNT",
        _ => return Err(StructureError),
    }
    .to_string();

    let compression_method = match arj_header.compression_method {
        0 => "stored",
        1 => "compressed most",
        2 => "compressed",
        3 => "compressed faster",
        4 => "compressed fastest",
        _ => return Err(StructureError),
    }
    .to_string();

    let file_type = match arj_header.file_type {
        0 => "binary",
        1 => "7-bit text",
        2 => "comment header",
        3 => "directory",
        4 => "volume label",
        5 => "chapter",
        6 => "UNIX special",
        _ => return Err(StructureError),
    }
    .to_string();

    let compressed_file_size = arj_header.compressed_filesize.get();
    if compressed_file_size < 0 {
        return Err(StructureError);
    }
    let uncompressed_file_size = arj_header.original_filesize.get();
    if uncompressed_file_size < 0 {
        return Err(StructureError);
    }

    // first_hdr_size is the offset within the header data block to the filename
    let first_hdr_size = arj_header.first_hdr_size as usize;
    if first_hdr_size < MIN_HDR_SIZE || first_hdr_size >= basic_hdr_size {
        return Err(StructureError);
    }

    // Filename starts at first_hdr_size within the header data block
    let original_name = arj_data
        .get(HDR_DATA_OFFSET + first_hdr_size..crc_start)
        .map_or_else(|| "".to_string(), get_cstring);

    Ok(ARJHeader {
        header_size: HDR_DATA_OFFSET + basic_hdr_size + CRC_SIZE,
        version: arj_header.archiver_version,
        min_version: arj_header.min_version,
        flags,
        host_os,
        compression_method,
        file_type,
        original_name,
        original_file_date: epoch_to_string(arj_header.datetime_file.get()),
        compressed_file_size: compressed_file_size as usize,
        uncompressed_file_size: uncompressed_file_size as usize,
        basic_hdr_size,
        header_crc,
    })
}
