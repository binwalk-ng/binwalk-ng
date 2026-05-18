use crate::common;
use crate::common::get_cstring;
use crate::extractors::inflate;
use crate::extractors::{ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "gzip compressed data";

/// Gzip magic bytes, plus compression type field (always 8 for deflate)
pub fn gzip_magic() -> Vec<Vec<u8>> {
    vec![b"\x1f\x8b\x08".to_vec()]
}

/// Validates gzip signatures
pub fn gzip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Length of the GZIP CRC located at the end of the deflate data stream
    const GZIP_CRC_SIZE: usize = 4;
    // Length of the ISIZE field located after the CRC field
    const GZIP_ISIZE_SIZE: usize = 4;

    // Do a dry-run decompression
    let dry_run = gzip_decompress(file_data, offset, None);

    // If dry-run was successful, this is almost certainly a valid gzip file
    if dry_run.success {
        // Get the size of the deflate data stream
        if let Some(deflate_data_size) = dry_run.size {
            // The dry run has already validated the header, but we want some header info to display to the user
            if let Ok(gzip_header) = parse_gzip_header(&file_data[offset..]) {
                // Original file name is optional
                let mut original_file_name_text: String = "".to_string();

                if !gzip_header.original_name.is_empty() {
                    original_file_name_text =
                        format!(" original file name: \"{}\",", gzip_header.original_name);
                }

                // Total size of the gzip file is the size of the header, plus the size of the compressed data, plus the trailing CRC and ISIZE fields
                let total_size =
                    gzip_header.size + deflate_data_size + GZIP_CRC_SIZE + GZIP_ISIZE_SIZE;

                return Ok(SignatureResult {
                    offset,
                    size: total_size,
                    confidence: CONFIDENCE_HIGH,
                    description: format!(
                        "{},{} operating system: {}, timestamp: {}, total size: {} bytes",
                        DESCRIPTION,
                        original_file_name_text,
                        gzip_header.os,
                        common::epoch_to_string(gzip_header.timestamp),
                        total_size,
                    ),
                    ..Default::default()
                });
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store useful Gzip header info
#[derive(Debug, Clone, Default)]
pub struct GzipHeader {
    pub os: String,
    pub size: usize,
    pub comment: String,
    pub timestamp: u32,
    pub original_name: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GzipHeaderBytes {
    magic: zerocopy::U16<LE>,
    compression_method: u8,
    flags: u8,
    timestamp: zerocopy::U32<LE>,
    extra_flags: u8,
    osid: u8,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GzipHeaderExtraBytes {
    id: zerocopy::U16<LE>,
    extra_data_len: zerocopy::U16<LE>,
}

/// Parses a Gzip file header
pub fn parse_gzip_header(header_data: &[u8]) -> Result<GzipHeader, StructureError> {
    // Some expected constant values
    const CRC_SIZE: usize = 2;
    const NULL_BYTE_SIZE: usize = 1;
    const DEFLATE_COMPRESSION: u8 = 8;

    const FLAG_CRC: u8 = 0b0000_0010;
    const FLAG_EXTRA: u8 = 0b0000_0100;
    const FLAG_NAME: u8 = 0b0000_1000;
    const FLAG_COMMENT: u8 = 0b0001_0000;
    const FLAG_RESERVED: u8 = 0b1110_0000;

    // Parse the gzip header
    let (gzip_header, _) =
        GzipHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    // Sanity check; compression type should be deflate, reserved flag bits should not be set, OS ID should be a known value
    if (gzip_header.flags & FLAG_RESERVED) == 0
        && gzip_header.compression_method == DEFLATE_COMPRESSION
    {
        let os = match gzip_header.osid {
            0 => "FAT filesystem (MS-DOS, OS/2, NT/Win32",
            1 => "Amiga",
            2 => "VMS (or OpenVMS)",
            3 => "Unix",
            4 => "VM/CMS",
            5 => "Atari TOS",
            6 => "HPFS filesystem (OS/2, NT)",
            7 => "Macintosh",
            8 => "Z-System",
            9 => "CP/M",
            10 => "TOPS-20",
            11 => "NTFS filesystem (NT)",
            12 => "QDOS",
            13 => "Acorn RISCOS",
            255 => "unknown",
            _ => return Err(StructureError),
        };
        let mut header_info = GzipHeader {
            size: std::mem::size_of::<GzipHeaderBytes>(),
            timestamp: gzip_header.timestamp.get(),
            os: os.to_string(),
            ..Default::default()
        };

        // Check if the optional "extra" data follows the standard Gzip header
        if (gzip_header.flags & FLAG_EXTRA) != 0 {
            // File offsets and sizes for parsing the extra header
            let extra_header_size = std::mem::size_of::<GzipHeaderExtraBytes>();
            let extra_header_start: usize = header_info.size;
            let extra_header_end: usize = extra_header_start + extra_header_size;

            match header_data.get(extra_header_start..extra_header_end) {
                None => {
                    return Err(StructureError);
                }
                Some(extra_header_data) => {
                    // Parse the extra header and update the header_info.size to include this data
                    let (extra_header, _) =
                        GzipHeaderExtraBytes::ref_from_prefix(extra_header_data)
                            .map_err(|_| StructureError)?;
                    header_info.size +=
                        extra_header_size + extra_header.extra_data_len.get() as usize;
                }
            }
        }

        // If the NULL-terminated original file name is included, it will be next
        if (gzip_header.flags & FLAG_NAME) != 0 {
            match header_data.get(header_info.size..) {
                None => {
                    return Err(StructureError);
                }
                Some(file_name_bytes) => {
                    header_info.original_name = get_cstring(file_name_bytes);
                    // The value returned by get_cstring does not include the terminating NULL byte
                    header_info.size += header_info.original_name.len() + NULL_BYTE_SIZE;
                }
            }
        }

        // If a NULL-terminated comment is included, it will be next
        if (gzip_header.flags & FLAG_COMMENT) != 0 {
            match header_data.get(header_info.size..) {
                None => {
                    return Err(StructureError);
                }
                Some(comment_bytes) => {
                    header_info.comment = get_cstring(comment_bytes);
                    // The value returned by get_cstring does not include the terminating NULL byte
                    header_info.size += header_info.comment.len() + NULL_BYTE_SIZE;
                }
            }
        }

        // Finally, a checksum field may be included
        if (gzip_header.flags & FLAG_CRC) != 0 {
            header_info.size += CRC_SIZE;
        }

        // Deflate data should start at header_info.size; make sure this offset is sane
        if header_data.len() >= header_info.size {
            return Ok(header_info);
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor function for decompressing gzip data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::gzip::gzip_extractor;
///
/// match gzip_extractor().utility {
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
pub fn gzip_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(gzip_decompress),
        ..Default::default()
    }
}

/// Internal extractor for gzip compressed data
pub fn gzip_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut exresult = ExtractionResult::default();

    // Parse the gzip header
    if let Ok(gzip_header) = parse_gzip_header(&file_data[offset..]) {
        // Deflate compressed data starts at the end of the gzip header
        let deflate_data_start: usize = offset + gzip_header.size;

        if file_data.len() > deflate_data_start {
            let inflate_result =
                inflate::inflate_decompressor(file_data, deflate_data_start, output_directory);
            if inflate_result.success {
                exresult.success = true;
                exresult.size = Some(inflate_result.size);
            }
        }
    }

    exresult
}
