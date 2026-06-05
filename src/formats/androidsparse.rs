use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "Android sparse image";

/// Magic bytes for Android Sparse files
pub fn android_sparse_magic() -> Vec<Vec<u8>> {
    vec![b"\x3A\xFF\x26\xED".to_vec()]
}

/// Parses Android Sparse files
pub fn android_sparse_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Default result, returned on success
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do a dry-run extraction
    let dry_run = extract_android_sparse(file_data, offset, None);

    if dry_run.success
        && let Some(total_size) = dry_run.size
    {
        // Dry-run went OK, parse the header to get some useful info to report
        if let Ok(header) = parse_android_sparse_header(&file_data[offset..]) {
            // Update reported size and description
            result.size = total_size;
            result.description = format!(
                "{}, version {}.{}, header size: {}, block size: {}, chunk count: {}, total size: {} bytes",
                result.description,
                header.major_version,
                header.minor_version,
                header.header_size,
                header.block_size,
                header.chunk_count,
                total_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Storage struct for AndroidSparse file header info
#[derive(Debug, Default, Clone)]
pub struct AndroidSparseHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub header_size: usize,
    pub block_size: usize,
    /// Total number of blocks in the unsparsed output image
    pub block_count: usize,
    pub chunk_count: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AndroidSparseHeaderBytes {
    magic: zerocopy::U32<LE>,
    major_version: zerocopy::U16<LE>,
    minor_version: zerocopy::U16<LE>,
    header_size: zerocopy::U16<LE>,
    chunk_header_size: zerocopy::U16<LE>,
    block_size: zerocopy::U32<LE>,
    block_count: zerocopy::U32<LE>,
    total_chunks: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
}

/// Parse Android Sparse header structures
pub fn parse_android_sparse_header(
    sparse_data: &[u8],
) -> Result<AndroidSparseHeader, StructureError> {
    // Version must be 1.0
    const MAJOR_VERSION: u16 = 1;
    const MINOR_VERSION: u16 = 0;

    // Blocks must be aligned on a 4-byte boundary
    const BLOCK_ALIGNMENT: u32 = 4;

    // Expected value for the reported chunk header size
    const CHUNK_HEADER_SIZE: u16 = 12;

    let expected_header_size = std::mem::size_of::<AndroidSparseHeaderBytes>();

    // Parse the header
    let (header, _) =
        AndroidSparseHeaderBytes::ref_from_prefix(sparse_data).map_err(|_| StructureError)?;

    // Sanity check header values
    if header.major_version.get() == MAJOR_VERSION
        && header.minor_version.get() == MINOR_VERSION
        && header.header_size.get() as usize == expected_header_size
        && header.chunk_header_size.get() == CHUNK_HEADER_SIZE
        && header.block_size.get().is_multiple_of(BLOCK_ALIGNMENT)
    {
        return Ok(AndroidSparseHeader {
            major_version: header.major_version.get(),
            minor_version: header.minor_version.get(),
            header_size: header.header_size.get() as usize,
            block_size: header.block_size.get() as usize,
            block_count: header.block_count.get() as usize,
            chunk_count: header.total_chunks.get() as usize,
        });
    }

    Err(StructureError)
}

/// Storage structure for Android Sparse chunk headers
#[derive(Debug, Default, Clone)]
pub struct AndroidSparseChunkHeader {
    pub header_size: usize,
    pub data_size: usize,
    pub block_count: usize,
    pub is_crc: bool,
    pub is_raw: bool,
    pub is_fill: bool,
    pub is_dont_care: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AndroidSparseChunkHeaderBytes {
    chunk_type: zerocopy::U16<LE>,
    reserved: zerocopy::U16<LE>,
    output_block_count: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
}

/// Parse the header for an Android Sparse chunk
pub fn parse_android_sparse_chunk_header(
    chunk_data: &[u8],
) -> Result<AndroidSparseChunkHeader, StructureError> {
    // Known chunk types
    const CHUNK_TYPE_RAW: u16 = 0xCAC1;
    const CHUNK_TYPE_FILL: u16 = 0xCAC2;
    const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
    const CHUNK_TYPE_CRC: u16 = 0xCAC4;

    let mut chonker = AndroidSparseChunkHeader {
        header_size: std::mem::size_of::<AndroidSparseChunkHeaderBytes>(),
        ..Default::default()
    };

    // Expected payload sizes by chunk type (per the Android sparse spec):
    //   FILL:      4 bytes (the repeated fill value)
    //   DONT_CARE: 0 bytes
    //   CRC:       4 bytes (CRC32)
    //   RAW:       block_count * block_size bytes (validated by the extractor,
    //              which has access to the sparse header)
    const FILL_DATA_SIZE: usize = 4;
    const DONT_CARE_DATA_SIZE: usize = 0;
    const CRC_DATA_SIZE: usize = 4;

    // Parse the header
    let (chunk_header, _) =
        AndroidSparseChunkHeaderBytes::ref_from_prefix(chunk_data).map_err(|_| StructureError)?;
    // Make sure the reserved field is zero
    if chunk_header.reserved == 0 {
        // Populate the structure values
        chonker.block_count = chunk_header.output_block_count.get() as usize;
        chonker.data_size = (chunk_header.total_size.get() as usize)
            .checked_sub(chonker.header_size)
            .ok_or(StructureError)?;
        chonker.is_crc = chunk_header.chunk_type == CHUNK_TYPE_CRC;
        chonker.is_raw = chunk_header.chunk_type == CHUNK_TYPE_RAW;
        chonker.is_fill = chunk_header.chunk_type == CHUNK_TYPE_FILL;
        chonker.is_dont_care = chunk_header.chunk_type == CHUNK_TYPE_DONT_CARE;

        // The chunk type must be one of the known chunk types
        if !(chonker.is_crc || chonker.is_raw || chonker.is_fill || chonker.is_dont_care) {
            return Err(StructureError);
        }

        // Reject chunks whose declared payload doesn't match the spec for their
        // type. In particular, a FILL chunk with data_size == 0 would cause the
        // extractor to loop forever trying to fill a block with no data.
        if chonker.is_fill && chonker.data_size != FILL_DATA_SIZE {
            return Err(StructureError);
        }
        if chonker.is_dont_care && chonker.data_size != DONT_CARE_DATA_SIZE {
            return Err(StructureError);
        }
        if chonker.is_crc && chonker.data_size != CRC_DATA_SIZE {
            return Err(StructureError);
        }

        return Ok(chonker);
    }

    Err(StructureError)
}

/// Defines the internal extractor function for extracting Android Sparse files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::androidsparse::android_sparse_extractor;
///
/// match android_sparse_extractor().utility {
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
pub fn android_sparse_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_android_sparse),
        ..Default::default()
    }
}

/// Android sparse internal extractor
pub fn extract_android_sparse(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "unsparsed.img";

    // Refuse to produce an unsparsed image larger than this. Real-world Android
    // partitions are well under this cap; anything beyond is almost certainly a
    // crafted header trying to exhaust disk space.
    const MAX_UNSPARSED_SIZE: usize = 16 * 1024 * 1024 * 1024; // 16 GiB

    let mut result = ExtractionResult::default();

    // Parse the sparse file header
    if let Ok(sparse_header) = parse_android_sparse_header(&file_data[offset..]) {
        match sparse_header
            .block_count
            .checked_mul(sparse_header.block_size)
        {
            Some(s) if s <= MAX_UNSPARSED_SIZE => {}
            _ => return result,
        };

        let available_data: usize = file_data.len();
        let mut last_chunk_offset: Option<usize> = None;
        let mut processed_chunk_count: usize = 0;
        let mut blocks_written: usize = 0;
        let mut next_chunk_offset: usize = offset + sparse_header.header_size;

        while is_offset_safe(available_data, next_chunk_offset, last_chunk_offset) {
            // Parse the next chunk's header
            match parse_android_sparse_chunk_header(&file_data[next_chunk_offset..]) {
                Err(_) => {
                    break;
                }

                Ok(chunk_header) => {
                    // A single chunk can never describe more blocks than the
                    // total declared by the sparse header. This bounds the
                    // cumulative output to max_output_size.
                    blocks_written = match blocks_written.checked_add(chunk_header.block_count) {
                        Some(n) if n <= sparse_header.block_count => n,
                        _ => break,
                    };

                    // For RAW chunks the payload must exactly cover block_count
                    // blocks; otherwise the extracted image would be silently
                    // misaligned and an absurd block_count would still drive
                    // unbounded reads via file_data.get().
                    if chunk_header.is_raw {
                        let expected = chunk_header
                            .block_count
                            .checked_mul(sparse_header.block_size);
                        if expected != Some(chunk_header.data_size) {
                            break;
                        }
                    }

                    // If not a dry run, extract the data from the next chunk
                    if let Some(output_directory) = output_directory {
                        let chroot = Chroot::new(output_directory);
                        let chunk_data_start: usize = next_chunk_offset + chunk_header.header_size;
                        let chunk_data_end: usize = chunk_data_start + chunk_header.data_size;

                        if let Some(chunk_data) = file_data.get(chunk_data_start..chunk_data_end) {
                            if !extract_chunk(
                                &sparse_header,
                                &chunk_header,
                                chunk_data,
                                OUTFILE_NAME,
                                &chroot,
                            ) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    processed_chunk_count += 1;
                    last_chunk_offset = Some(next_chunk_offset);
                    next_chunk_offset += chunk_header.header_size + chunk_header.data_size;
                }
            }
        }

        // Make sure the number of processed chunks equals the number of chunks reported in the sparse flie header
        if processed_chunk_count == sparse_header.chunk_count {
            result.success = true;
            result.size = Some(next_chunk_offset - offset);
        }
    }

    result
}

// Extract a sparse file chunk to disk
fn extract_chunk(
    sparse_header: &AndroidSparseHeader,
    chunk_header: &AndroidSparseChunkHeader,
    chunk_data: &[u8],
    outfile: &str,
    chroot: &Chroot,
) -> bool {
    if chunk_header.is_raw {
        // Raw chunks are just data chunks stored verbatim
        if !chroot.append_to_file(outfile, chunk_data) {
            return false;
        }
    } else if chunk_header.is_fill {
        // The parser rejects FILL chunks whose payload isn't the spec-required
        // 4 bytes, but guard here too: an empty fill value would make the inner
        // loop below spin forever.
        if chunk_data.is_empty() {
            return false;
        }
        // Fill chunks are block_count blocks that contain a repeated sequence of data (typically 4-bytes repeated over and over again)
        for _ in 0..chunk_header.block_count {
            let mut fill_block: Vec<u8> = vec![];

            // Fill each block with the repeated data
            while fill_block.len() < sparse_header.block_size {
                fill_block.extend(chunk_data);
            }

            // Append fill block to file
            if !chroot.append_to_file(outfile, &fill_block) {
                return false;
            }
        }
    } else if chunk_header.is_dont_care {
        let null_block = vec![0u8; sparse_header.block_size];

        // Write block_count NULL blocks to disk
        for _ in 0..chunk_header.block_count {
            if !chroot.append_to_file(outfile, &null_block) {
                return false;
            }
        }
    }

    true
}
