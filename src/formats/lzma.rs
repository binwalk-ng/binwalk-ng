use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use liblzma::stream::{Action, Status, Stream};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "LZMA compressed data";

/// Builds a list of common LZMA magic bytes (properties + dictionary sizes)
pub fn lzma_magic() -> Vec<Vec<u8>> {
    // Common LZMA properties
    let supported_properties = [0x5D, 0x6E, 0x6D, 0x6C];

    let supported_dictionary_sizes = [
        0x10_00_00_00u32,
        0x20_00_00_00u32,
        0x01_00_00_00u32,
        0x02_00_00_00u32,
        0x04_00_00_00u32,
        0x00_80_00_00u32,
        0x00_40_00_00u32,
        0x00_20_00_00u32,
        0x00_10_00_00u32,
        0x00_08_00_00u32,
        0x00_02_00_00u32,
        0x00_01_00_00u32,
    ];

    let mut magic_signatures: Vec<Vec<u8>> =
        Vec::with_capacity(supported_properties.len() * supported_dictionary_sizes.len());

    /*
     * Build a list of magic signatures to search for based on the supported property and dictionary values.
     * This means having a lot of LZMA signatures, but they are less prone to false positives than searching
     * for a more generic, but shorter, signature, such as b"\x5d\x00\x00". This results in less validation
     * of false positives, improving analysis times.
     */
    for property in supported_properties {
        for dictionary_size in &supported_dictionary_sizes {
            let mut magic: Vec<u8> = Vec::with_capacity(5);
            magic.push(property);
            magic.extend(dictionary_size.to_le_bytes().to_vec());
            magic_signatures.push(magic);
        }
    }

    magic_signatures
}

/// Validate LZMA signatures
pub fn lzma_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the LZMA header
    if let Ok(lzma_header) = parse_lzma_header(&file_data[offset..]) {
        /*
         * LZMA signatures are very prone to false positives, so do a dry-run extraction.
         * If it succeeds, we have high confidence that this signature is valid.
         * Else, assume this is a false positive.
         */
        let dry_run = lzma_decompress(file_data, offset, None);

        // Return success if dry run succeeded
        if dry_run.success
            && let Some(lzma_stream_size) = dry_run.size
        {
            result.size = lzma_stream_size;
            result.description = format!(
                "{}, properties: {:#04X}, dictionary size: {} bytes, compressed size: {} bytes, uncompressed size: {} bytes",
                result.description,
                lzma_header.properties,
                lzma_header.dictionary_size,
                result.size,
                lzma_header.decompressed_size as i64
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store useful LZMA header data
#[derive(Debug, Default, Clone)]
pub struct LZMAHeader {
    pub properties: u8,
    pub dictionary_size: u32,
    pub decompressed_size: u64,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZMAHeaderBytes {
    properties: u8,
    dictionary_size: zerocopy::U32<LE>,
    decompressed_size: zerocopy::U64<LE>,
    null_byte: u8,
}

/// Parse an LZMA header
pub fn parse_lzma_header(lzma_data: &[u8]) -> Result<LZMAHeader, StructureError> {
    // Streamed data has a reported size of -1
    const LZMA_STREAM_SIZE: u64 = 0xFFFFFFFFFFFFFFFF;

    // Some sane min and max values on the reported decompressed data size
    const MIN_SUPPORTED_DECOMPRESSED_SIZE: u64 = 256;
    const MAX_SUPPORTED_DECOMPRESSED_SIZE: u64 = 0xFFFFFFFF;

    let mut lzma_hdr_info = LZMAHeader::default();

    // Parse the lzma header
    let (lzma_header, _) =
        LZMAHeaderBytes::ref_from_prefix(lzma_data).map_err(|_| StructureError)?;

    // Make sure the expected NULL byte is NULL
    if lzma_header.null_byte == 0 {
        // Sanity check the reported decompressed size
        let decompressed_size = lzma_header.decompressed_size.get();
        if decompressed_size >= MIN_SUPPORTED_DECOMPRESSED_SIZE
            && (decompressed_size == LZMA_STREAM_SIZE
                || decompressed_size <= MAX_SUPPORTED_DECOMPRESSED_SIZE)
        {
            lzma_hdr_info.properties = lzma_header.properties;
            lzma_hdr_info.dictionary_size = lzma_header.dictionary_size.get();
            lzma_hdr_info.decompressed_size = decompressed_size;

            return Ok(lzma_hdr_info);
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor function for decompressing LZMA/XZ data
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::lzma::lzma_extractor;
///
/// match lzma_extractor().utility {
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
pub fn lzma_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(lzma_decompress),
        ..Default::default()
    }
}

/// Internal extractor for decompressing LZMA/XZ data streams
pub fn lzma_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // Output file name
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";
    // Output buffer size
    const BLOCK_SIZE: usize = 8192;
    // Maximum memory limit: 4GB
    const MEM_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

    let mut result = ExtractionResult::default();

    // Output buffer
    let mut output_buf = [0; BLOCK_SIZE];

    // Input compression stream
    let lzma_stream = &file_data[offset..];

    // Instantiate a new decoder, auto-detect LZMA or XZ
    if let Ok(mut decompressor) = Stream::new_auto_decoder(MEM_LIMIT, 0) {
        // Tracks number of bytes written to disk
        let mut bytes_written: usize = 0;
        // Tracks current position of bytes consumed from input stream
        let mut stream_position: usize = 0;

        /*
         * Loop through all compressed data and decompress it.
         *
         * This has a significant performance hit since 1) decompression takes time, and 2) data is
         * decompressed once during signature validation and a second time during extraction (if extraction
         * was requested).
         *
         * The advantage is that not only are we 100% sure that this data is a valid LZMA stream, but we
         * can also determine the exact size of the LZMA data.
         */
        loop {
            // Decompress data into output_buf
            match decompressor.process(
                &lzma_stream[stream_position..],
                &mut output_buf,
                Action::Run,
            ) {
                Err(_) => {
                    // Decompression error, break
                    break;
                }
                Ok(status) => {
                    // Check reported status
                    match status {
                        Status::GetCheck => break,
                        Status::MemNeeded => break,
                        Status::Ok => {
                            // Decompression OK, but there is still more data to decompress
                            stream_position = decompressor.total_in() as usize;
                        }
                        Status::StreamEnd => {
                            // Decompression complete. If some data was decompressed, report success, else break.
                            if decompressor.total_out() > 0 {
                                result.success = true;
                                result.size = Some(decompressor.total_in() as usize);
                            } else {
                                break;
                            }
                        }
                    }

                    // Some data was decompressed successfully; if extraction was requested, write the data to disk.
                    if let Some(output_directory) = output_directory {
                        // Number of decompressed bytes in the output buffer
                        let n = (decompressor.total_out() as usize) - bytes_written;

                        let chroot = Chroot::new(output_directory);
                        if !chroot.append_to_file(OUTPUT_FILE_NAME, &output_buf[0..n]) {
                            // If writing data to disk fails, report failure and break
                            result.success = false;
                            break;
                        }

                        // Remember how much data has been written to disk
                        bytes_written += n;
                    }

                    // If result.success is true, then everything has been processed and written to disk successfully.
                    if result.success {
                        break;
                    }
                }
            }
        }
    }

    result
}
