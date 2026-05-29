use crate::common::crc32;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "TRX firmware image";

/// TRX magic bytes
pub fn trx_magic() -> Vec<Vec<u8>> {
    vec![b"HDR0".to_vec()]
}

/// Validates a TRX signature
pub fn trx_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do a dry run to validate the TRX data
    let dry_run = extract_trx_partitions(file_data, offset, None);

    if dry_run.success
        && let Some(trx_total_size) = dry_run.size
    {
        // Dry run successful, parse the TRX header and return a useful description
        if let Ok(trx_header) = parse_trx_header(&file_data[offset..]) {
            result.size = trx_total_size;
            result.description = format!(
                "{}, version {}, partition count: {}, header size: {} bytes, total size: {} bytes",
                result.description,
                trx_header.version,
                trx_header.partitions.len(),
                trx_header.header_size,
                result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores TRX firmware header info
#[derive(Debug, Clone, Default)]
pub struct TRXHeader {
    pub version: u16,
    pub checksum: u32,
    pub total_size: usize,
    pub header_size: usize,
    pub partitions: Vec<usize>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TRXHeaderBytes {
    magic: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
    crc32: zerocopy::U32<LE>,
    flags: zerocopy::U16<LE>,
    version: zerocopy::U16<LE>,
    partition1_offset: zerocopy::U32<LE>,
    partition2_offset: zerocopy::U32<LE>,
    partition3_offset: zerocopy::U32<LE>,
    partition4_offset: zerocopy::U32<LE>,
}

/// Parse a TRX firmware header
pub fn parse_trx_header(header_data: &[u8]) -> Result<TRXHeader, StructureError> {
    // TRX comes in two flavors: v1 and v2
    const TRX_VERSION_2: u16 = 2;

    let allowed_versions = [1, 2];

    // Size of the fixed-length portion of the header structure
    let mut struct_size: usize = std::mem::size_of::<TRXHeaderBytes>();

    // Parse the header
    let (trx_header, _) =
        TRXHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;
    // Sanity check partition offsets. Partition offsets may be 0.
    if trx_header.partition1_offset <= trx_header.total_size
        && trx_header.partition2_offset <= trx_header.total_size
        && trx_header.partition3_offset <= trx_header.total_size
    {
        // Sanity check the reported total size
        if trx_header.total_size.get() as usize > struct_size {
            // Sanity check the reported version number
            if allowed_versions.contains(&trx_header.version.get()) {
                let mut partitions = vec![];

                if trx_header.partition1_offset != 0 {
                    partitions.push(trx_header.partition1_offset.get() as usize);
                }

                if trx_header.partition2_offset != 0 {
                    partitions.push(trx_header.partition2_offset.get() as usize);
                }

                if trx_header.partition3_offset != 0 {
                    partitions.push(trx_header.partition3_offset.get() as usize);
                }

                // Only TRXv2 has a fourth partition entry
                if trx_header.version == TRX_VERSION_2 {
                    if trx_header.partition4_offset != 0 {
                        partitions.push(trx_header.partition4_offset.get() as usize);
                    }
                } else {
                    // For TRXv1, this means the real structure size is 4 bytes shorter
                    struct_size -= std::mem::size_of::<u32>();
                }

                return Ok(TRXHeader {
                    version: trx_header.version.get(),
                    checksum: trx_header.crc32.get(),
                    total_size: trx_header.total_size.get() as usize,
                    header_size: struct_size,
                    partitions: partitions.clone(),
                });
            }
        }
    }

    Err(StructureError)
}

/// Defines the internal TRX extractor
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::trx::trx_extractor;
///
/// match trx_extractor().utility {
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
pub fn trx_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_trx_partitions),
        ..Default::default()
    }
}

/// Internal extractor for TRX partitions
pub fn extract_trx_partitions(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const CRC_DATA_START_OFFSET: usize = 12;

    let mut result = ExtractionResult::default();

    // Get the TRX data and parse the header
    if let Some(trx_header_data) = file_data.get(offset..)
        && let Ok(trx_header) = parse_trx_header(trx_header_data)
    {
        let crc_data_start = offset + CRC_DATA_START_OFFSET;
        let crc_data_end = crc_data_start + trx_header.total_size - CRC_DATA_START_OFFSET;

        if let Some(crc_data) = file_data.get(crc_data_start..crc_data_end)
            && trx_crc32(crc_data) == trx_header.checksum
        {
            result.success = true;
            result.size = Some(trx_header.total_size);

            // If extraction was requested, carve the TRX partitions
            if let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);

                for i in 0..trx_header.partitions.len() {
                    let next_partition: usize = i + 1;
                    let this_partition_relative_offset: usize = trx_header.partitions[i];
                    let this_partition_absolute_offset: usize =
                        offset + this_partition_relative_offset;
                    let mut this_partition_size: usize =
                        trx_header.total_size - this_partition_relative_offset;

                    if next_partition < trx_header.partitions.len() {
                        this_partition_size =
                            trx_header.partitions[next_partition] - this_partition_relative_offset;
                    }

                    let this_partition_file_name = format!("partition_{i}.bin");
                    result.success = chroot.carve_file(
                        &this_partition_file_name,
                        file_data,
                        this_partition_absolute_offset,
                        this_partition_size,
                    );

                    if !result.success {
                        break;
                    }
                }
            }
        }
    }

    result
}

fn trx_crc32(crc_data: &[u8]) -> u32 {
    crc32(crc_data) ^ 0xFFFFFFFF
}
