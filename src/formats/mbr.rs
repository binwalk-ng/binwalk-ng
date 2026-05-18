use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "DOS Master Boot Record";

/// Offset of magic bytes from the start of the MBR
pub const MAGIC_OFFSET: usize = 0x01FE;

/// MBR always contains these bytes
pub fn mbr_magic() -> Vec<Vec<u8>> {
    vec![b"\x55\xAA".to_vec()]
}

/// Validates the MBR header
pub fn mbr_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // This signature is only matched at the beginning of files (see magic.rs), so this check is not strictly necessary
    if offset == MAGIC_OFFSET {
        // MBR actually starts this may bytes before the magic bytes
        result.offset = offset - MAGIC_OFFSET;

        // Do an extraction dry run
        let dry_run = extract_mbr_partitions(file_data, result.offset, None);

        // If dry run was a success, this is likely a valid MBR
        if dry_run.success
            && let Some(mbr_total_size) = dry_run.size
        {
            // Update reported MBR size
            result.size = mbr_total_size;

            // Parse the MBR header
            if let Ok(mbr_header) = parse_mbr_image(&file_data[result.offset..]) {
                // Examine all reported partitions
                for partition in &mbr_header.partitions {
                    // Carving out partitions starting at offset 0 would result in infinite recurstion during recursive extraction!
                    if partition.start == result.offset {
                        result.extraction_declined = true;
                    }

                    // Add partition info to the description
                    result.description =
                        format!("{}, partition: {}", result.description, partition.name);
                }

                // Add total size to the description
                result.description =
                    format!("{}, image size: {} bytes", result.description, result.size);

                // Everything looks ok
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Struct to store MBR partition info
#[derive(Debug, Default, Clone)]
pub struct MBRPartition {
    pub start: usize,
    pub size: usize,
    pub name: String,
}

/// Struct to store MBR info
#[derive(Debug, Default, Clone)]
pub struct MBRHeader {
    pub image_size: usize,
    pub partitions: Vec<MBRPartition>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct PartitionEntryBytes {
    status: u8,
    chs_start: [u8; 3],
    os_type: u8,
    chs_end: [u8; 3],
    lba_start: zerocopy::U32<LE>,
    lba_size: zerocopy::U32<LE>,
}

/// Parse a Master Boot Record image
pub fn parse_mbr_image(mbr_data: &[u8]) -> Result<MBRHeader, StructureError> {
    const BLOCK_SIZE: usize = 512;
    const MIN_IMAGE_SIZE: usize = BLOCK_SIZE * 2;

    const PARTITION_COUNT: usize = 4;
    const PARTITION_TABLE_OFFSET: usize = 446;
    const ALLOWED_STATUS_VALUES: [u8; 2] = [0, 0x80];

    let partition_structure_size = std::mem::size_of::<PartitionEntryBytes>();

    let partition_table_start = PARTITION_TABLE_OFFSET;
    let partition_table_end = partition_table_start + (partition_structure_size * PARTITION_COUNT);

    let mut mbr_header = MBRHeader::default();

    // Get the partition table raw bytes
    if let Some(partition_table) = mbr_data.get(partition_table_start..partition_table_end) {
        // Parse each partition table entry
        for i in 0..PARTITION_COUNT {
            // Offset in the partition table for this entry
            let partition_entry_start: usize = i * partition_structure_size;

            // Parse this partition table entry
            let (partition_entry, _) =
                PartitionEntryBytes::ref_from_prefix(&partition_table[partition_entry_start..])
                    .map_err(|_| StructureError)?;

            // OS type of zero or LBA size of 0 can be ignored
            if partition_entry.os_type != 0 || partition_entry.lba_size.get() != 0 {
                // Validate the reported MBR status value
                if ALLOWED_STATUS_VALUES.contains(&partition_entry.status) {
                    // Default to unknown partition type
                    let this_partition_name = match partition_entry.os_type {
                        0x07 => "NTFS_IFS_HPFS_exFAT",
                        0x0B => "FAT32",
                        0x0C => "FAT32",
                        0x43 => "Linux",
                        0x4D => "QNX Primary Volume",
                        0x4E => "QNX Secondary Volume",
                        0x81 => "Minix",
                        0x83 => "Linux",
                        0x8E => "Linux LVM",
                        0x96 => "ISO-9660",
                        0xB1 => "QNXv6 File System",
                        0xB2 => "QNXv6 File System",
                        0xB3 => "QNXv6 File System",
                        0xEE => "EFI GPT Protective",
                        0xEF => "EFI System Partition",
                        _ => "Unknown",
                    };

                    // Create an MBRPartition structure for this entry
                    let this_partition = MBRPartition {
                        start: partition_entry.lba_start.get() as usize * BLOCK_SIZE,
                        size: partition_entry.lba_size.get() as usize * BLOCK_SIZE,
                        name: this_partition_name.to_string(),
                    };

                    // Calculate where this partition ends
                    let this_partition_end_offset = this_partition.start + this_partition.size;

                    // Some valid MBRs have partitions that start/end out of bounds WRT the disk image.
                    // Not sure why? At any rate, don't include them in the reported partitions.
                    if this_partition_end_offset <= mbr_data.len() {
                        // Don't report the partition where the MBR header resides
                        if this_partition.start != 0 {
                            // Add it to the list of partitions
                            mbr_header.partitions.push(this_partition.clone());
                        }

                        // Image size is the end of the farthest away partition
                        if this_partition_end_offset > mbr_header.image_size {
                            mbr_header.image_size = this_partition_end_offset;
                        }
                    }
                }
            }
        }

        // There should be at least one valid partition
        if !mbr_header.partitions.is_empty() {
            // Total size should be greater than minimum size
            if mbr_header.image_size > MIN_IMAGE_SIZE {
                return Ok(mbr_header);
            }
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor function for MBR partitions
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::mbr::mbr_extractor;
///
/// match mbr_extractor().utility {
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
pub fn mbr_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_mbr_partitions),
        ..Default::default()
    }
}

/// Validate and extract partitions from an MBR
pub fn extract_mbr_partitions(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // Return value
    let mut result = ExtractionResult::default();

    let available_data = file_data.len() - offset;

    // Parse the MBR header
    if let Ok(mbr_header) = parse_mbr_image(&file_data[offset..]) {
        // Make sure there is at least one valid partition
        if !mbr_header.partitions.is_empty() {
            // Make sure the reported size of the MBR does not extend beyond EOF
            if available_data >= mbr_header.image_size {
                // Everything looks ok
                result.success = true;
                result.size = Some(mbr_header.image_size);

                // Do extraction if requested
                if let Some(output_directory) = output_directory {
                    // Chroot extracted files into the output directory
                    let chroot = Chroot::new(output_directory);

                    // Loop through each partition
                    for (partition_count, partition) in mbr_header.partitions.iter().enumerate() {
                        // Partition names are not unique, output file will be: "<name>_partition.<partition count>"
                        let partition_name =
                            format!("{}_partition.{}", partition.name, partition_count);

                        // Carve out the partition
                        result.success = chroot.carve_file(
                            partition_name,
                            file_data,
                            partition.start,
                            partition.size,
                        );

                        // If partition extraction failed, quit and report a failure
                        if !result.success {
                            break;
                        }
                    }
                }
            }
        }
    }

    result
}
