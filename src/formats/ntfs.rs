use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::{debug, error, warn};
use ntfs_core::NtfsFs;
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// The MFT record number of the NTFS root directory.
const NTFS_ROOT_RECORD: u64 = 5;

/// `FILE_ATTRIBUTE_DIRECTORY`
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// `FILE_ATTRIBUTE_REPARSE_POINT`
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// MFT records below this number are reserved for NTFS metadata files such as
/// `$MFT`, `$Bitmap`, and `$Extend`. They describe the volume itself rather
/// than user data, so extraction leaves them out.
const FIRST_USER_MFT_RECORD: u64 = 16;

/// Human readable description
pub const DESCRIPTION: &str = "NTFS partition";

/// NTFS partitions start with these bytes
pub fn ntfs_magic() -> Vec<Vec<u8>> {
    vec![b"\xEb\x52\x90NTFS\x20\x20\x20\x20".to_vec()]
}

/// Validates the NTFS header
pub fn ntfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(ntfs_header) = parse_ntfs_header(&file_data[offset..]) {
        // Bytes-per-sector is a fixed hardware value.
        const VALID_SECTOR_SIZES: [u16; 4] = [512, 1024, 2048, 4096];
        if !VALID_SECTOR_SIZES.contains(&ntfs_header.sector_size) {
            return Err(SignatureError);
        }
        // The reported sector count does not include the NTFS boot sector itself.
        // An overflowing count or product cannot describe data in this file.
        let sector_size = ntfs_header.sector_size as usize;
        let Some(reported_size) = ntfs_header
            .sector_count
            .checked_add(1)
            .and_then(|count| sector_size.checked_mul(count as usize))
        else {
            return Err(SignatureError);
        };
        result.size = reported_size;

        // Simple sanity check on the reported total size
        if result.size > sector_size
            && let Some(image_end) = offset.checked_add(result.size)
            && image_end <= file_data.len()
        {
            result.description = format!(
                "{}, number of sectors: {}, bytes per sector: {}, total size: {} bytes",
                result.description, ntfs_header.sector_count, ntfs_header.sector_size, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store NTFS info
#[derive(Debug, Default, Clone)]
pub struct NTFSPartition {
    pub sector_size: u16,
    pub sector_count: u64,
}

// https://en.wikipedia.org/wiki/NTFS
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct NtfsPartitionHeader {
    opcodes: [u8; 3],
    magic: zerocopy::U64<LE>,
    bytes_per_sector: zerocopy::U16<LE>,
    sectors_per_cluster: u8,
    unused1: [u8; 7],
    media_type: u8,
    unused2: [u8; 2],
    sectors_per_track: zerocopy::U16<LE>,
    head_count: zerocopy::U16<LE>,
    hidden_sector_count: zerocopy::U32<LE>,
    unused3: [u8; 4],
    unknown: [u8; 4],
    sector_count: zerocopy::U64<LE>,
}

/// Parses an NTFS partition header
pub fn parse_ntfs_header(ntfs_data: &[u8]) -> Result<NTFSPartition, StructureError> {
    // Parse the NTFS partition header
    let (ntfs_header, _) =
        NtfsPartitionHeader::ref_from_prefix(ntfs_data).map_err(|_| StructureError)?;

    // Sanity check to make sure the unused fields are not used
    if ntfs_header
        .unused1
        .iter()
        .chain(&ntfs_header.unused2)
        .chain(&ntfs_header.unused3)
        .all(|&b| b == 0)
    {
        return Ok(NTFSPartition {
            sector_count: ntfs_header.sector_count.get(),
            sector_size: ntfs_header.bytes_per_sector.get(),
        });
    }

    Err(StructureError)
}

/// Defines the internal extractor for NTFS filesystems.
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::ntfs::ntfs_extractor;
///
/// match ntfs_extractor().utility {
///     ExtractorType::Internal(_) => {}
///     _ => panic!("NTFS extractor should be internal"),
/// }
/// ```
pub fn ntfs_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_ntfs),
        ..Default::default()
    }
}

/// Internal extractor: unpack an NTFS volume into a `rootfs/` subtree of the
/// output directory.
///
/// When `output_directory` is `None`, this performs a dry run: the filesystem is
/// loaded and validated, but nothing is written to disk.
pub fn extract_ntfs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(ntfs_data) = file_data.get(offset..) else {
        error!("NTFS extractor received invalid offset {offset:#X}");
        return result;
    };
    let Ok(header) = parse_ntfs_header(ntfs_data) else {
        error!("Failed to parse NTFS boot sector at offset {offset:#X}");
        return result;
    };

    // The boot sector's sector count excludes the boot sector itself.
    let Some(image_size) = header
        .sector_count
        .checked_add(1)
        .and_then(|sectors| (header.sector_size as usize).checked_mul(sectors as usize))
    else {
        error!("NTFS image at offset {offset:#X} reports an overflowing size");
        return result;
    };
    if image_size == 0 {
        error!("NTFS image at offset {offset:#X} reports a zero size");
        return result;
    }

    let Some(image_data) = file_data.get(offset..offset.saturating_add(image_size)) else {
        error!("NTFS image at offset {offset:#X} extends past the end of the file");
        return result;
    };
    if image_data.len() != image_size {
        error!(
            "NTFS image at offset {offset:#X} is truncated: expected {image_size} bytes, got {}",
            image_data.len()
        );
        return result;
    }

    let filesystem = match NtfsFs::open(Cursor::new(image_data)) {
        Ok(filesystem) => filesystem,
        Err(e) => {
            error!("Failed to load NTFS filesystem at offset {offset:#X}: {e}");
            return result;
        }
    };
    result.size = Some(image_size);

    // A dry run validates the image without touching the filesystem.
    let Some(output_directory) = output_directory else {
        result.success = true;
        return result;
    };

    let chroot = Chroot::new(output_directory);
    if !chroot.create_directory(Path::new("rootfs")) {
        error!("Failed to create the NTFS output directory");
        return result;
    }

    let mut success = true;
    let mut visited_directories = HashSet::new();

    extract_ntfs_directory(
        &filesystem,
        NTFS_ROOT_RECORD,
        &chroot,
        Path::new("rootfs"),
        &mut visited_directories,
        &mut success,
    );

    result.success = success;
    result
}

/// Recursively extract one NTFS directory, addressed by MFT record number.
fn extract_ntfs_directory<R: Read + Seek>(
    filesystem: &NtfsFs<R>,
    record_number: u64,
    chroot: &Chroot,
    output_path: &Path,
    visited_directories: &mut HashSet<u64>,
    success: &mut bool,
) {
    // A corrupt or hostile index could point a directory at an ancestor. Track
    // visited directory records so the walk always terminates.
    if !visited_directories.insert(record_number) {
        warn!(
            "Skipping NTFS directory cycle at MFT record {record_number} ({})",
            output_path.display()
        );
        return;
    }

    let record = match filesystem.read_record(record_number) {
        Ok(record) => record,
        Err(e) => {
            error!(
                "Failed to read NTFS directory MFT record {record_number} ({}): {e}",
                output_path.display()
            );
            *success = false;
            return;
        }
    };
    let entries = match filesystem.directory_entries(&record) {
        Ok(entries) => entries,
        Err(e) => {
            error!(
                "Failed to read NTFS directory entries for {}: {e}",
                output_path.display()
            );
            *success = false;
            return;
        }
    };

    for entry in entries {
        let Some(file_name) = entry.file_name else {
            continue;
        };

        // Each file commonly also has a short DOS 8.3 name; extracting both
        // would duplicate every entry that has a long name.
        if file_name.is_dos_namespace() {
            continue;
        }

        let name = file_name.name.as_str();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let child_record = entry.file_reference.record_number;
        if child_record < FIRST_USER_MFT_RECORD {
            debug!("Skipping NTFS metadata file {name} (MFT record {child_record})");
            continue;
        }

        let path = output_path.join(name);

        if file_name.flags & FILE_ATTRIBUTE_DIRECTORY != 0 {
            if chroot.create_directory(&path) {
                extract_ntfs_directory(
                    filesystem,
                    child_record,
                    chroot,
                    &path,
                    visited_directories,
                    success,
                );
            } else {
                error!("Failed to create NTFS directory {}", path.display());
                *success = false;
            }
        } else if file_name.flags & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            // Reparse-point data lives in a separate attribute that ntfs-core
            // does not expose; recreating the link faithfully is not possible.
            warn!(
                "Skipping NTFS reparse point {}: target data is not exposed",
                path.display()
            );
        } else {
            // `read_data_by_record` follows $ATTRIBUTE_LIST fragments and
            // LZNT1-decompresses compressed $DATA, so the extracted file holds
            // its logical contents rather than the raw on-disk runs.
            match filesystem.read_data_by_record(child_record, None, u64::MAX) {
                Ok(data) => {
                    if !chroot.create_file(&path, &data) {
                        error!("Failed to extract NTFS file {}", path.display());
                        *success = false;
                    }
                }
                Err(e) => {
                    error!("Failed to read NTFS file {}: {e}", path.display());
                    *success = false;
                }
            }
        }
    }
}
