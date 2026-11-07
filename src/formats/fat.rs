use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use fat::{FatFs, FileId};
use log::{debug, error, warn};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "FAT file system";

/// Offset of magic bytes from the start of the FAT
pub const MAGIC_OFFSET: usize = 0x01FE;

/// FAT always contains these bytes
pub fn fat_magic() -> Vec<Vec<u8>> {
    vec![b"\x55\xAA".to_vec()]
}

/// Validates the FAT header
pub fn fat_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Sanity check the magic offset
    if offset >= MAGIC_OFFSET {
        // FAT actually starts this may bytes before the magic bytes
        result.offset = offset - MAGIC_OFFSET;

        // Parse and validate the FAT header
        if let Some(fat_data) = file_data.get(result.offset..)
            && let Ok(fat_header) = parse_fat_header(fat_data)
        {
            // Report the total size of the FAT image
            result.size = fat_header.total_size;

            // Include FAT type in the description
            let fat_type_desc = if fat_header.is_fat32 {
                "FAT32"
            } else {
                "FAT12/16"
            };

            result.description = format!(
                "{}, type: {}, total size: {} bytes",
                result.description, fat_type_desc, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store FAT header info
#[derive(Debug, Default, Clone)]
pub struct FATHeader {
    pub is_fat32: bool,
    pub total_size: usize,
}

// http://elm-chan.org/docs/fat_e.html
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FATBootSectorBytes {
    opcode1: u8,
    opcode2: u8,
    opcode3: u8,
    oem_name: zerocopy::U64<LE>,
    bytes_per_sector: zerocopy::U16<LE>,
    sectors_per_cluster: u8,
    reserved_sectors: zerocopy::U16<LE>,
    fat_count: u8,
    root_entries_count_16: zerocopy::U16<LE>,
    total_sectors_16: zerocopy::U16<LE>,
    media_type: u8,
    fat_size_16: zerocopy::U16<LE>,
    sectors_per_track: zerocopy::U16<LE>,
    number_of_heads: zerocopy::U16<LE>,
    hidden_sectors: zerocopy::U32<LE>,
    total_sectors_32: zerocopy::U32<LE>,
}

/// Parses a FAT header
pub fn parse_fat_header(fat_data: &[u8]) -> Result<FATHeader, StructureError> {
    // Number of FATs is 1 or 2 (2 is the norm, 1 is valid on flash media)
    const VALID_FAT_COUNTS: [u8; 2] = [1, 2];

    let valid_opcode1 = [0xEB, 0xE9];
    let valid_sector_sizes = [512, 1024, 2048, 4096];
    let valid_sectors_per_cluster = [1, 2, 4, 8, 16, 32, 64, 128];
    let valid_media_types = [0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE];

    // Return value
    let mut result = FATHeader::default();

    // Parse the boot sector header

    let (bs_header, _) =
        FATBootSectorBytes::ref_from_prefix(fat_data).map_err(|_| StructureError)?;
    // Sanity check the first opcode, reported sector size, reported sectors per cluster
    if valid_opcode1.contains(&bs_header.opcode1)
        && valid_sector_sizes.contains(&bs_header.bytes_per_sector.get())
        && valid_sectors_per_cluster.contains(&bs_header.sectors_per_cluster)
    {
        // Reserved sectors must be at least 1
        if bs_header.reserved_sectors > 0 {
            // Sanity check the reported number of FATs, reported media type
            if VALID_FAT_COUNTS.contains(&bs_header.fat_count)
                && valid_media_types.contains(&bs_header.media_type)
            {
                // This field is set to 0 for FAT32, but populated by FAT12/16
                result.is_fat32 = bs_header.fat_size_16 == 0;

                // total_sectors_16 is used for FAT12/16 that have less than 0x10000 sectors
                if bs_header.total_sectors_16 != 0 {
                    result.total_size = (bs_header.total_sectors_16.get() as usize)
                        .checked_mul(bs_header.bytes_per_sector.get() as usize)
                        .ok_or(StructureError)?;
                // Else, total_sectors_32 is used to define the number of sectors
                } else {
                    result.total_size = (bs_header.total_sectors_32.get() as usize)
                        .checked_mul(bs_header.bytes_per_sector.get() as usize)
                        .ok_or(StructureError)?;
                }

                // If both total_sectors_32 and total_sectors_16 is 0, this is not a valid FAT
                if result.total_size > 0 {
                    return Ok(result);
                }
            }
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor for FAT12/16/32 filesystems.
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::fat::fat_extractor;
///
/// match fat_extractor().utility {
///     ExtractorType::Internal(_) => {}
///     _ => panic!("FAT extractor should be internal"),
/// }
/// ```
pub fn fat_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_fat),
        ..Default::default()
    }
}

/// Unpack a FAT image into `rootfs/` under `output_directory`.
///
/// When `output_directory` is `None`, the filesystem is opened but no contents are
/// extracted or traversed.
pub fn extract_fat(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(fat_data) = file_data.get(offset..) else {
        error!("FAT extractor received invalid offset {offset:#X}");
        return result;
    };
    let Ok(header) = parse_fat_header(fat_data) else {
        error!("Failed to parse FAT boot sector at offset {offset:#X}");
        return result;
    };
    let image_size = header.total_size;
    if image_size == 0 {
        error!("FAT image at offset {offset:#X} reports a zero size");
        return result;
    }

    let Some(image_end) = offset.checked_add(image_size) else {
        error!("FAT image range overflows at offset {offset:#X}");
        return result;
    };
    let Some(image_data) = file_data.get(offset..image_end) else {
        error!("FAT image at offset {offset:#X} extends past the end of the file");
        return result;
    };

    // `FatFs` takes only `Read + Seek`, so the evidence slice is never writable.
    let filesystem = match FatFs::open(Cursor::new(image_data)) {
        Ok(filesystem) => filesystem,
        Err(e) => {
            error!("Failed to load FAT filesystem at offset {offset:#X}: {e}");
            return result;
        }
    };
    result.size = Some(image_size);

    let Some(output_directory) = output_directory else {
        result.success = true;
        return result;
    };

    let chroot = Chroot::new(output_directory);
    if !chroot.create_directory(Path::new("rootfs")) {
        error!("Failed to create the FAT output directory");
        return result;
    }

    let mut success = true;
    let mut visited_directories = HashSet::new();
    extract_fat_directory(
        &filesystem,
        filesystem.root(),
        &chroot,
        Path::new("rootfs"),
        &mut visited_directories,
        &mut success,
    );

    result.success = success;
    result
}

/// Recursively extract one FAT directory, addressed by [`FileId`].
fn extract_fat_directory<R: Read + Seek>(
    filesystem: &FatFs<R>,
    directory: FileId,
    chroot: &Chroot,
    output_path: &Path,
    visited_directories: &mut HashSet<(u32, u16)>,
    success: &mut bool,
) {
    let entries = match filesystem.read_dir(directory) {
        Ok(entries) => entries,
        Err(e) => {
            error!(
                "Failed to read FAT directory {}: {e}",
                output_path.display()
            );
            *success = false;
            return;
        }
    };

    for entry in entries {
        // `read_dir` also reports deleted entries and the volume label; neither
        // belongs in a recovery of the live tree.
        if entry.is_deleted {
            debug!(
                "Skipping deleted FAT entry {} in {}",
                entry.name,
                output_path.display()
            );
            continue;
        }
        if entry.is_volume_label {
            continue;
        }

        let name = entry.name.as_str();
        // "." and ".." are stored as real directory entries and would recurse
        // forever (and ".." would escape the output tree).
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let path = output_path.join(name);

        if entry.is_dir {
            // A corrupt image can point a directory entry at an ancestor; track
            // visited entry ids so the walk always terminates.
            let FileId::Entry { dir_cluster, index } = entry.id else {
                continue;
            };
            if !visited_directories.insert((dir_cluster, index)) {
                warn!(
                    "Skipping FAT directory cycle at {} ({})",
                    path.display(),
                    entry.name
                );
                continue;
            }

            if chroot.create_directory(&path) {
                extract_fat_directory(
                    filesystem,
                    entry.id,
                    chroot,
                    &path,
                    visited_directories,
                    success,
                );
            } else {
                error!("Failed to create FAT directory {}", path.display());
                *success = false;
            }
        } else {
            match read_fat_file(filesystem, entry.id, entry.size) {
                Ok(data) => {
                    if data.len() as u64 != entry.size {
                        warn!(
                            "FAT file {} is truncated: expected {} bytes, read {}",
                            path.display(),
                            entry.size,
                            data.len()
                        );
                    }
                    if !chroot.create_file(&path, &data) {
                        error!("Failed to extract FAT file {}", path.display());
                        *success = false;
                    }
                }
                Err(e) => {
                    error!("Failed to read FAT file {}: {e}", path.display());
                    *success = false;
                }
            }
        }
    }
}

/// Read file data through [`FatFs::read_at`], growing the buffer as data
/// actually arrives so a corrupt size field cannot force a huge upfront
/// allocation.
fn read_fat_file<R: Read + Seek>(
    filesystem: &FatFs<R>,
    id: FileId,
    size: u64,
) -> fat::Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 64 * 1024;

    let mut data = Vec::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut offset = 0u64;

    while offset < size {
        let remaining = size - offset;
        let want = usize::try_from(remaining.min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
        let read = filesystem.read_at(id, offset, &mut buffer[..want])?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        offset += read as u64;
    }

    Ok(data)
}
