use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use ext4_view::{Ext4, FileType};
use log::{debug, error, warn};
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "EXT filesystem";

/// EXT magic bytes
pub fn ext_magic() -> Vec<Vec<u8>> {
    /*
     * The magic bytes for EXT are only a u16, resulting in many false positives.
     * These magic signatures include all possible values for the state and errors fields in the superblock,
     * as well as the minor version number (assumed to be 0).
     * This means fewer false positive matches, and less time spent validating false positives.
     */
    vec![
        b"\x53\xEF\x01\x00\x01\x00\x00\x00".to_vec(),
        b"\x53\xEF\x01\x00\x02\x00\x00\x00".to_vec(),
        b"\x53\xEF\x01\x00\x03\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x01\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x02\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x03\x00\x00\x00".to_vec(),
    ]
}

/// Parse the EXT signature
pub fn ext_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Offset inside the EXT image where the magic bytes reside
    const MAGIC_OFFSET: usize = 1080;

    // The magic bytes live MAGIC_OFFSET bytes into the image; a match any earlier
    // cannot be a valid EXT superblock (and would underflow the subtraction below).
    if offset < MAGIC_OFFSET {
        return Err(SignatureError);
    }

    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset: offset - MAGIC_OFFSET,
        size: 0,
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Some(ext_data) = file_data.get(result.offset..)
        && let Ok(ext_header) = parse_ext_header(ext_data)
        && ext_header.image_size > 0
        && ext_header.image_size <= ext_data.len()
    {
        result.size = ext_header.image_size;
        result.description = format!(
            "{} for {}, inodes: {}, block size: {}, block count: {}, free blocks: {}, reserved blocks: {}, total size: {} bytes",
            result.description,
            ext_header.os,
            ext_header.inodes_count,
            ext_header.block_size,
            ext_header.free_blocks_count,
            ext_header.reserved_blocks_count,
            ext_header.blocks_count,
            result.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Expected size of an EXT superblock
pub const SUPERBLOCK_SIZE: usize = 1024;

/// Expected file offset of an EXT superblock
pub const SUPERBLOCK_OFFSET: usize = 1024;

/// Struct to store some useful EXT info
#[derive(Debug, Default, Clone)]
pub struct EXTHeader {
    pub os: String,
    pub block_size: usize,
    pub image_size: usize,
    pub blocks_count: usize,
    pub inodes_count: usize,
    pub free_blocks_count: usize,
    pub reserved_blocks_count: usize,
}

// Partial superblock structure, just enough for validation and size calculation
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EXTSuprtBlockBytes {
    inodes_count: zerocopy::U32<LE>,
    blocks_count: zerocopy::U32<LE>,
    reserved_blocks_count: zerocopy::U32<LE>,
    free_blocks_count: zerocopy::U32<LE>,
    free_inodes_count: zerocopy::U32<LE>,
    first_data_block: zerocopy::U32<LE>,
    log_block_size: zerocopy::U32<LE>,
    log_frag_size: zerocopy::U32<LE>,
    blocks_per_group: zerocopy::U32<LE>,
    frags_per_group: zerocopy::U32<LE>,
    inodes_per_group: zerocopy::U32<LE>,
    modification_time: zerocopy::U32<LE>,
    write_time: zerocopy::U32<LE>,
    mount_count: zerocopy::U16<LE>,
    max_mount_count: zerocopy::U16<LE>,
    magic: zerocopy::U16<LE>,
    state: zerocopy::U16<LE>,
    errors: zerocopy::U16<LE>,
    s_minor_rev_level: zerocopy::U16<LE>,
    last_check: zerocopy::U32<LE>,
    check_interval: zerocopy::U32<LE>,
    creator_os: zerocopy::U32<LE>,
    s_rev_level: zerocopy::U32<LE>,
    resuid: zerocopy::U16<LE>,
    resgid: zerocopy::U16<LE>,
}

/// Partially parses an EXT superblock structure
pub fn parse_ext_header(ext_data: &[u8]) -> Result<EXTHeader, StructureError> {
    // Max value of the EXT log block size
    const MAX_BLOCK_LOG: u32 = 2;

    const ALLOWED_REV_LEVELS: [u32; 2] = [0, 1];
    const ALLOWED_FIRST_DATA_BLOCKS: [u32; 2] = [0, 1];

    // Sanity check the available data
    if ext_data.len() >= (SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE) {
        // Parse the EXT superblock structure
        let (ext_superblock, _) =
            EXTSuprtBlockBytes::ref_from_prefix(&ext_data[SUPERBLOCK_OFFSET..])
                .map_err(|_| StructureError)?;

        // Sanity check the reported OS this EXT image was created on
        let creator_os = match ext_superblock.creator_os.get() {
            0 => "Linux",
            1 => "GNU HURD",
            2 => "MASIX",
            3 => "FreeBSD",
            4 => "Lites",
            _ => return Err(StructureError),
        };
        // Sanity check the s_rev_level field
        if ALLOWED_REV_LEVELS.contains(&ext_superblock.s_rev_level.get()) {
            // Sanity check the first_data_block field, which must be either 0 or 1
            if ALLOWED_FIRST_DATA_BLOCKS.contains(&ext_superblock.first_data_block.get()) {
                // Santiy check the log_block_size
                if ext_superblock.log_block_size.get() <= MAX_BLOCK_LOG {
                    let block_size = 1024 << ext_superblock.log_block_size.get();
                    return Ok(EXTHeader {
                        os: creator_os.to_string(),
                        block_size,
                        image_size: block_size * (ext_superblock.blocks_count.get() as usize),
                        blocks_count: ext_superblock.blocks_count.get() as usize,
                        inodes_count: ext_superblock.inodes_count.get() as usize,
                        free_blocks_count: ext_superblock.free_blocks_count.get() as usize,
                        reserved_blocks_count: ext_superblock.reserved_blocks_count.get() as usize,
                    });
                }
            }
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor for ext2/ext3/ext4 filesystems.
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::ext::ext_extractor;
///
/// match ext_extractor().utility {
///     ExtractorType::Internal(_) => {}
///     _ => panic!("EXT extractor should be internal"),
/// }
/// ```
pub fn ext_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_ext),
        ..Default::default()
    }
}

/// Internal extractor: unpack an ext2/ext3/ext4 image into a `rootfs/`
/// subtree of the output directory.
///
/// When `output_directory` is `None`, this performs a dry run: the filesystem is
/// loaded and validated, but nothing is written to disk.
pub fn extract_ext(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(ext_data) = file_data.get(offset..) else {
        error!("EXT extractor received invalid offset {offset:#X}");
        return result;
    };
    let Ok(header) = parse_ext_header(ext_data) else {
        error!("Failed to parse EXT superblock at offset {offset:#X}");
        return result;
    };
    let image_size = header.image_size;
    if image_size == 0 {
        error!("EXT image at offset {offset:#X} reports a zero size");
        return result;
    }

    let Some(image_data) = file_data.get(offset..offset.saturating_add(image_size)) else {
        error!("EXT image at offset {offset:#X} extends past the end of the file");
        return result;
    };
    if image_data.len() != image_size {
        error!(
            "EXT image at offset {offset:#X} is truncated: expected {image_size} bytes, got {}",
            image_data.len()
        );
        return result;
    }

    // ext4-view reads from any `Ext4Read`; `Vec<u8>` is its in-memory
    // implementation. The image is copied so the borrow of `file_data` does not
    // outlive this function.
    let filesystem = match Ext4::load(Box::new(image_data.to_vec())) {
        Ok(filesystem) => filesystem,
        Err(e) => {
            error!("Failed to load EXT filesystem at offset {offset:#X}: {e}");
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
        error!("Failed to create the EXT output directory");
        return result;
    }

    let mut success = true;
    let mut directory_metadata: Vec<(PathBuf, u32, u32, u32)> = Vec::new();

    extract_ext_directory(
        &filesystem,
        Path::new("/"),
        &chroot,
        &mut directory_metadata,
        &mut success,
    );

    // Apply directory modes/ownership only after all contents have been
    // written, so a restrictive directory mode cannot block extraction.
    if success {
        for (path, mode, uid, gid) in directory_metadata {
            chroot.set_ownership(&path, uid, gid);
            chroot.set_mode(&path, mode);
        }
    } else {
        debug!("Skipping EXT directory metadata restoration for a failed extraction");
    }

    result.success = success;
    result
}

/// Recursively extract one EXT directory. `directory` is the absolute path
/// inside the ext4 image; `output_path` is derived from each entry's own path.
fn extract_ext_directory(
    filesystem: &Ext4,
    directory: &Path,
    chroot: &Chroot,
    directory_metadata: &mut Vec<(PathBuf, u32, u32, u32)>,
    success: &mut bool,
) {
    let entries = match filesystem.read_dir(directory) {
        Ok(entries) => entries,
        Err(e) => {
            error!("Failed to read EXT directory {}: {e}", directory.display());
            *success = false;
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                error!(
                    "Failed to read an entry in EXT directory {}: {e}",
                    directory.display()
                );
                *success = false;
                continue;
            }
        };

        // The on-disk "." and ".." entries point back into the tree; following
        // them would recurse forever (and ".." would try to escape the output).
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }

        let Some(entry_path) = ext_pathbuf_to_std(entry.path()) else {
            warn!(
                "EXT entry in {} has a path that cannot be represented on this platform",
                directory.display()
            );
            continue;
        };
        let Ok(relative_path) = entry_path.strip_prefix("/") else {
            warn!(
                "EXT entry {} is not an absolute path inside the image",
                entry_path.display()
            );
            *success = false;
            continue;
        };
        let output_path = Path::new("rootfs").join(relative_path);

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(e) => {
                error!(
                    "Failed to read metadata for EXT entry {}: {e}",
                    entry_path.display()
                );
                *success = false;
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                error!(
                    "Failed to read file type for EXT entry {}: {e}",
                    entry_path.display()
                );
                *success = false;
                continue;
            }
        };

        let extracted = match file_type {
            FileType::Directory => {
                let created = chroot.create_directory(&output_path);
                if created {
                    directory_metadata.push((
                        output_path.clone(),
                        u32::from(metadata.mode()),
                        metadata.uid(),
                        metadata.gid(),
                    ));
                    extract_ext_directory(
                        filesystem,
                        &entry_path,
                        chroot,
                        directory_metadata,
                        success,
                    );
                }
                created
            }
            FileType::Regular => match filesystem.read(entry_path.as_path()) {
                Ok(data) => chroot.create_file(&output_path, &data),
                Err(e) => {
                    error!("Failed to read EXT file {}: {e}", entry_path.display());
                    false
                }
            },
            FileType::Symlink => match filesystem.read_link(entry_path.as_path()) {
                Ok(target) => ext_pathbuf_to_std(target).map_or_else(
                    || {
                        warn!(
                            "EXT symlink {} has a target that cannot be represented on this platform",
                            entry_path.display()
                        );
                        false
                    },
                    |target| chroot.create_symlink(&output_path, target),
                ),
                Err(e) => {
                    error!("Failed to read EXT symlink {}: {e}", entry_path.display());
                    false
                }
            },
            FileType::BlockDevice
            | FileType::CharacterDevice
            | FileType::Fifo
            | FileType::Socket => {
                // ext4-view exposes the inode mode but not the device major/minor
                // numbers, so these cannot be recreated faithfully.
                warn!(
                    "Skipping EXT special file {}: ext4-view does not expose device numbers",
                    entry_path.display()
                );
                continue;
            }
        };

        if !extracted {
            error!("Failed to extract EXT entry {}", output_path.display());
            *success = false;
            continue;
        }

        // Directory metadata is deferred until all contents exist. Symlink
        // ownership is safe to set (lchown), but chmod follows links, so never
        // apply a mode to a symlink.
        if file_type != FileType::Directory {
            chroot.set_ownership(&output_path, metadata.uid(), metadata.gid());
            if file_type != FileType::Symlink {
                chroot.set_mode(&output_path, u32::from(metadata.mode()));
            }
        }
    }
}

/// Convert an ext4-view path into a platform path, preserving non-UTF-8 bytes
/// on Unix. On other platforms non-UTF-8 paths cannot be represented.
fn ext_pathbuf_to_std(path: ext4_view::PathBuf) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from(path))
    }
    #[cfg(not(unix))]
    {
        path.to_str().ok().map(PathBuf::from)
    }
}
