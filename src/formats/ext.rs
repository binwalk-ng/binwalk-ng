use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use ext4fs::Ext4Fs;
use ext4fs::ondisk::FileType;
use log::{debug, error, warn};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// The ext2/3/4 root directory inode number.
const EXT_ROOT_INODE: u64 = 2;

/// Read file data in bounded windows: a whole-file read would allocate the
/// inode's claimed size up front.
const EXT_READ_CHUNK: u64 = 1024 * 1024;

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

    // `Ext4Fs` reads from any `Read + Seek` source; the borrowed image slice is
    // never written to.
    let mut filesystem = match Ext4Fs::open(Cursor::new(image_data)) {
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

    let mut walker = ExtWalker {
        filesystem: &mut filesystem,
        image_size,
        chroot: &chroot,
        visited_directories: HashSet::from([EXT_ROOT_INODE]),
        directory_metadata: Vec::new(),
        success: true,
    };
    walker.extract_directory(EXT_ROOT_INODE, Path::new("rootfs"));

    // Apply directory modes/ownership only after all contents have been
    // written, so a restrictive directory mode cannot block extraction.
    let success = walker.success;
    if success {
        for (path, mode, uid, gid) in walker.directory_metadata {
            chroot.set_ownership(&path, uid, gid);
            chroot.set_mode(&path, mode);
        }
    } else {
        debug!("Skipping EXT directory metadata restoration for a failed extraction");
    }

    result.success = success;
    result
}

/// State shared across the recursive EXT directory walk.
struct ExtWalker<'a, R: Read + Seek> {
    filesystem: &'a mut Ext4Fs<R>,
    image_size: usize,
    chroot: &'a Chroot,
    visited_directories: HashSet<u64>,
    directory_metadata: Vec<(PathBuf, u32, u32, u32)>,
    success: bool,
}

impl<R: Read + Seek> ExtWalker<'_, R> {
    /// Recursively extract one EXT directory, addressed by inode number.
    fn extract_directory(&mut self, directory_inode: u64, output_path: &Path) {
        let entries = match self.filesystem.read_dir_by_ino(directory_inode) {
            Ok(entries) => entries,
            Err(e) => {
                error!(
                    "Failed to read EXT directory inode {directory_inode} ({}): {e}",
                    output_path.display()
                );
                self.success = false;
                return;
            }
        };

        for entry in entries {
            // The on-disk "." and ".." entries point back into the tree; following
            // them would recurse forever (and ".." would escape the output).
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            let Some(name) = ext_name_to_path(&entry.name) else {
                warn!(
                    "EXT entry in {} has a name that cannot be represented on this platform",
                    output_path.display()
                );
                continue;
            };
            let path = output_path.join(name);
            let inode_number = u64::from(entry.inode);
            if inode_number == 0 {
                continue;
            }

            let inode = match self.filesystem.inode(inode_number) {
                Ok(inode) => inode,
                Err(e) => {
                    error!(
                        "Failed to read EXT inode {inode_number} for {}: {e}",
                        path.display()
                    );
                    self.success = false;
                    continue;
                }
            };
            let file_type = inode.file_type();

            let extracted = match file_type {
                FileType::Directory => {
                    // A corrupt image can point a directory entry at an ancestor;
                    // track visited inodes so the walk always terminates.
                    if !self.visited_directories.insert(inode_number) {
                        warn!(
                            "Skipping EXT directory cycle at {} (inode {inode_number})",
                            path.display()
                        );
                        continue;
                    }
                    let created = self.chroot.create_directory(&path);
                    if created {
                        self.directory_metadata.push((
                            path.clone(),
                            u32::from(inode.mode),
                            inode.uid,
                            inode.gid,
                        ));
                        self.extract_directory(inode_number, &path);
                    }
                    created
                }
                FileType::RegularFile => {
                    if inode.size > self.image_size as u64 {
                        debug!(
                            "EXT file {} claims {} bytes in a {}-byte image; extracting only the in-image range",
                            path.display(),
                            inode.size,
                            self.image_size
                        );
                    }
                    match read_ext_file(
                        self.filesystem,
                        inode_number,
                        inode.size,
                        self.image_size,
                    ) {
                        Ok(data) => self.chroot.create_file(&path, &data),
                        Err(e) => {
                            error!("Failed to read EXT file {}: {e}", path.display());
                            false
                        }
                    }
                }
                FileType::Symlink => match self.filesystem.read_link_by_ino(inode_number) {
                    Ok(target) => ext_name_to_path(&target).map_or_else(
                        || {
                            warn!(
                                "EXT symlink {} has a target that cannot be represented on this platform",
                                path.display()
                            );
                            false
                        },
                        |target| self.chroot.create_symlink(&path, target),
                    ),
                    Err(e) => {
                        error!("Failed to read EXT symlink {}: {e}", path.display());
                        false
                    }
                },
                FileType::BlockDevice
                | FileType::CharDevice
                | FileType::Fifo
                | FileType::Socket
                | FileType::Unknown => {
                    // The inode mode does not carry device major/minor numbers, so
                    // these cannot be recreated faithfully.
                    warn!(
                        "Skipping EXT special file {}: device numbers are not exposed",
                        path.display()
                    );
                    continue;
                }
            };

            if !extracted {
                error!("Failed to extract EXT entry {}", path.display());
                self.success = false;
                continue;
            }

            // Directory metadata is deferred until all contents exist. Symlink
            // ownership is safe to set (lchown), but chmod follows links, so never
            // apply a mode to a symlink.
            if file_type != FileType::Directory {
                self.chroot.set_ownership(&path, inode.uid, inode.gid);
                if file_type != FileType::Symlink {
                    self.chroot.set_mode(&path, u32::from(inode.mode));
                }
            }
        }
    }
}

/// Read file data in bounded windows.
///
/// `Ext4Fs::read_inode_data` concatenates the mapped blocks and therefore loses
/// sparse holes, so read through `read_inode_data_range` and zero-fill the
/// unmapped tail of each window instead.
fn read_ext_file<R: Read + Seek>(
    filesystem: &mut Ext4Fs<R>,
    inode_number: u64,
    claimed_size: u64,
    image_size: usize,
) -> ext4fs::error::Result<Vec<u8>> {
    // Bytes past the end of the image can only be sparse holes; capping also
    // stops a corrupt size field from driving an unbounded extraction.
    let size = claimed_size.min(image_size as u64);
    let mut data = Vec::new();
    let mut offset = 0u64;

    while offset < size {
        let want = (size - offset).min(EXT_READ_CHUNK) as usize;
        let chunk = filesystem.read_inode_data_range(inode_number, offset, want)?;
        data.extend_from_slice(&chunk);
        if chunk.len() < want {
            // `read_inode_data_range` stops at the last mapped byte; the rest of
            // this window is a hole and reads as zero.
            data.resize(data.len() + (want - chunk.len()), 0);
        }
        offset += want as u64;
    }

    Ok(data)
}

/// Convert a raw on-disk name into a platform path, preserving non-UTF-8 bytes
/// on Unix. On other platforms non-UTF-8 names cannot be represented.
fn ext_name_to_path(name: &[u8]) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(name)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(name).ok().map(PathBuf::from)
    }
}
