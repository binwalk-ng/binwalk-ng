use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use ext4fs::Ext4Fs;
use ext4fs::ondisk::FileType;
use log::{debug, error, warn};
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// The ext2/3/4 root directory inode number.
const EXT_ROOT_INODE: u64 = 2;

/// Human readable description
pub const DESCRIPTION: &str = "EXT filesystem";

/// EXT filesystem magic signatures.
pub fn ext_magic() -> Vec<Vec<u8>> {
    // Only u16 magic; include state/errors/minor-rev variants to reduce false positives.
    vec![
        b"\x53\xEF\x01\x00\x01\x00\x00\x00".to_vec(),
        b"\x53\xEF\x01\x00\x02\x00\x00\x00".to_vec(),
        b"\x53\xEF\x01\x00\x03\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x01\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x02\x00\x00\x00".to_vec(),
        b"\x53\xEF\x02\x00\x03\x00\x00\x00".to_vec(),
    ]
}

pub fn ext_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MAGIC_OFFSET: usize = 1080;

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
            ext_header.blocks_count,
            ext_header.free_blocks_count,
            ext_header.reserved_blocks_count,
            result.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}

pub const SUPERBLOCK_SIZE: usize = 1024;
pub const SUPERBLOCK_OFFSET: usize = 1024;

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

pub fn parse_ext_header(ext_data: &[u8]) -> Result<EXTHeader, StructureError> {
    const MAX_BLOCK_LOG: u32 = 2;

    const ALLOWED_REV_LEVELS: [u32; 2] = [0, 1];
    const ALLOWED_FIRST_DATA_BLOCKS: [u32; 2] = [0, 1];

    if ext_data.len() >= (SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE) {
        let (ext_superblock, _) =
            EXTSuprtBlockBytes::ref_from_prefix(&ext_data[SUPERBLOCK_OFFSET..])
                .map_err(|_| StructureError)?;

        let creator_os = match ext_superblock.creator_os.get() {
            0 => "Linux",
            1 => "GNU HURD",
            2 => "MASIX",
            3 => "FreeBSD",
            4 => "Lites",
            _ => return Err(StructureError),
        };
        if ALLOWED_REV_LEVELS.contains(&ext_superblock.s_rev_level.get())
            && ALLOWED_FIRST_DATA_BLOCKS.contains(&ext_superblock.first_data_block.get())
            && ext_superblock.log_block_size.get() <= MAX_BLOCK_LOG
        {
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

/// Unpack an ext2/ext3/ext4 image into `rootfs/` under `output_directory`.
///
/// When `output_directory` is `None`, the filesystem is opened but no contents are
/// extracted or traversed.
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

    let Some(image_end) = offset.checked_add(image_size) else {
        error!("EXT image range overflows at offset {offset:#X}");
        return result;
    };
    let Some(image_data) = file_data.get(offset..image_end) else {
        error!("EXT image at offset {offset:#X} extends past the end of the file");
        return result;
    };

    let mut filesystem = match Ext4Fs::open(Cursor::new(image_data)) {
        Ok(filesystem) => filesystem,
        Err(e) => {
            error!("Failed to load EXT filesystem at offset {offset:#X}: {e}");
            return result;
        }
    };
    result.size = Some(image_size);

    let Some(output_directory) = output_directory else {
        result.success = true;
        return result;
    };

    let rootfs = output_directory.join("rootfs");
    if !Chroot::new(output_directory).create_directory(Path::new("rootfs")) {
        error!("Failed to create the EXT output directory");
        return result;
    }

    let chroot = Chroot::new(&rootfs);
    let mut walker = ExtWalker {
        filesystem: &mut filesystem,
        block_size: header.block_size,
        chroot: &chroot,
        visited_directories: HashSet::from([EXT_ROOT_INODE]),
        directory_metadata: Vec::new(),
        success: true,
    };
    walker.extract_directory_contents(EXT_ROOT_INODE, Path::new(""));

    // Restore directory metadata deepest-first so a restrictive parent mode does
    // not block chmod/chown on its children.
    let success = walker.success;
    if success {
        walker
            .directory_metadata
            .sort_by_key(|(path, ..)| std::cmp::Reverse(path.components().count()));
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

struct ExtWalker<'a, R: Read + Seek> {
    filesystem: &'a mut Ext4Fs<R>,
    block_size: usize,
    chroot: &'a Chroot,
    visited_directories: HashSet<u64>,
    directory_metadata: Vec<(PathBuf, u32, u32, u32)>,
    success: bool,
}

impl<R: Read + Seek> ExtWalker<'_, R> {
    fn extract_directory_contents(&mut self, directory_inode: u64, output_path: &Path) {
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

            // Extract only allocated inodes.
            let allocated = match self.filesystem.is_inode_allocated(inode_number) {
                Ok(allocated) => allocated,
                Err(e) => {
                    error!(
                        "Failed to check EXT inode allocation for {}: {e}",
                        path.display()
                    );
                    self.success = false;
                    continue;
                }
            };
            if !allocated {
                debug!(
                    "Skipping EXT entry {} with unallocated inode {inode_number}",
                    path.display()
                );
                continue;
            }

            let extracted = match file_type {
                FileType::Directory => {
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
                        self.extract_directory_contents(inode_number, &path);
                    }
                    created
                }
                FileType::RegularFile => {
                    match write_ext_file(
                        self.filesystem,
                        inode_number,
                        &inode,
                        self.block_size,
                        self.chroot,
                        &path,
                    ) {
                        Ok(()) => true,
                        Err(e) => {
                            error!("Failed to extract EXT file {}: {e}", path.display());
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

            // Directory metadata is deferred; chmod follows symlinks.
            if file_type != FileType::Directory {
                self.chroot.set_ownership(&path, inode.uid, inode.gid);
                if file_type != FileType::Symlink {
                    self.chroot.set_mode(&path, u32::from(inode.mode));
                }
            }
        }
    }
}

/// Explicit extraction budget for a single EXT file. A corrupt or malicious
/// size field can claim an absurd logical size; failing explicitly is better
/// than silently truncating or attempting an unbounded allocation.
const MAX_EXT_FILE_BYTES: u64 = 1 << 40; // 1 TiB

#[derive(Clone, Copy)]
struct ExtMapEntry {
    logical_block: u64,
    physical_block: u64,
    length: u64,
    unwritten: bool,
}

fn walk_ext_map<R: Read + Seek>(
    filesystem: &mut Ext4Fs<R>,
    inode: &ext4fs::ondisk::Inode,
    block_size: usize,
) -> ext4fs::error::Result<Vec<ExtMapEntry>> {
    if inode.uses_extents() {
        let mut out = Vec::new();
        walk_extent_node(filesystem, inode.i_block.as_slice(), &mut out, 0)?;
        Ok(out)
    } else {
        walk_indirect_blocks(filesystem, &inode.i_block, block_size)
    }
}

fn walk_extent_node<R: Read + Seek>(
    filesystem: &mut Ext4Fs<R>,
    buf: &[u8],
    out: &mut Vec<ExtMapEntry>,
    depth: usize,
) -> ext4fs::error::Result<()> {
    if depth > 5 {
        return Err(ext4fs::error::Ext4Error::CorruptMetadata {
            structure: "extent tree",
            detail: "depth exceeds limit".to_string(),
        });
    }
    let header = ext4fs::ondisk::ExtentHeader::parse(buf)?;
    let entries = header.entries as usize;

    if header.depth == 0 {
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > buf.len() {
                break;
            }
            let leaf = ext4fs::ondisk::ExtentLeaf::parse(&buf[off..]);
            if leaf.length == 0 {
                continue;
            }
            out.push(ExtMapEntry {
                logical_block: u64::from(leaf.logical_block),
                physical_block: leaf.physical_block,
                length: u64::from(leaf.length),
                unwritten: leaf.unwritten,
            });
        }
    } else {
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > buf.len() {
                break;
            }
            let idx = ext4fs::ondisk::ExtentIndex::parse(&buf[off..]);
            let child = filesystem.read_block(idx.child_block)?;
            walk_extent_node(filesystem, &child, out, depth + 1)?;
        }
    }
    Ok(())
}

fn walk_indirect_blocks<R: Read + Seek>(
    filesystem: &mut Ext4Fs<R>,
    i_block: &[u8; 60],
    block_size: usize,
) -> ext4fs::error::Result<Vec<ExtMapEntry>> {
    let ptrs_per_block = block_size / 4;
    let read_u32 = |buf: &[u8], off: usize| -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    };

    let mut out = Vec::new();
    let mut logical = 0u64;

    for i in 0..12usize {
        let ptr = u64::from(read_u32(i_block, i * 4));
        if ptr != 0 {
            out.push(ExtMapEntry {
                logical_block: logical,
                physical_block: ptr,
                length: 1,
                unwritten: false,
            });
        }
        logical += 1;
    }

    let sind = u64::from(read_u32(i_block, 48));
    if sind != 0 {
        let blk = filesystem.read_block(sind)?;
        for i in 0..ptrs_per_block {
            let ptr = u64::from(read_u32(&blk, i * 4));
            if ptr != 0 {
                out.push(ExtMapEntry {
                    logical_block: logical,
                    physical_block: ptr,
                    length: 1,
                    unwritten: false,
                });
            }
            logical += 1;
        }
    } else {
        logical += ptrs_per_block as u64;
    }

    let dind = u64::from(read_u32(i_block, 52));
    if dind != 0 {
        let l1 = filesystem.read_block(dind)?;
        for i in 0..ptrs_per_block {
            let ptr1 = u64::from(read_u32(&l1, i * 4));
            if ptr1 != 0 {
                let l2 = filesystem.read_block(ptr1)?;
                for j in 0..ptrs_per_block {
                    let ptr2 = u64::from(read_u32(&l2, j * 4));
                    if ptr2 != 0 {
                        out.push(ExtMapEntry {
                            logical_block: logical,
                            physical_block: ptr2,
                            length: 1,
                            unwritten: false,
                        });
                    }
                    logical += 1;
                }
            } else {
                logical += ptrs_per_block as u64;
            }
        }
    } else {
        logical += (ptrs_per_block * ptrs_per_block) as u64;
    }

    let tind = u64::from(read_u32(i_block, 56));
    if tind != 0 {
        let l1 = filesystem.read_block(tind)?;
        for i in 0..ptrs_per_block {
            let ptr1 = u64::from(read_u32(&l1, i * 4));
            if ptr1 != 0 {
                let l2 = filesystem.read_block(ptr1)?;
                for j in 0..ptrs_per_block {
                    let ptr2 = u64::from(read_u32(&l2, j * 4));
                    if ptr2 != 0 {
                        let l3 = filesystem.read_block(ptr2)?;
                        for k in 0..ptrs_per_block {
                            let ptr3 = u64::from(read_u32(&l3, k * 4));
                            if ptr3 != 0 {
                                out.push(ExtMapEntry {
                                    logical_block: logical,
                                    physical_block: ptr3,
                                    length: 1,
                                    unwritten: false,
                                });
                            }
                            logical += 1;
                        }
                    } else {
                        logical += ptrs_per_block as u64;
                    }
                }
            } else {
                logical += (ptrs_per_block * ptrs_per_block) as u64;
            }
        }
    }

    Ok(out)
}

/// Write file data in filesystem-block-sized windows, preserving sparse holes.
///
/// Reading one logical block at a time keeps each range either fully mapped or
/// a hole, so unmapped regions become sparse holes in the output. Data is
/// streamed through a chroot-controlled writer to avoid buffering the full
/// logical file in memory.
///
/// Inline-data inodes are read whole: `read_inode_data_range` does not expose
/// the `system.data` xattr overflow used for inline content > 60 bytes.
fn write_ext_file<R: Read + Seek>(
    filesystem: &mut Ext4Fs<R>,
    inode_number: u64,
    inode: &ext4fs::ondisk::Inode,
    block_size: usize,
    chroot: &Chroot,
    path: &Path,
) -> ext4fs::error::Result<()> {
    let size = inode.size;
    if size > MAX_EXT_FILE_BYTES {
        return Err(ext4fs::error::Ext4Error::CorruptMetadata {
            structure: "inode",
            detail: format!("file size {size} exceeds extraction limit {MAX_EXT_FILE_BYTES} bytes"),
        });
    }
    let size_usize =
        usize::try_from(size).map_err(|_| ext4fs::error::Ext4Error::CorruptMetadata {
            structure: "inode",
            detail: format!("file size {size} does not fit addressable memory"),
        })?;

    let mut file = chroot.create_file_writer(path).ok_or_else(|| {
        ext4fs::error::Ext4Error::Io(std::io::Error::other(format!(
            "failed to create extracted file {}",
            path.display()
        )))
    })?;

    if inode.has_inline_data() {
        let mut data = filesystem.read_inode_data(inode_number)?;
        if data.len() < size_usize {
            return Err(ext4fs::error::Ext4Error::CorruptMetadata {
                structure: "inode",
                detail: format!(
                    "inline data is incomplete: expected {size_usize} bytes, got {}",
                    data.len()
                ),
            });
        }
        data.truncate(size_usize);
        file.write_all(&data)?;
        file.set_len(size)?;
        return Ok(());
    }

    let map = walk_ext_map(filesystem, inode, block_size)?;

    let mut pos = 0u64;
    for mapping in &map {
        let logical_start = mapping.logical_block.saturating_mul(block_size as u64);
        if logical_start >= size {
            break;
        }
        if logical_start > pos {
            // Gap in mappings is a sparse hole.
            file.seek(SeekFrom::Start(logical_start.min(size)))?;
            pos = logical_start;
        }

        for blk_offset in 0..mapping.length {
            let logical = (mapping.logical_block + blk_offset) * block_size as u64;
            if logical >= size {
                break;
            }
            let write_len = ((size - logical) as usize).min(block_size);
            if mapping.unwritten {
                // Unwritten extents must read back as zeros.
                file.seek(SeekFrom::Start(logical + write_len as u64))?;
            } else {
                let phys = mapping.physical_block + blk_offset;
                let blk_data = filesystem.read_block(phys)?;
                let end = write_len.min(blk_data.len());
                file.seek(SeekFrom::Start(logical))?;
                file.write_all(&blk_data[..end])?;
                if end < write_len {
                    file.seek(SeekFrom::Start(logical + write_len as u64))?;
                }
            }
            pos = logical + write_len as u64;
        }
    }

    if pos < size {
        // Trailing hole extends to logical EOF.
        file.seek(SeekFrom::Start(size))?;
    }
    file.set_len(size)?;
    Ok(())
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
