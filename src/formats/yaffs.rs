use crate::common::is_offset_safe;
use crate::extractors;
use crate::extractors::{Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Minimum number of expected YAFFS objects in a YAFFS image
const MIN_NUMBER_OF_OBJS: usize = 2;

/// Human readable description
pub const DESCRIPTION: &str = "YAFFSv2 filesystem";

/// Expect the first YAFFS entry to be either a directory (0x00000003) or file (0x00000001), big or little endian
pub fn yaffs_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x03\x00\x00\x00\x01\x00\x00\x00\xFF\xFF".to_vec(),
        b"\x00\x00\x00\x03\x00\x00\x00\x01\xFF\xFF".to_vec(),
        b"\x01\x00\x00\x00\x01\x00\x00\x00\xFF\xFF".to_vec(),
        b"\x00\x00\x00\x01\x00\x00\x00\x01\xFF\xFF".to_vec(),
    ]
}

/// Validate a YAFFS signature
pub fn yaffs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Max page size + max spare size
    const MAX_OBJ_SIZE: usize = 16896;
    const BIG_ENDIAN_FIRST_BYTE: u8 = 0;

    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        size: 0,
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let available_data = file_data.len();
    let required_min_offset = offset + (MAX_OBJ_SIZE * MIN_NUMBER_OF_OBJS);

    // Sanity check the amount of available data
    if is_offset_safe(available_data, required_min_offset, None) {
        // Detect endianness
        let endianness = match file_data[offset] {
            BIG_ENDIAN_FIRST_BYTE => Endianness::Big,
            _ => Endianness::Little,
        };

        // Determine the page
        if let Ok(page_size) = get_page_size(&file_data[offset..]) {
            // Deterine the chunk size
            if let Ok(spare_size) = get_spare_size(&file_data[offset..], page_size, endianness) {
                // Get the total image size
                if let Ok(image_size) =
                    get_image_size(&file_data[offset..], page_size, spare_size, endianness)
                {
                    result.size = image_size;
                    result.description = format!(
                        "{}, {} endian, page size: {}, spare size: {}, image size: {} bytes",
                        result.description, endianness, page_size, spare_size, image_size
                    );
                    return Ok(result);
                }
            }
        }
    }

    Err(SignatureError)
}

/// Returns the detected page size used by the YAFFS image
fn get_page_size(file_data: &[u8]) -> Result<usize, SignatureError> {
    // Spare area is expected to start with these bytes, depending on endianness and ECC settings (YAFFS2 only)
    let spare_magics = [
        b"\x00\x00\x10\x00".to_vec(),
        b"\x00\x10\x00\x00".to_vec(),
        b"\xFF\xFF\x00\x00\x10\x00".to_vec(),
        b"\xFF\xFF\x00\x10\x00\x00".to_vec(),
    ];

    // Valid YAFFS page sizes
    let page_sizes = [512, 1024, 2048, 4096, 8192, 16384];

    // Loop through each page size looking for one that is immediately followed by a valid spare data entry.
    // This is only for YAFFS2! It will fail for YAFFS1 images.
    for page_size in &page_sizes {
        for spare_magic in &spare_magics {
            let start_spare_offset: usize = *page_size;
            let end_spare_offset: usize = start_spare_offset + spare_magic.len();

            if let Some(spare_magic_candidate) = file_data.get(start_spare_offset..end_spare_offset)
            {
                // If this spare data starts with the expected bytes, then we've guessed the page size correctly
                if spare_magic_candidate == *spare_magic {
                    return Ok(*page_size);
                }
            }
        }
    }

    // Nothing valid found
    Err(SignatureError)
}

/// Returns the detected spare size of the YAFFS image
fn get_spare_size(
    file_data: &[u8],
    page_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // Valid spare sizes
    let spare_sizes = [16, 32, 64, 128, 256, 512];

    // Loop through all spare sizes until a valid object header is found
    // This is only for YAFFS2! It will fail for YAFFS1 images.
    for spare_size in &spare_sizes {
        // If this spare size is correct, this should be the location of the next object header
        let next_obj_offset: usize = (page_size + *spare_size) * MIN_NUMBER_OF_OBJS;

        if let Some(obj_header_data) = file_data.get(next_obj_offset..) {
            // Attempt to parse this data as a YAFFS object header
            if parse_yaffs_obj_header(obj_header_data, endianness).is_ok() {
                return Ok(*spare_size);
            }
        }
    }

    // Nothing valid found
    Err(SignatureError)
}

/// Returns the total size of the image, in bytes
fn get_image_size(
    file_data: &[u8],
    page_size: usize,
    spare_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // Object type for files
    const FILE_TYPE: u32 = 1;

    let mut image_size: usize = 0;
    let mut next_obj_offset: usize = 0;
    let mut previous_obj_offset = None;

    let available_data = file_data.len();
    let block_size: usize = page_size + spare_size;

    // Loop through all available data, parsing YAFFS object headers
    while is_offset_safe(available_data, next_obj_offset, previous_obj_offset) {
        match file_data.get(next_obj_offset..) {
            None => {
                return Err(SignatureError);
            }
            Some(obj_data) => {
                // Parse and validate the object header
                match parse_yaffs_obj_header(obj_data, endianness) {
                    Err(_) => {
                        // This is not necessarily an error; could just be that there is trailing data after the YAFFS image
                        break;
                    }
                    Ok(header) => {
                        // Each object header takes up at least one block of data
                        let mut data_blocks: usize = 1;

                        // If this is a file, the file data wil take up additional data blocks
                        if header.obj_type == FILE_TYPE {
                            match get_file_block_count(obj_data, page_size, endianness) {
                                Err(e) => {
                                    return Err(e);
                                }
                                Ok(block_count) => {
                                    data_blocks += block_count;
                                }
                            }
                        }

                        // Update calculated image size and object header offsets
                        previous_obj_offset = Some(next_obj_offset);
                        image_size += data_blocks * block_size;
                        next_obj_offset = image_size;
                    }
                }
            }
        }
    }

    // Sanity check the calculated image size; should be large enough to fit MIN_NUMBER_OF_OBJS, but not extend past EOF
    if (block_size * MIN_NUMBER_OF_OBJS) < image_size && image_size <= available_data {
        return Ok(image_size);
    }

    Err(SignatureError)
}

/// Returns the number of data blocks used to store file data; this size is only valid for file type objects
fn get_file_block_count(
    obj_data: &[u8],
    page_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // parse_yaffs_file_header only parses a portion of the header that we need; the partial structure starts this many bytes into the object data
    const INFO_STRUCT_START: usize = 268;

    if let Some(file_header_data) = obj_data.get(INFO_STRUCT_START..) {
        // Parse the partial object header.
        if let Ok(file_info) = parse_yaffs_file_header(file_header_data, endianness) {
            // File data is broken up into blocks of page_size bytes
            let file_block_count: usize =
                ((file_info.file_size as f64) / (page_size as f64)).ceil() as usize;
            return Ok(file_block_count);
        }
    }

    Err(SignatureError)
}

/// Stores info about a YAFFS object
#[derive(Debug, Default, Clone)]
pub struct YAFFSObject {
    // All that is needed for now is the object type; this may be updated in the future as necessary
    pub obj_type: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct YAFFSHeader {
    obj_type: dyn_endian::U32,
    parent_id: dyn_endian::U32,
    name_checksum: dyn_endian::U16,
}

/// Partially parse a YAFFS object header
pub fn parse_yaffs_obj_header(
    header_data: &[u8],
    endianness: Endianness,
) -> Result<YAFFSObject, StructureError> {
    // The name checksum field is unused and should be 0xFFFF
    const UNUSED: u16 = 0xFFFF;

    // Allowed object types
    let allowed_types = [0, 1, 2, 3, 4, 5];

    // Parse the object header
    let (obj_header, _) = YAFFSHeader::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    // Validate that the header looks sane
    if allowed_types.contains(&obj_header.obj_type.get(endianness))
        && (obj_header.parent_id.get(endianness) > 0)
        && (obj_header.name_checksum.get(endianness) == UNUSED)
    {
        return Ok(YAFFSObject {
            obj_type: obj_header.obj_type.get(endianness),
        });
    }

    Err(StructureError)
}

/// Stores info about a YAFFS file header
#[derive(Debug, Default, Clone)]
pub struct YAFFSFileHeader {
    // Only this field is needed, for now. Struct may be updated in the future if necessary.
    pub file_size: usize,
}

// Second part of an object header (after the name field)
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct YAFFSFileHeaderBytes {
    mode: dyn_endian::U32,
    uid: dyn_endian::U32,
    gid: dyn_endian::U32,
    atime: dyn_endian::U32,
    mtime: dyn_endian::U32,
    ctime: dyn_endian::U32,
    file_size: dyn_endian::U32,
}

/// Partially parse a YAFFS file header
pub fn parse_yaffs_file_header(
    header_data: &[u8],
    endianness: Endianness,
) -> Result<YAFFSFileHeader, StructureError> {
    let (file_info, _) =
        YAFFSFileHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    Ok(YAFFSFileHeader {
        file_size: file_info.file_size.get(endianness) as usize,
    })
}

/// Defines the internal extractor for YAFFS2 file systems.
///
/// The image is unpacked directly in Rust (no external `unyaffs` dependency) through the
/// chroot-safe `Chroot` API, so object paths cannot escape the extraction directory.
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::yaffs::yaffs2_extractor;
///
/// match yaffs2_extractor().utility {
///     ExtractorType::Internal(_) => {}
///     _ => panic!("yaffs extractor should be internal"),
/// }
/// ```
pub fn yaffs2_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_yaffs),
        ..Default::default()
    }
}

/// Metadata parsed from a YAFFS object header, used to reconstruct the file tree.
#[derive(Debug, Clone, Default)]
struct YaffsObjectInfo {
    obj_type: u32,
    parent_id: u32,
    name: String,
    /// Symlink target (only meaningful for symlink objects)
    alias: String,
    /// Object id this hardlink points at (only meaningful for hardlink objects)
    equiv_id: u32,
    /// Unix mode bits (used to distinguish special-file types)
    mode: u32,
    /// Packed device numbers (only meaningful for special objects)
    rdev: u32,
    /// Declared file size in bytes (only meaningful for regular files)
    file_size: usize,
}

/// Internal extractor: reconstructs the YAFFS2 file tree directly in Rust (a port of the
/// `unyaffs` utility's logic, generalized to the page/spare geometry detected by the
/// signature parser).
///
/// The image is a sequence of fixed-size chunks, each made up of `page_size` bytes of data
/// followed by a `spare_size`-byte spare/OOB area. The spare begins with the packed tags
/// (sequence number, object id, chunk id, byte count). A chunk id of 0 marks an object
/// header (file/dir/symlink/hardlink/special); chunk ids greater than 0 carry file data,
/// where chunk id `N` holds the `N`-th `page_size`-byte block of the file. Object ids from
/// the tags are mapped to each object's parent and name (from the headers) to rebuild full
/// paths, which are written out through the chroot-safe `Chroot` API.
///
/// When `output_directory` is `None`, this performs a dry run (parse/validate only, nothing
/// is written to disk).
fn extract_yaffs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const ROOT_OBJECT_ID: u32 = 1;
    const UNUSED_OBJECT_ID: u32 = 0xFFFF_FFFF;
    const TAG_SEQUENCE_NUMBER: usize = 0;
    const TAG_OBJECT_ID: usize = 4;
    const TAG_CHUNK_ID: usize = 8;
    const TAG_BYTE_COUNT: usize = 12;

    let mut result = ExtractionResult::default();

    let Some(data) = file_data.get(offset..) else {
        return result;
    };
    let Some(&first_byte) = data.first() else {
        return result;
    };

    // A big-endian image starts with the high byte of the (little) object type field == 0.
    let endianness = if first_byte == 0 {
        Endianness::Big
    } else {
        Endianness::Little
    };

    // Reuse the signature parser's geometry/size detection.
    let Ok(page_size) = get_page_size(data) else {
        return result;
    };
    let Ok(spare_size) = get_spare_size(data, page_size, endianness) else {
        return result;
    };
    let Ok(image_size) = get_image_size(data, page_size, spare_size, endianness) else {
        return result;
    };

    let block_size = page_size + spare_size;
    let chunk_count = image_size / block_size;

    // object id -> parsed header metadata, plus the sequence number it came from
    let mut objects: BTreeMap<u32, YaffsObjectInfo> = BTreeMap::new();
    let mut header_sequence: BTreeMap<u32, u32> = BTreeMap::new();
    // object id -> (chunk id -> (sequence number, valid data bytes)) for file content
    let mut file_chunks: BTreeMap<u32, BTreeMap<u32, (u32, Vec<u8>)>> = BTreeMap::new();

    for chunk_index in 0..chunk_count {
        let block_offset = chunk_index * block_size;
        let Some(page) = data.get(block_offset..block_offset + page_size) else {
            break;
        };
        let Some(spare) = data.get(block_offset + page_size..block_offset + block_size) else {
            break;
        };

        let Some(sequence) = read_u32(spare, TAG_SEQUENCE_NUMBER, endianness) else {
            continue;
        };
        let Some(object_id) = read_u32(spare, TAG_OBJECT_ID, endianness) else {
            continue;
        };
        let Some(chunk_id) = read_u32(spare, TAG_CHUNK_ID, endianness) else {
            continue;
        };

        // Skip erased / unused chunks.
        if object_id == 0 || object_id == UNUSED_OBJECT_ID {
            continue;
        }

        // YAFFS is log-structured: superseded pages are left in place, so for each
        // logical page keep the version with the highest sequence number (ties resolve
        // to the later physical page, matching how unyaffs replays the image in order).
        if chunk_id == 0 {
            // Object header chunk.
            let is_newest = match header_sequence.get(&object_id) {
                Some(&previous) => sequence >= previous,
                None => true,
            };
            if is_newest && let Some(object) = parse_full_object_header(page, endianness) {
                objects.insert(object_id, object);
                header_sequence.insert(object_id, sequence);
            }
        } else {
            // File data chunk: only `byte_count` bytes of the page are valid (the final
            // chunk of a file is usually partial).
            let byte_count = read_u32(spare, TAG_BYTE_COUNT, endianness).unwrap_or(0) as usize;
            let valid_len = byte_count.min(page_size);
            if let Some(chunk_bytes) = page.get(..valid_len) {
                let entry = file_chunks.entry(object_id).or_default();
                let is_newest = match entry.get(&chunk_id) {
                    Some((previous, _)) => sequence >= *previous,
                    None => true,
                };
                if is_newest {
                    entry.insert(chunk_id, (sequence, chunk_bytes.to_vec()));
                }
            }
        }
    }

    if objects.is_empty() {
        return result;
    }

    let chroot = output_directory.map(Chroot::new);
    let object_ids: Vec<u32> = objects.keys().copied().collect();
    let mut extracted_something = false;

    for object_id in object_ids {
        if object_id == ROOT_OBJECT_ID {
            continue;
        }
        let Some(path) = resolve_object_path(object_id, &objects) else {
            continue;
        };

        // Dry run: validate only, don't touch the filesystem.
        let Some(chroot) = &chroot else {
            extracted_something = true;
            continue;
        };

        if write_object(
            chroot,
            object_id,
            &path,
            &objects,
            &mut file_chunks,
            page_size,
        ) {
            extracted_something = true;
        }
    }

    if extracted_something {
        result.success = true;
        result.size = Some(image_size);
    }

    result
}

/// Write a single parsed object (file/dir/symlink/hardlink/special) into the chroot.
fn write_object(
    chroot: &Chroot,
    object_id: u32,
    path: &Path,
    objects: &BTreeMap<u32, YaffsObjectInfo>,
    file_chunks: &mut BTreeMap<u32, BTreeMap<u32, (u32, Vec<u8>)>>,
    page_size: usize,
) -> bool {
    // yaffs_obj_type enum values
    const FILE: u32 = 1;
    const SYMLINK: u32 = 2;
    const DIRECTORY: u32 = 3;
    const HARDLINK: u32 = 4;
    const SPECIAL: u32 = 5;

    let Some(object) = objects.get(&object_id) else {
        return false;
    };

    // Ensure the parent directory exists (paths may be nested).
    if let Some(parent) = path.parent() {
        chroot.create_directory(parent);
    }

    match object.obj_type {
        DIRECTORY => chroot.create_directory(path),
        SYMLINK => chroot.create_symlink(path, &object.alias),
        // The Chroot API has no hardlink primitive; represent a hardlink as a symlink to
        // its target object, mirroring how the tarball extractor handles hardlinks.
        // resolve_object_path returns a path relative to the extraction root, so anchor
        // it at "/": create_symlink resolves a *relative* target against the symlink's
        // own parent directory, which would aim a nested hardlink at the wrong place.
        HARDLINK => resolve_object_path(object.equiv_id, objects)
            .is_some_and(|target| chroot.create_symlink(path, Path::new("/").join(target))),
        FILE => {
            let contents =
                materialize_file(file_chunks.remove(&object_id), object.file_size, page_size);
            chroot.create_file(path, &contents)
        }
        SPECIAL => create_special_file(chroot, path, object),
        // Unknown object type: nothing to write.
        _ => false,
    }
}

/// Reassemble a regular file's contents by placing each data chunk at its logical offset
/// `(chunk_id - 1) * page_size`, zero-filling any holes between chunks.
///
/// The buffer length is bounded by the data actually present (then truncated to the
/// declared `file_size` when that is smaller), so a corrupt size field cannot trigger a
/// huge allocation — mirroring the tarball extractor's "don't trust the header size"
/// stance while still honoring chunk positions and the partial final page.
fn materialize_file(
    chunks: Option<BTreeMap<u32, (u32, Vec<u8>)>>,
    file_size: usize,
    page_size: usize,
) -> Vec<u8> {
    let chunks = chunks.unwrap_or_default();

    // Furthest byte any present chunk reaches (the final chunk's tag byte count already
    // encodes the partial last page).
    let content_end = chunks
        .iter()
        .map(|(&chunk_id, (_seq, bytes))| {
            (chunk_id as usize)
                .saturating_sub(1)
                .saturating_mul(page_size)
                .saturating_add(bytes.len())
        })
        .max()
        .unwrap_or(0);

    // Logical length: the declared size, but never larger than the chunk data supports.
    let len = if file_size == 0 {
        content_end
    } else {
        file_size.min(content_end)
    };

    let mut contents = vec![0u8; len];
    for (chunk_id, (_seq, bytes)) in chunks {
        let start = (chunk_id as usize)
            .saturating_sub(1)
            .saturating_mul(page_size);
        if start >= len {
            continue;
        }
        let copy_len = bytes.len().min(len - start);
        contents[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
    }
    contents
}

/// Create a placeholder for a YAFFS special file (device node / fifo / socket), using the
/// object's mode bits to pick the kind. As with the other extractors, device nodes are
/// represented as regular files describing the device rather than real device nodes.
fn create_special_file(chroot: &Chroot, path: &Path, object: &YaffsObjectInfo) -> bool {
    // S_IFMT file-type bits
    const S_IFMT: u32 = 0o170_000;
    const S_IFSOCK: u32 = 0o140_000;
    const S_IFBLK: u32 = 0o060_000;
    const S_IFCHR: u32 = 0o020_000;

    let major = ((object.rdev >> 8) & 0xff) as usize;
    let minor = (object.rdev & 0xff) as usize;

    match object.mode & S_IFMT {
        S_IFCHR => chroot.create_character_device(path, major, minor),
        S_IFBLK => chroot.create_block_device(path, major, minor),
        S_IFSOCK => chroot.create_socket(path),
        // Treat fifos and anything else as a fifo placeholder.
        _ => chroot.create_fifo(path),
    }
}

/// Fully parse a YAFFS object header from a header chunk's page data.
fn parse_full_object_header(page: &[u8], endianness: Endianness) -> Option<YaffsObjectInfo> {
    const NAME_CHECKSUM_OFFSET: usize = 8;
    const NAME_OFFSET: usize = 10;
    const NAME_MAX_LEN: usize = 256;
    const MODE_OFFSET: usize = 268;
    const FILE_SIZE_OFFSET: usize = 292;
    const EQUIV_ID_OFFSET: usize = 296;
    const ALIAS_OFFSET: usize = 300;
    const ALIAS_MAX_LEN: usize = 160;
    const RDEV_OFFSET: usize = 460;
    const MAX_OBJ_TYPE: u32 = 5;
    // The name-checksum field is unused in modern YAFFS images and is set to all-ones.
    const NAME_CHECKSUM_UNUSED: u16 = 0xFFFF;

    let obj_type = read_u32(page, 0, endianness)?;
    let parent_id = read_u32(page, 4, endianness)?;
    let name_checksum = read_u16(page, NAME_CHECKSUM_OFFSET, endianness)?;

    // Mirror parse_yaffs_obj_header's sanity checks, including the unused name-checksum
    // sentinel, so corrupt pages with chunk id 0 are rejected.
    if obj_type > MAX_OBJ_TYPE || parent_id == 0 || name_checksum != NAME_CHECKSUM_UNUSED {
        return None;
    }

    Some(YaffsObjectInfo {
        obj_type,
        parent_id,
        name: read_cstring(page, NAME_OFFSET, NAME_MAX_LEN),
        alias: read_cstring(page, ALIAS_OFFSET, ALIAS_MAX_LEN),
        equiv_id: read_u32(page, EQUIV_ID_OFFSET, endianness).unwrap_or(0),
        mode: read_u32(page, MODE_OFFSET, endianness).unwrap_or(0),
        rdev: read_u32(page, RDEV_OFFSET, endianness).unwrap_or(0),
        file_size: read_u32(page, FILE_SIZE_OFFSET, endianness).unwrap_or(0) as usize,
    })
}

/// Resolve an object's full (relative) path by walking the parent chain up to the root.
fn resolve_object_path(
    object_id: u32,
    objects: &BTreeMap<u32, YaffsObjectInfo>,
) -> Option<PathBuf> {
    const ROOT_OBJECT_ID: u32 = 1;
    // Bounds the walk so a corrupt/cyclic parent chain cannot loop forever.
    const MAX_PATH_DEPTH: usize = 1000;

    let mut components: Vec<&str> = Vec::new();
    let mut current_id = object_id;

    for _ in 0..MAX_PATH_DEPTH {
        if current_id == ROOT_OBJECT_ID {
            let mut path = PathBuf::new();
            for component in components.iter().rev() {
                path.push(component);
            }
            return Some(path);
        }

        let object = objects.get(&current_id)?;
        if object.name.is_empty() {
            return None;
        }
        components.push(&object.name);
        current_id = object.parent_id;
    }

    None
}

/// Read a little/big-endian `u32` at `offset`, returning `None` if out of bounds.
fn read_u32(data: &[u8], offset: usize, endianness: Endianness) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(match endianness {
        Endianness::Big => u32::from_be_bytes(bytes),
        Endianness::Little => u32::from_le_bytes(bytes),
    })
}

/// Read a little/big-endian `u16` at `offset`, returning `None` if out of bounds.
fn read_u16(data: &[u8], offset: usize, endianness: Endianness) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(match endianness {
        Endianness::Big => u16::from_be_bytes(bytes),
        Endianness::Little => u16::from_le_bytes(bytes),
    })
}

/// Read a NUL-terminated string of at most `max_len` bytes starting at `offset`.
fn read_cstring(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = offset.saturating_add(max_len).min(data.len());
    let field = data.get(offset..end).unwrap_or(&[]);
    let string_len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..string_len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared test fixture: a little-endian YAFFS2 image (page size 2048, spare size 64)
    /// containing 13 regular files in the root directory (the yaffs source headers used to
    /// build it). Image size is 126720 bytes; the file has trailing padding past that.
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/inputs/yaffs2.bin"
    ));
    const IMAGE_SIZE: usize = 126720;

    #[test]
    fn detects_page_and_spare_size() {
        assert_eq!(get_page_size(FIXTURE).unwrap(), 2048);
        assert_eq!(
            get_spare_size(FIXTURE, 2048, Endianness::Little).unwrap(),
            64
        );
    }

    #[test]
    fn parser_reports_image_geometry() {
        let result = yaffs_parser(FIXTURE, 0).unwrap();
        assert_eq!(result.offset, 0);
        assert_eq!(result.size, IMAGE_SIZE);
        assert!(result.description.contains("page size: 2048"));
        assert!(result.description.contains("spare size: 64"));
        assert!(result.description.contains("Little"));
    }

    #[test]
    fn first_object_header_is_a_file() {
        // The first chunk is an object header for a regular file (yaffs type 1).
        let object = parse_yaffs_obj_header(FIXTURE, Endianness::Little).unwrap();
        assert_eq!(object.obj_type, 1);

        let full = parse_full_object_header(&FIXTURE[..2048], Endianness::Little).unwrap();
        assert_eq!(full.obj_type, 1);
        assert_eq!(full.parent_id, 1); // lives in the root directory
        assert!(!full.name.is_empty());
    }

    #[test]
    fn read_u32_respects_endianness() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(
            read_u32(&bytes, 0, Endianness::Little).unwrap(),
            0x0403_0201
        );
        assert_eq!(read_u32(&bytes, 0, Endianness::Big).unwrap(), 0x0102_0304);
        // Out-of-bounds reads return None rather than panicking.
        assert!(read_u32(&bytes, 2, Endianness::Little).is_none());
    }

    #[test]
    fn read_cstring_stops_at_nul() {
        let bytes = b"hello\x00world";
        assert_eq!(read_cstring(bytes, 0, 11), "hello");
        assert_eq!(read_cstring(bytes, 6, 5), "world");
        // A field with no NUL is read up to max_len / end of slice.
        assert_eq!(read_cstring(b"abc", 0, 8), "abc");
    }

    #[test]
    fn resolve_path_walks_parent_chain() {
        let mut objects = BTreeMap::new();
        objects.insert(
            10,
            YaffsObjectInfo {
                obj_type: 3,
                parent_id: 1,
                name: "dir".to_string(),
                ..Default::default()
            },
        );
        objects.insert(
            11,
            YaffsObjectInfo {
                obj_type: 1,
                parent_id: 10,
                name: "file.txt".to_string(),
                ..Default::default()
            },
        );
        assert_eq!(
            resolve_object_path(10, &objects).unwrap(),
            PathBuf::from("dir")
        );
        assert_eq!(
            resolve_object_path(11, &objects).unwrap(),
            PathBuf::from("dir").join("file.txt")
        );
        // An object whose parent chain never reaches the root is rejected.
        let mut orphan = BTreeMap::new();
        orphan.insert(
            5,
            YaffsObjectInfo {
                obj_type: 1,
                parent_id: 999,
                name: "lost".to_string(),
                ..Default::default()
            },
        );
        assert!(resolve_object_path(5, &orphan).is_none());
    }

    #[test]
    fn dry_run_validates_without_writing() {
        let result = extract_yaffs(FIXTURE, 0, None);
        assert!(result.success);
        assert_eq!(result.size, Some(IMAGE_SIZE));
    }

    #[test]
    fn nested_hardlink_resolves_to_target() {
        // A regular file in one directory and a hardlink to it from a *different*
        // directory, to exercise root-relative target resolution.
        let mut objects = BTreeMap::new();
        objects.insert(
            10,
            YaffsObjectInfo {
                obj_type: 3,
                parent_id: 1,
                name: "d1".to_string(),
                ..Default::default()
            },
        );
        objects.insert(
            11,
            YaffsObjectInfo {
                obj_type: 1,
                parent_id: 10,
                name: "f.txt".to_string(),
                file_size: 5,
                ..Default::default()
            },
        );
        objects.insert(
            12,
            YaffsObjectInfo {
                obj_type: 3,
                parent_id: 1,
                name: "d2".to_string(),
                ..Default::default()
            },
        );
        objects.insert(
            13,
            YaffsObjectInfo {
                obj_type: 4,
                parent_id: 12,
                name: "link".to_string(),
                equiv_id: 11,
                ..Default::default()
            },
        );

        let mut file_chunks: BTreeMap<u32, BTreeMap<u32, (u32, Vec<u8>)>> = BTreeMap::new();
        let mut chunks = BTreeMap::new();
        chunks.insert(1u32, (4096u32, b"hello".to_vec()));
        file_chunks.insert(11, chunks);

        let output = tempfile::tempdir().unwrap();
        let chroot = Chroot::new(output.path());

        for id in [10u32, 11, 12, 13] {
            let path = resolve_object_path(id, &objects).unwrap();
            assert!(write_object(
                &chroot,
                id,
                &path,
                &objects,
                &mut file_chunks,
                2048
            ));
        }

        // The file extracted correctly...
        assert_eq!(
            std::fs::read_to_string(output.path().join("d1").join("f.txt")).unwrap(),
            "hello"
        );
        // ...and the nested hardlink (written as a symlink) resolves back to it rather
        // than to a path relative to its own directory.
        let link = output.path().join("d2").join("link");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "hello");
    }

    #[test]
    fn extracts_all_files_to_disk() {
        let output = tempfile::tempdir().unwrap();
        let result = extract_yaffs(FIXTURE, 0, Some(output.path()));
        assert!(result.success);
        assert_eq!(result.size, Some(IMAGE_SIZE));

        // The fixture holds 13 regular files, all in the root directory.
        let entries: Vec<_> = std::fs::read_dir(output.path())
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 13);

        // Spot-check two recognizable files and their exact sizes.
        let guts = output.path().join("yaffs_guts.h");
        assert!(guts.is_file());
        assert_eq!(std::fs::metadata(&guts).unwrap().len(), 27266);

        let mk = output.path().join("mkyaffs2image.c");
        assert!(mk.is_file());
        assert_eq!(std::fs::metadata(&mk).unwrap().len(), 15107);
    }
}
