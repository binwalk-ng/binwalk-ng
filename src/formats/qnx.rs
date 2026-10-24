use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::{debug, error, warn};
use qnx_ifs::{Compress, Endian, Entry, EntryKind, Image};
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const IFS_DESCRIPTION: &str = "QNX IFS image";

/// On-disk QNX image filesystem header (`struct image_header`), up to the
/// NUL terminated mountpoint string.
///
/// `qnx-ifs` does not export the size of its own layout structure, so mirror
/// it here and derive the constant with `size_of` rather than hard-coding it.
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct QNXImageHeaderBytes {
    signature: [u8; 7],
    flags: u8,
    image_size: u32,
    hdr_dir_size: u32,
    dir_offset: u32,
    boot_ino: [u32; 4],
    script_ino: u32,
    chain_paddr: u32,
    spare: [u32; 10],
    mountflags: u32,
}

/// Fixed size of a QNX image filesystem header (`struct image_header`),
/// before the NUL terminated mountpoint string.
const QNX_IMAGE_HEADER_SIZE: usize = size_of::<QNXImageHeaderBytes>();

// The integration test fixtures (tests/qnx.rs) hard-code this size in order to
// build image filesystems by hand; fail to compile if it ever drifts.
const _: () = assert!(QNX_IMAGE_HEADER_SIZE == 88);

/// QNX IFS magic bytes
pub fn qnx_ifs_magic() -> Vec<Vec<u8>> {
    vec![
        // Startup header: magic followed by version 1, little and big endian.
        b"\xEB\x7E\xFF\x00\x01\x00".to_vec(),
        b"\x00\xFF\x7E\xEB\x00\x01".to_vec(),
        // Bare image filesystem, without a startup header.
        qnx_ifs::image::IMAGE_SIGNATURE.to_vec(),
    ]
}

/// Validate a QNX IFS signature
pub fn qnx_ifs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: IFS_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.get(offset..).ok_or(SignatureError)?;

    // Bare image filesystems have no startup header. Validate the header and
    // its structural size relationships, but leave walking the dirent chain to
    // extraction: scanning must not do work proportional to every "imagefs"
    // match in a hostile file.
    if available_data.starts_with(qnx_ifs::image::IMAGE_SIGNATURE) {
        let (image_header, endian) =
            qnx_ifs::parse_image_header(available_data, 0).map_err(|_| SignatureError)?;
        let total_size = image_header.image_size;

        // The same constraints qnx-ifs enforces before it walks the dirents.
        if total_size == 0
            || total_size > available_data.len()
            || image_header.dir_offset < QNX_IMAGE_HEADER_SIZE
            || image_header.dir_offset > image_header.hdr_dir_size
            || total_size < image_header.hdr_dir_size.saturating_add(4)
        {
            return Err(SignatureError);
        }

        result.size = total_size;
        result.description = format!(
            "{}, endianness: {}, mountpoint: {}, total size: {} bytes",
            result.description,
            endian_name(endian),
            image_header.mountpoint,
            total_size
        );

        return Ok(result);
    }

    // For bootable images, validating the startup header is enough for
    // signature detection. The filesystem may be compressed, so defer
    // decompression and dirent parsing to extraction.
    let startup = qnx_ifs::parse_startup_header(available_data, 0).map_err(|_| SignatureError)?;
    let total_size = startup.stored_size;

    if total_size == 0 || total_size > available_data.len() {
        return Err(SignatureError);
    }

    result.size = total_size;
    result.description = format!(
        "{}, endianness: {}, compression: {}, total size: {} bytes",
        result.description,
        endian_name(startup.endian),
        compression_name(startup.compress),
        total_size
    );

    Ok(result)
}

/// Stores info on a QNX IFS header
#[derive(Debug, Clone, Copy)]
pub struct IFSHeader {
    pub total_size: usize,
}

/// Parse a QNX IFS startup header
pub fn parse_ifs_header(ifs_data: &[u8]) -> Result<IFSHeader, StructureError> {
    let startup = qnx_ifs::parse_startup_header(ifs_data, 0).map_err(|_| StructureError)?;
    Ok(IFSHeader {
        total_size: startup.stored_size,
    })
}

const fn endian_name(endian: Endian) -> &'static str {
    match endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    }
}

const fn compression_name(compression: Compress) -> &'static str {
    match compression {
        Compress::None => "none",
        Compress::Zlib => "zlib",
        Compress::Lzo => "lzo",
        Compress::Ucl => "ucl",
    }
}

/// Describes the internal extractor for QNX IFS images
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::qnx::qnx_ifs_extractor;
///
/// match qnx_ifs_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => panic!("Unexpected external extractor '{}'", cmd),
/// }
/// ```
pub fn qnx_ifs_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_qnx_ifs),
        ..Default::default()
    }
}

/// Extract the contents of a QNX IFS image
pub fn extract_qnx_ifs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(ifs_data) = file_data.get(offset..) else {
        error!("QNX IFS extractor received invalid offset {offset:#X}");
        return result;
    };

    let image = match Image::parse(ifs_data) {
        Ok(image) => image,
        Err(e) => {
            error!("Failed to parse QNX IFS image at offset {offset:#X}: {e}");
            return result;
        }
    };

    result.size = Some(image.total_size());

    // Dirents with a zero inode are skipped by the kernel and quarantined by
    // the parser; report how many were skipped rather than dropping them in
    // silence.
    if !image.omitted_dirents.is_empty() {
        debug!(
            "QNX IFS image at offset {offset:#X} contains {} dirent(s) with a zero inode, skipped as the kernel would",
            image.omitted_dirents.len()
        );
    }

    // A dry run validates the image without touching the filesystem.
    let Some(output_directory) = output_directory else {
        result.success = true;
        return result;
    };

    let chroot = Chroot::new(output_directory);
    let mut success = true;

    // Create every directory before extracting its contents. Directory
    // metadata is applied afterwards, so restrictive modes cannot prevent
    // files from being written into the directory.
    let mut directory_metadata: Vec<(PathBuf, u32, u32, u32)> = Vec::new();
    for entry in &image.entries {
        if !matches!(entry.kind, EntryKind::Dir) {
            continue;
        }

        let path = entry_path(entry);
        if chroot.create_directory(&path) {
            directory_metadata.push((path, entry.uid, entry.gid, entry.permissions()));
        } else {
            error!("Failed to create directory {}", path.display());
            success = false;
        }
    }

    for entry in &image.entries {
        if matches!(entry.kind, EntryKind::Dir) {
            continue;
        }

        let path = entry_path(entry);
        let extracted = match &entry.kind {
            EntryKind::Dir => unreachable!("directories are handled above"),
            EntryKind::File { .. } => {
                ensure_parent(&chroot, &path)
                    && image
                        .file_bytes(entry)
                        .is_some_and(|file_data| chroot.create_file(&path, file_data))
            }
            EntryKind::Symlink { .. } => {
                ensure_parent(&chroot, &path)
                    && symlink_target(entry)
                        .is_some_and(|target| chroot.create_symlink(&path, target))
            }
            EntryKind::Char { rdev, .. } => {
                ensure_parent(&chroot, &path)
                    && chroot.create_character_device(
                        &path,
                        device_major(*rdev),
                        device_minor(*rdev),
                    )
            }
            EntryKind::Block { rdev, .. } => {
                ensure_parent(&chroot, &path)
                    && chroot.create_block_device(&path, device_major(*rdev), device_minor(*rdev))
            }
            EntryKind::Fifo { .. } => ensure_parent(&chroot, &path) && chroot.create_fifo(&path),
            EntryKind::Socket { .. } => {
                ensure_parent(&chroot, &path) && chroot.create_socket(&path)
            }
            // Named special files (QNX semaphores and shared memory names) have
            // no direct Unix filesystem equivalent; record their packed device
            // number as text, matching the device placeholder convention.
            EntryKind::Named { rdev, .. } => {
                ensure_parent(&chroot, &path)
                    && chroot.create_file(
                        &path,
                        format!("n {} {}", device_major(*rdev), device_minor(*rdev)).as_bytes(),
                    )
            }
        };

        if extracted {
            apply_metadata(&chroot, &path, entry);
        } else {
            warn!("Failed to extract QNX IFS entry {}", path.display());
            success = false;
        }
    }

    // Apply directory ownership and modes now that all contents are in place.
    //
    // Only when every entry was extracted: the root directory's entry restores
    // its mode onto the output directory itself, so a hostile image could
    // otherwise leave an unwritable directory behind on failure, breaking the
    // framework's cleanup of failed extractions (and warning spam in the
    // process). On success the deferred metadata is applied faithfully, like
    // the tar extractor.
    if success {
        for (path, uid, gid, mode) in directory_metadata {
            chroot.set_ownership(&path, uid, gid);
            chroot.set_mode(&path, mode);
        }
    } else {
        debug!("Skipping directory metadata restoration for a failed QNX IFS extraction");
    }

    result.success = success;
    result
}

fn entry_path(entry: &Entry) -> PathBuf {
    path_from_bytes(&entry.raw_path, &entry.path)
}

fn symlink_target(entry: &Entry) -> Option<PathBuf> {
    match &entry.kind {
        EntryKind::Symlink {
            target, raw_target, ..
        } => Some(path_from_bytes(raw_target, target)),
        _ => None,
    }
}

/// Convert an entry path stored as raw bytes into a [`PathBuf`].
///
/// Valid UTF-8 bytes are used as-is: on Unix, `str` → `PathBuf` preserves the
/// bytes verbatim (identical to `OsStr::from_bytes`), and other platforms
/// (e.g. Windows) convert them natively. Invalid bytes fall back to the
/// parser's lossy UTF-8 decoding, which is what the `lossy` string contains.
fn path_from_bytes(raw: &[u8], lossy: &str) -> PathBuf {
    std::str::from_utf8(raw).map_or_else(|_| PathBuf::from(lossy), PathBuf::from)
}

fn ensure_parent(chroot: &Chroot, path: &Path) -> bool {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => chroot.create_directory(parent),
        _ => true,
    }
}

fn apply_metadata(chroot: &Chroot, path: &Path, entry: &Entry) {
    chroot.set_ownership(path, entry.uid, entry.gid);

    // chmod follows symlinks, so never apply mode bits to a link.
    if !matches!(entry.kind, EntryKind::Symlink { .. }) {
        chroot.set_mode(path, entry.permissions());
    }
}

// QNX device numbers encode a 6-bit major and 10-bit minor number.
const QNX_DEV_MAJOR_MASK: u32 = 0x3f;
const QNX_DEV_MINOR_MASK: u32 = 0x3ff;

const fn device_major(device: u32) -> usize {
    ((device >> 10) & QNX_DEV_MAJOR_MASK) as usize
}

const fn device_minor(device: u32) -> usize {
    (device & QNX_DEV_MINOR_MASK) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const MOUNTPOINT: &str = "/fs";
    const FILE_DATA: &[u8] = b"#!/bin/sh\necho hello\n";

    fn le16(value: u16) -> [u8; 2] {
        value.to_le_bytes()
    }

    fn le32(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    fn be16(value: u16) -> [u8; 2] {
        value.to_be_bytes()
    }

    fn be32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    fn align4(value: usize) -> usize {
        value.div_ceil(4) * 4
    }

    fn attr(size: u16, ino: u32, mode: u32) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&le16(size));
        value.extend_from_slice(&le16(0)); // extattr_offset
        value.extend_from_slice(&le32(ino));
        value.extend_from_slice(&le32(mode));
        value.extend_from_slice(&le32(0)); // gid
        value.extend_from_slice(&le32(0)); // uid
        value.extend_from_slice(&le32(1)); // mtime
        value
    }

    fn dirent(path: &str, extra: &[u8], ino: u32, mode: u32) -> Vec<u8> {
        let size = align4(24 + extra.len() + path.len() + 1);
        let mut value = attr(size as u16, ino, mode);
        value.extend_from_slice(extra);
        value.extend_from_slice(path.as_bytes());
        value.push(0);
        value.resize(size, 0);
        value
    }

    fn build_filesystem() -> Vec<u8> {
        build_filesystem_with_file_path("bin/sh")
    }

    fn build_filesystem_with_file_path(file_path: &str) -> Vec<u8> {
        let header_len = align4(QNX_IMAGE_HEADER_SIZE + 1 + MOUNTPOINT.len());
        let root = dirent("", &[], 1, 0o040755);
        let dir = dirent("bin", &[], 2, 0o040755);
        let file_size = align4(24 + 8 + file_path.len() + 1);

        let dir_area = root.len() + dir.len() + file_size + 4;
        let data_offset = header_len + dir_area;
        let image_size = align4(data_offset + FILE_DATA.len()) + 4;

        let file = dirent(
            file_path,
            &[
                le32(data_offset as u32).as_slice(),
                le32(FILE_DATA.len() as u32).as_slice(),
            ]
            .concat(),
            3,
            0o100755,
        );
        assert_eq!(file.len(), file_size);

        let mut filesystem = Vec::new();
        filesystem.extend_from_slice(qnx_ifs::image::IMAGE_SIGNATURE);
        filesystem.push(0); // little endian
        filesystem.extend_from_slice(&le32(image_size as u32));
        filesystem.extend_from_slice(&le32(
            (header_len + root.len() + dir.len() + file.len() + 4) as u32,
        ));
        filesystem.extend_from_slice(&le32(header_len as u32));
        filesystem.extend_from_slice(&[0u8; 4 * 4]); // boot_ino
        filesystem.extend_from_slice(&le32(0)); // script_ino
        filesystem.extend_from_slice(&le32(0)); // chain_paddr
        filesystem.extend_from_slice(&[0u8; 10 * 4]); // spare
        filesystem.extend_from_slice(&le32(0)); // mountflags
        filesystem.extend_from_slice(MOUNTPOINT.as_bytes());
        filesystem.push(0);
        filesystem.resize(header_len, 0);

        filesystem.extend_from_slice(&root);
        filesystem.extend_from_slice(&dir);
        filesystem.extend_from_slice(&file);
        filesystem.extend_from_slice(&[0u8; 4]); // dirent terminator
        filesystem.extend_from_slice(FILE_DATA);
        filesystem.resize(image_size - 4, 0);
        filesystem.extend_from_slice(&[0u8; 4]); // image trailer
        filesystem
    }

    #[test]
    fn parser_accepts_bare_imagefs() {
        let filesystem = build_filesystem();
        let result = qnx_ifs_parser(&filesystem, 0).expect("valid imagefs");

        assert_eq!(result.size, filesystem.len());
        assert!(result.description.contains("mountpoint: /fs"));
    }

    #[test]
    fn parser_rejects_bad_imagefs() {
        let mut filesystem = build_filesystem();
        filesystem[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(qnx_ifs_parser(&filesystem, 0).is_err());
    }

    #[test]
    fn parser_accepts_big_endian_startup_header() {
        let mut startup = Vec::new();
        startup.extend_from_slice(b"\x00\xFF\x7E\xEB");
        startup.extend_from_slice(&be16(1)); // version
        startup.push(0x02); // big endian, no compression
        startup.push(0); // flags2
        startup.extend_from_slice(&be16(256)); // header_size
        startup.extend_from_slice(&be16(1)); // machine
        startup.extend_from_slice(&[0u8; 5 * 4]); // vaddrs and ram_size
        startup.extend_from_slice(&be32(260)); // startup_size
        startup.extend_from_slice(&be32(260)); // stored_size
        startup.extend_from_slice(&be32(0)); // imagefs_paddr
        startup.extend_from_slice(&be32(0)); // imagefs_size
        startup.extend_from_slice(&be16(0)); // preboot_size
        startup.extend_from_slice(&[0u8; 14]); // zero fields
        assert_eq!(startup.len(), 64);
        startup.resize(260, 0);

        let result = qnx_ifs_parser(&startup, 0).expect("valid big-endian startup header");
        assert_eq!(result.size, startup.len());
        assert!(result.description.contains("big-endian"));
        assert!(result.description.contains("compression: none"));

        let header = parse_ifs_header(&startup).expect("valid big-endian startup header");
        assert_eq!(header.total_size, startup.len());
    }

    #[test]
    fn extractor_writes_image_contents() {
        let filesystem = build_filesystem();
        let output = tempfile::tempdir().unwrap();
        let result = extract_qnx_ifs(&filesystem, 0, Some(output.path()));

        assert!(result.success);
        assert_eq!(result.size, Some(filesystem.len()));
        assert_eq!(
            std::fs::read(output.path().join("bin/sh")).unwrap(),
            FILE_DATA
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(output.path().join("bin/sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }

    #[test]
    fn extraction_keeps_paths_inside_the_output_directory() {
        let filesystem = build_filesystem_with_file_path("../escaped");

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let outside = temp_dir.path().join("escaped");

        let result = extract_qnx_ifs(&filesystem, 0, Some(&output));
        assert!(result.success);
        assert!(!outside.exists());
        assert_eq!(std::fs::read(output.join("escaped")).unwrap(), FILE_DATA);
    }

    /// A file entry colliding with the "bin" directory path fails to extract,
    /// failing the image extraction. A mode without any permission bits on the
    /// image's root directory entry must then not be restored onto the output
    /// directory itself, or the framework's cleanup of a failed extraction
    /// (which removes the directory) could no longer traverse it.
    #[test]
    fn failed_extraction_leaves_the_output_directory_writable() {
        let header_len = align4(QNX_IMAGE_HEADER_SIZE + 1 + MOUNTPOINT.len());
        let root = dirent("", &[], 1, 0o040000); // directory, but no permission bits
        let bin_dir = dirent("bin", &[], 2, 0o040755);
        let bin_file = dirent("bin", &[le32(0), le32(0)].concat(), 3, 0o100644);
        let sh_len = align4(24 + 8 + "bin/sh".len() + 1);
        let dir_area = root.len() + bin_dir.len() + bin_file.len() + sh_len + 4;
        let data_offset = header_len + dir_area;
        let sh_file = dirent(
            "bin/sh",
            &[
                le32(data_offset as u32).as_slice(),
                le32(FILE_DATA.len() as u32).as_slice(),
            ]
            .concat(),
            4,
            0o100755,
        );
        assert_eq!(sh_file.len(), sh_len);
        let image_size = align4(data_offset + FILE_DATA.len()) + 4;

        let mut filesystem = Vec::new();
        filesystem.extend_from_slice(qnx_ifs::image::IMAGE_SIGNATURE);
        filesystem.push(0); // little endian
        filesystem.extend_from_slice(&le32(image_size as u32));
        filesystem.extend_from_slice(&le32((header_len + dir_area) as u32));
        filesystem.extend_from_slice(&le32(header_len as u32));
        filesystem.extend_from_slice(&[0u8; 4 * 4]); // boot_ino
        filesystem.extend_from_slice(&le32(0)); // script_ino
        filesystem.extend_from_slice(&le32(0)); // chain_paddr
        filesystem.extend_from_slice(&[0u8; 10 * 4]); // spare
        filesystem.extend_from_slice(&le32(0)); // mountflags
        filesystem.extend_from_slice(MOUNTPOINT.as_bytes());
        filesystem.push(0);
        filesystem.resize(header_len, 0);

        filesystem.extend_from_slice(&root);
        filesystem.extend_from_slice(&bin_dir);
        filesystem.extend_from_slice(&bin_file);
        filesystem.extend_from_slice(&sh_file);
        filesystem.extend_from_slice(&[0u8; 4]); // dirent terminator
        filesystem.extend_from_slice(FILE_DATA);
        filesystem.resize(image_size - 4, 0);
        filesystem.extend_from_slice(&[0u8; 4]); // image trailer

        let output = tempfile::tempdir().unwrap();
        let result = extract_qnx_ifs(&filesystem, 0, Some(output.path()));

        assert!(!result.success);
        // Cleanup and recursive extraction need a usable output directory.
        let probe = output.path().join("cleanup_probe");
        assert!(std::fs::write(&probe, b"probe").is_ok());
        assert!(std::fs::remove_file(&probe).is_ok());
    }
}
