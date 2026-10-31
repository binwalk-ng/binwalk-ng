use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::Endianness;
use log::{debug, error, warn};
use qnx_ifs::{Compress, Endian, Entry, EntryKind, Image};
use std::path::{Path, PathBuf};

/// Human readable description
pub const IFS_DESCRIPTION: &str = "QNX IFS image";

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

    // Bare image filesystems: a valid header alone cannot claim the extent,
    // because a header with broken dirents would fail extraction and mask a
    // real signature stored inside it. The data area is uncompressed, so
    // walk the dirent chain here and only report a fully parsed image.
    if available_data.starts_with(qnx_ifs::image::IMAGE_SIGNATURE) {
        let image =
            qnx_ifs::Image::parse_imagefs_at(available_data, 0).map_err(|_| SignatureError)?;
        let total_size = image.total_size();

        result.size = total_size;
        result.description = format!(
            "{}, {}, mountpoint: {}, total size: {} bytes",
            result.description,
            to_endianness(image.endian),
            image.image_header.mountpoint,
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
        "{}, {}, compression: {}, total size: {} bytes",
        result.description,
        to_endianness(startup.endian),
        compression_name(startup.compress),
        total_size
    );

    Ok(result)
}

const fn to_endianness(endian: Endian) -> Endianness {
    match endian {
        Endian::Little => Endianness::Little,
        Endian::Big => Endianness::Big,
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

    // The image begins at the match offset: dispatch on the header kind
    // to skip the crate's whole-buffer header re-scan.
    let image = if ifs_data.starts_with(qnx_ifs::image::IMAGE_SIGNATURE) {
        Image::parse_imagefs_at(ifs_data, 0)
    } else {
        Image::parse_at(ifs_data, 0)
    };
    let image = match image {
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

    // mkifs computes both trailers; report checksum mismatches.
    for (kind, checksums) in [
        ("filesystem", image.image_checksum()),
        ("startup", image.startup_checksum()),
    ] {
        if let Some(checksums) = checksums
            && !checksums.valid()
        {
            warn!(
                "QNX IFS image at offset {offset:#X} has a {kind} checksum mismatch (stored: {:#x}, computed: {:#x})",
                checksums.stored, checksums.computed
            );
        }
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

        let path = match path_from_bytes(&entry.raw_path) {
            Some(path) => path,
            None => {
                warn!(
                    "QNX IFS directory entry {}: path cannot be represented on this platform",
                    entry.path
                );
                success = false;
                continue;
            }
        };
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

        let path = match path_from_bytes(&entry.raw_path) {
            Some(path) => path,
            None => {
                warn!(
                    "QNX IFS entry {}: path cannot be represented on this platform",
                    entry.path
                );
                success = false;
                continue;
            }
        };
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

fn symlink_target(entry: &Entry) -> Option<PathBuf> {
    let EntryKind::Symlink {
        target, raw_target, ..
    } = &entry.kind
    else {
        return None;
    };
    path_from_bytes(raw_target).map_or_else(
        || {
            warn!("QNX IFS symlink target {target:?} cannot be represented on this platform");
            None
        },
        Some,
    )
}

/// Convert stored path bytes to a [`PathBuf`].
///
/// On Unix, paths are byte strings, so the stored bytes are kept
/// verbatim; valid UTF-8 yields an identical path on every platform.
/// On non-Unix platforms, non-UTF-8 bytes are not representable; `None`
/// lets callers skip the entry instead of extracting a renamed one.
fn path_from_bytes(raw: &[u8]) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(raw).ok().map(PathBuf::from)
    }
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
