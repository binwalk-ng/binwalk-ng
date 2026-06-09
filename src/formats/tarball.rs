use crate::common::is_offset_safe;
use crate::extractors;
use crate::extractors::{Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, EntryType};

/// Some tarball constants
const TARBALL_BLOCK_SIZE: usize = 512;
const TARBALL_MAGIC_OFFSET: usize = 257;
const TARBALL_MAGIC_SIZE: usize = 5;
const TARBALL_SIZE_OFFSET: usize = 124;
const TARBALL_SIZE_LEN: usize = 11;
const TARBALL_UNIVERSAL_MAGIC: &[u8; 5] = b"ustar";
const TARBALL_MIN_EXPECTED_HEADERS: usize = 10;

/// Human readable description
pub const DESCRIPTION: &str = "POSIX tar archive";

/// Magic bytes for tarball and GNU tarball file types
pub fn tarball_magic() -> Vec<Vec<u8>> {
    vec![b"ustar\x00".to_vec(), b"ustar\x20\x20\x00".to_vec()]
}

/// Validate tarball signatures
pub fn tarball_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Stores the running total size of the tarball
    let mut tarball_total_size: usize = 0;

    // Keep a count of how many tar entry headers were validated
    let mut valid_header_count: usize = 0;

    // Calculate the actual start of the tarball (header magic does not start at the beginning of a tar entry)
    let tarball_start_offset = offset - TARBALL_MAGIC_OFFSET;

    // Tarball magic bytes do not start at the beginning of the tarball file
    let mut next_header_start = tarball_start_offset;
    let mut previous_header_start = None;
    let available_data = file_data.len();

    // Loop through available data, processing tarball entry headers
    while is_offset_safe(available_data, next_header_start, previous_header_start) {
        // Calculate the end of the next tarball entry data
        let next_header_end = next_header_start + TARBALL_BLOCK_SIZE;

        // Get the next header's data; this will fail if not enough data is present, protecting
        // other functions (header_checksum_is_valid, tarball_entry_size) from out-of-bounds access
        match file_data.get(next_header_start..next_header_end) {
            None => {
                break;
            }
            Some(tarball_header_block) => {
                // Bad checksum? Quit processing headers.
                if !header_checksum_is_valid(tarball_header_block) {
                    break;
                }

                // Increment the count of valid tarball headers found
                valid_header_count += 1;

                // Get the reported size of the next entry header
                match tarball_entry_size(tarball_header_block) {
                    Err(_) => {
                        break;
                    }
                    Ok(entry_size) => {
                        // Update total size count, and next/previous header offsets
                        tarball_total_size += entry_size;
                        previous_header_start = Some(next_header_start);
                        next_header_start += entry_size;
                    }
                }
            }
        }
    }

    // We expect that a tarball should be, at a minimum, one block in size
    if tarball_total_size >= TARBALL_BLOCK_SIZE {
        // Default confidence is medium, if more than just a few tarball headers were found and
        // processed successfully, we have pretty high confidence that this isn't a false positive
        let confidence = if valid_header_count >= TARBALL_MIN_EXPECTED_HEADERS {
            CONFIDENCE_HIGH
        } else {
            CONFIDENCE_MEDIUM
        };

        return Ok(SignatureResult {
            description: format!("{DESCRIPTION}, file count: {valid_header_count}"),
            offset: tarball_start_offset,
            size: tarball_total_size,
            confidence,
            ..Default::default()
        });
    }

    Err(SignatureError)
}

/// Validate a tarball entry checksum
fn header_checksum_is_valid(header_block: &[u8]) -> bool {
    const TARBALL_CHECKSUM_START: usize = 148;
    const TARBALL_CHECKSUM_END: usize = 156;

    let checksum_value_string: &[u8] = &header_block[TARBALL_CHECKSUM_START..TARBALL_CHECKSUM_END];
    let reported_checksum = tarball_octal(checksum_value_string);
    let mut sum: usize = 0;

    for (i, header_byte) in header_block.iter().enumerate() {
        if (TARBALL_CHECKSUM_START..TARBALL_CHECKSUM_END).contains(&i) {
            sum += 0x20;
        } else {
            sum += *header_byte as usize;
        }
    }

    sum == reported_checksum
}

/// Returns the size of a tarball entry, including header and data
fn tarball_entry_size(tarball_entry_data: &[u8]) -> Result<usize, SignatureError> {
    // Get the tarball entry's magic bytes
    let entry_magic: &[u8] =
        &tarball_entry_data[TARBALL_MAGIC_OFFSET..TARBALL_MAGIC_OFFSET + TARBALL_MAGIC_SIZE];

    // Make sure the magic bytes are valid
    if entry_magic == TARBALL_UNIVERSAL_MAGIC {
        // Pull this tarball entry's data size, stored as ASCII octal, out of the header
        let entry_size_string: &[u8] =
            &tarball_entry_data[TARBALL_SIZE_OFFSET..TARBALL_SIZE_OFFSET + TARBALL_SIZE_LEN];

        // Convert the ASCII octal to a number
        let reported_entry_size = tarball_octal(entry_size_string);

        // The actual size of this entry will be the data size, rounded up to the nearest block size, PLUS one block for the entry header
        let block_count: usize =
            1 + (reported_entry_size as f32 / TARBALL_BLOCK_SIZE as f32).ceil() as usize;

        // Total size is the total number of blocks times the block size
        return Ok(block_count * TARBALL_BLOCK_SIZE);
    }

    Err(SignatureError)
}

/// Convert octal string to a number
fn tarball_octal(octal_string: &[u8]) -> usize {
    let mut num: usize = 0;

    for octal_char in octal_string {
        // ASCII octal values should be ASCII
        if *octal_char < 0x30 || *octal_char > 0x39 {
            break;
        } else {
            num *= 8;
            num = num + (*octal_char as usize) - 0x30;
        }
    }

    num
}

/// Defines the internal extractor for tarball archives.
///
/// Archive entries are unpacked into the output directory through the chroot-safe
/// `Chroot` API, so entry paths (including absolute paths and `..` traversal) cannot
/// escape the extraction directory.
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::tarball::tarball_extractor;
///
/// match tarball_extractor().utility {
///     ExtractorType::Internal(_) => {}
///     _ => panic!("tarball extractor should be internal"),
/// }
/// ```
pub fn tarball_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_tarball),
        ..Default::default()
    }
}

/// Internal extractor: unpacks a POSIX/GNU tar archive using the `tar` crate.
///
/// When `output_directory` is `None`, this performs a dry run (the archive is parsed
/// and validated, but nothing is written to disk).
fn extract_tarball(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(tarball_data) = file_data.get(offset..) else {
        return result;
    };

    let mut archive = Archive::new(tarball_data);
    let Ok(entries) = archive.entries() else {
        return result;
    };

    // None => dry run (validate only); Some => extract into this chroot.
    let chroot = output_directory.map(Chroot::new);
    let mut extracted_something = false;
    let mut consumed: usize = 0;

    // Directory attributes are applied only after every entry is extracted: restoring a
    // restrictive directory mode (e.g. read-only) up front could otherwise block writes
    // of the files that live inside it. This mirrors how `tar` defers directory perms.
    let mut deferred_dir_metadata: Vec<(PathBuf, EntryMetadata)> = Vec::new();

    for entry in entries {
        // Stop at the first malformed/truncated entry, keeping anything already
        // extracted (signature matching is imperfect, so trailing data may be junk).
        let Ok(mut entry) = entry else {
            break;
        };

        let entry_type = entry.header().entry_type();
        let entry_size = entry.size() as usize;
        // End of this entry's data within the archive, rounded up to the tar block
        // size (every entry is padded to a 512-byte boundary). The size field is
        // attacker-controlled, so use saturating arithmetic and clamp to the input
        // length to avoid an integer-overflow panic.
        consumed = (entry.raw_file_position() as usize)
            .saturating_add(entry_size)
            .min(tarball_data.len())
            .next_multiple_of(TARBALL_BLOCK_SIZE);

        // Preserve the entry's mode (permission + setuid/setgid/sticky bits) and
        // ownership. Read these before any mutable borrow of the entry.
        let metadata = EntryMetadata::from_entry(&entry);

        // Resolve the entry's (owned) path; skip entries with an unrepresentable path.
        let Ok(path) = entry.path().map(|p| p.into_owned()) else {
            continue;
        };

        // Dry run: validate only, don't touch the filesystem.
        let Some(chroot) = &chroot else {
            extracted_something = true;
            continue;
        };

        let entry_extracted = match entry_type {
            EntryType::Directory => {
                let created = chroot.create_directory(&path);
                if created {
                    deferred_dir_metadata.push((path, metadata));
                }
                created
            }

            // Represent both symlinks and hardlinks as symlinks; the Chroot API has
            // no hardlink primitive, and a symlink preserves the reference.
            EntryType::Symlink | EntryType::Link => match entry.link_name() {
                Ok(Some(link)) => {
                    let created = chroot.create_symlink(&path, &link);
                    if created {
                        // Only ownership applies to a symlink (its mode is ignored).
                        metadata.apply_ownership(chroot, &path);
                    }
                    created
                }
                _ => false,
            },

            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                // Don't pre-allocate from the header's (untrusted) size field; let the
                // buffer grow from the bytes actually read to avoid an allocation bomb.
                let mut data = Vec::new();
                if entry.read_to_end(&mut data).is_err() {
                    false
                } else {
                    // Chroot::create_file does not create parent directories.
                    if let Some(parent) = path.parent() {
                        chroot.create_directory(parent);
                    }
                    let created = chroot.create_file(&path, &data);
                    if created {
                        metadata.apply(chroot, &path);
                    }
                    created
                }
            }

            // Character/block devices, fifos, sockets, and metadata-only entries:
            // nothing to carve, but their presence must not fail the extraction.
            _ => true,
        };

        extracted_something |= entry_extracted;
    }

    // Now that every file is in place, restore directory ownership and modes.
    if let Some(chroot) = &chroot {
        for (path, metadata) in &deferred_dir_metadata {
            metadata.apply(chroot, path);
        }
    }

    if extracted_something {
        result.success = true;
        result.size = Some(consumed);
    }

    result
}

/// Unix ownership and mode pulled from a tar entry header, used to restore an extracted
/// path's attributes (execute/setuid/setgid/sticky bits and uid/gid).
#[derive(Clone, Copy, Default)]
struct EntryMetadata {
    mode: Option<u32>,
    owner: Option<(u32, u32)>,
}

impl EntryMetadata {
    fn from_entry<R: Read>(entry: &tar::Entry<'_, R>) -> Self {
        let header = entry.header();
        let owner = header
            .uid()
            .ok()
            .zip(header.gid().ok())
            .map(|(uid, gid)| (uid as u32, gid as u32));
        Self {
            mode: header.mode().ok(),
            owner,
        }
    }

    /// Restore ownership (best effort; needs privileges) without following the final
    /// symlink, so it is safe to call on symlink entries.
    fn apply_ownership(&self, chroot: &Chroot, path: &Path) {
        if let Some((uid, gid)) = self.owner {
            chroot.set_ownership(path, uid, gid);
        }
    }

    /// Restore ownership and then mode. Ownership is set first because changing it can
    /// clear the setuid/setgid bits on some systems.
    fn apply(&self, chroot: &Chroot, path: &Path) {
        self.apply_ownership(chroot, path);
        if let Some(mode) = self.mode {
            chroot.set_mode(path, mode);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM};

    /// The shared test fixture: a deterministic POSIX (ustar) tar archive containing
    /// three files (see tests/inputs/gen_tarball.sh). The `ustar` magic for the first
    /// entry lives at TARBALL_MAGIC_OFFSET (257), i.e. the archive starts at offset 0.
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/inputs/tarball.bin"
    ));

    #[test]
    fn octal_parses_basic_values() {
        assert_eq!(tarball_octal(b"33"), 27);
        assert_eq!(tarball_octal(b"00000000644"), 0o644);
        assert_eq!(tarball_octal(b""), 0);
    }

    #[test]
    fn octal_stops_at_non_octal_terminator() {
        // tar size/checksum fields are space- or NUL-terminated; parsing must stop there.
        assert_eq!(tarball_octal(b"17 "), 0o17);
        assert_eq!(tarball_octal(b"17\x00rest"), 0o17);
        // A leading terminator yields zero.
        assert_eq!(tarball_octal(b"\x0033"), 0);
    }

    #[test]
    fn checksum_validates_real_header() {
        let header = &FIXTURE[0..TARBALL_BLOCK_SIZE];
        assert!(header_checksum_is_valid(header));
    }

    #[test]
    fn checksum_rejects_corrupted_header() {
        let mut header = FIXTURE[0..TARBALL_BLOCK_SIZE].to_vec();
        // Flip a byte in the file name field (outside the checksum field), which must
        // invalidate the stored checksum.
        header[0] ^= 0xFF;
        assert!(!header_checksum_is_valid(&header));
    }

    #[test]
    fn entry_size_rounds_up_to_block_size() {
        // First entry holds a 27-byte file: one header block + one (partial) data block.
        let header = &FIXTURE[0..TARBALL_BLOCK_SIZE];
        assert_eq!(tarball_entry_size(header).unwrap(), 2 * TARBALL_BLOCK_SIZE);
    }

    #[test]
    fn entry_size_rejects_bad_magic() {
        let zeros = [0u8; TARBALL_BLOCK_SIZE];
        assert!(tarball_entry_size(&zeros).is_err());
    }

    #[test]
    fn parser_detects_fixture_archive() {
        let result = tarball_parser(FIXTURE, TARBALL_MAGIC_OFFSET).unwrap();

        // Archive starts at the very beginning of the file.
        assert_eq!(result.offset, 0);
        // Reported size covers all six entries' header + data blocks (not the trailing
        // end-of-archive zero padding): four files (1024 each) plus a directory and a
        // symlink (one 512-byte header block each).
        assert_eq!(result.size, 10 * TARBALL_BLOCK_SIZE);
        // Six valid headers found; below TARBALL_MIN_EXPECTED_HEADERS, so medium.
        assert_eq!(result.confidence, CONFIDENCE_MEDIUM);
        assert!(result.confidence < CONFIDENCE_HIGH);
        assert!(result.description.contains("file count: 6"));
    }

    #[test]
    fn parser_rejects_non_tarball_data() {
        // A region with no valid tar header (all zeros) must not be reported as a tarball.
        let zeros = [0u8; 2 * TARBALL_BLOCK_SIZE];
        assert!(tarball_parser(&zeros, TARBALL_MAGIC_OFFSET).is_err());
    }
}
