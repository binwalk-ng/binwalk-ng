use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use aho_corasick::AhoCorasick;
use log::error;
use std::io::{self, Write};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "RAR archive";

/// RAR magic bytes for both v4 and v5
pub fn rar_magic() -> Vec<Vec<u8>> {
    vec![b"Rar!\x1A\x07".to_vec()]
}

/// Validate RAR signature
pub fn rar_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        ..Default::default()
    };

    let mut extra_description: String = "".to_string();

    // Parse the archive header
    if let Ok(rar_header) = parse_rar_archive_header(&file_data[offset..]) {
        // Try to locate the RAR end-of-file marker
        if let Ok(rar_size) = get_rar_size(&file_data[offset..], rar_header.version) {
            result.size = rar_size;
            result.confidence = CONFIDENCE_MEDIUM;
        } else {
            extra_description = " (failed to locate RAR EOF)".to_string();
        }

        result.description = format!(
            "{}, version: {}, total size: {} bytes{}",
            result.description, rar_header.version, result.size, extra_description
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Determine the size of the RAR file
fn get_rar_size(file_data: &[u8], rar_version: usize) -> Result<usize, SignatureError> {
    // EOF markers for Rar v4 and v5
    let eof_marker = match rar_version {
        4 => vec![b"\xC4\x3D\x7B\x00\x40\x07\x00".to_vec()],
        5 => vec![b"\x1d\x77\x56\x51\x03\x05\x04\x00".to_vec()],
        _ => return Err(SignatureError),
    };

    // Need to grep the file for the EOF marker
    let grep = AhoCorasick::new(eof_marker.clone()).unwrap();

    // Search the file data for the EOF marker
    if let Some(eof_match) = grep.find_overlapping_iter(file_data).next() {
        // Accept the first match; total size is the start of the EOF marker plus the size of the EOF marker
        return Ok(eof_match.start() + eof_marker[0].len());
    }

    Err(SignatureError)
}

/// Stores info on a RAR archive
#[derive(Debug, Default, Clone)]
pub struct RarArchiveHeader {
    pub version: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RarHeaderBytes {
    magic: [u8; 6],
    version: u8,
}

/// Parse a RAR archive header
pub fn parse_rar_archive_header(rar_data: &[u8]) -> Result<RarArchiveHeader, StructureError> {
    let (archive_header, _) =
        RarHeaderBytes::ref_from_prefix(rar_data).map_err(|_| StructureError)?;

    // Make sure the version number is one of the known versions, version field of 0 indicates RARv4; version field of 1 indicates RARv5
    let version = match archive_header.version {
        0 => 4,
        1 => 5,
        _ => return Err(StructureError),
    };

    Ok(RarArchiveHeader { version })
}

pub fn rar_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_rar),
        ..Default::default()
    }
}

pub fn extract_rar(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let slice = &file_data[offset..];

    let archive = match rars::ArchiveReader::read(slice) {
        Ok(arch) => arch,
        Err(e) => {
            eprintln!("Failed to parse RAR archive: {}", e);
            return result;
        }
    };

    result.size = Some(slice.len());
    result.success = true;

    let Some(chroot) = output_directory.map(Chroot::new) else {
        return result;
    };

    let extraction_result = archive.extract_to(None, |meta| {
        let name = meta.name_lossy();

        if meta.is_directory {
            if !chroot.create_directory(&name) {
                result.success = false;
            }
            return Ok(Box::new(io::sink()) as Box<dyn Write>);
        }

        // Create writer for regular file
        match chroot.create_file_writer(&name) {
            Some(file) => Ok(Box::new(file) as Box<dyn Write>),
            None => {
                result.success = false;
                error!("Failed to create writer for '{}'", name);
                // Continue extraction (discard this file's data)
                Ok(Box::new(io::sink()) as Box<dyn Write>)
            }
        }
    });

    if let Err(e) = extraction_result {
        error!("RAR extraction error: {}", e);
        result.success = false;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::{extract_rar, rar_extractor};
    use crate::extractors::ExtractorType;

    /// RAR5 fixture: an 89-byte archive containing one directory ("testdir")
    /// and one file ("testdir/hello.txt" with content "Hello, RAR!\n").
    /// Generated by tests/inputs/gen_rar.sh.
    const RAR5_FIXTURE: &[u8] = include_bytes!("../../tests/inputs/rar.bin");

    /// Minimal valid RAR5 empty archive (no files, only archive header + EOF).
    /// Generated by tests/inputs/gen_rar.sh (magic + archive_header + end_of_archive).
    const RAR5_EMPTY: &[u8] = &[
        0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, // magic
        0xc5, 0x1a, 0x33, 0x32, 0x03, 0x01, 0x00, 0x00, // archive header block
        0x19, 0xb2, 0x3a, 0x35, 0x03, 0x05, 0x00, 0x00, // end-of-archive block
    ];

    // ── rar_extractor() ──────────────────────────────────────────────────────

    /// rar_extractor() must return an Internal extractor (not External or None)
    /// now that the native `rars` crate replaced the external `unrar` command.
    #[test]
    fn rar_extractor_is_internal() {
        match rar_extractor().utility {
            ExtractorType::Internal(_) => {}
            ExtractorType::External(cmd) => {
                panic!("expected Internal extractor, got External({cmd:?})");
            }
            ExtractorType::None => {
                panic!("expected Internal extractor, got None");
            }
        }
    }

    /// The extractor should not require a specific file extension (extension
    /// field should be the default empty string) because internal extractors
    /// do not carve a file to disk before running.
    #[test]
    fn rar_extractor_has_empty_extension() {
        assert_eq!(rar_extractor().extension, "");
    }

    // ── extract_rar: failure paths ───────────────────────────────────────────

    /// Completely empty input must not succeed: result should have
    /// success=false and size=None.
    #[test]
    fn extract_rar_fails_on_empty_data() {
        let result = extract_rar(&[], 0, None);
        assert!(!result.success, "empty data should not succeed");
        assert!(result.size.is_none(), "size should be None on failure");
    }

    /// Random garbage bytes must not be parsed as a valid RAR archive.
    #[test]
    fn extract_rar_fails_on_garbage_data() {
        let garbage = vec![0xAB; 256];
        let result = extract_rar(&garbage, 0, None);
        assert!(!result.success);
        assert!(result.size.is_none());
    }

    /// Only the RAR magic bytes (no archive blocks) must also fail.
    #[test]
    fn extract_rar_fails_on_magic_only() {
        let magic_only = b"Rar!\x1a\x07\x01\x00";
        let result = extract_rar(magic_only, 0, None);
        assert!(!result.success);
        assert!(result.size.is_none());
    }

    /// A truncated archive (valid magic, partial header) must fail gracefully.
    #[test]
    fn extract_rar_fails_on_truncated_archive() {
        let truncated = &RAR5_FIXTURE[..16]; // magic + partial archive header
        let result = extract_rar(truncated, 0, None);
        assert!(!result.success);
        assert!(result.size.is_none());
    }

    /// A non-zero offset that moves past the end of the data must not succeed.
    #[test]
    fn extract_rar_fails_when_offset_exceeds_data() {
        let data = b"some data";
        let result = extract_rar(data, data.len(), None);
        // slice &file_data[offset..] is empty, so parsing must fail
        assert!(!result.success);
    }

    // ── extract_rar: dry run (no output directory) ───────────────────────────

    /// A valid archive with no output directory must parse successfully and
    /// return success=true without touching the filesystem.
    #[test]
    fn extract_rar_dry_run_with_valid_archive() {
        let result = extract_rar(RAR5_FIXTURE, 0, None);
        assert!(
            result.success,
            "valid archive must succeed in dry-run mode"
        );
        assert_eq!(
            result.size,
            Some(RAR5_FIXTURE.len()),
            "size should be the slice length"
        );
    }

    /// Dry run on the empty archive (no files) must also succeed.
    #[test]
    fn extract_rar_dry_run_with_empty_archive() {
        let result = extract_rar(RAR5_EMPTY, 0, None);
        assert!(
            result.success,
            "empty archive must succeed in dry-run mode"
        );
        assert_eq!(result.size, Some(RAR5_EMPTY.len()));
    }

    // ── extract_rar: nonzero offset ──────────────────────────────────────────

    /// When the archive starts at a nonzero offset in the buffer, extract_rar
    /// must use &file_data[offset..] as the input slice.
    #[test]
    fn extract_rar_dry_run_with_nonzero_offset() {
        // Prefix 16 zero bytes before the archive.
        let prefix_len = 16;
        let mut data_with_prefix = vec![0u8; prefix_len];
        data_with_prefix.extend_from_slice(RAR5_FIXTURE);

        let result = extract_rar(&data_with_prefix, prefix_len, None);
        assert!(
            result.success,
            "must parse archive correctly at nonzero offset"
        );
        // size is len(slice) = len(data_with_prefix) - prefix_len
        assert_eq!(result.size, Some(RAR5_FIXTURE.len()));
    }

    // ── extract_rar: extraction to output directory ──────────────────────────

    /// A valid archive with an output directory must extract its contents to
    /// disk, with result.success=true.
    #[test]
    fn extract_rar_extracts_files_to_output_directory() {
        let outdir = tempfile::tempdir().unwrap();
        let result = extract_rar(RAR5_FIXTURE, 0, Some(outdir.path()));
        assert!(
            result.success,
            "extraction to output directory must succeed"
        );

        // The file "testdir/hello.txt" must exist and contain the expected bytes.
        let extracted_file = outdir.path().join("testdir").join("hello.txt");
        assert!(
            extracted_file.exists(),
            "expected extracted file not found: {extracted_file:?}"
        );
        let contents = std::fs::read(&extracted_file).unwrap();
        assert_eq!(
            contents, b"Hello, RAR!\n",
            "extracted file contents mismatch"
        );
    }

    /// An empty archive (no files) extracted to a directory should still
    /// report success because the archive was valid even though no files
    /// were emitted.
    #[test]
    fn extract_rar_empty_archive_with_output_dir_succeeds() {
        let outdir = tempfile::tempdir().unwrap();
        let result = extract_rar(RAR5_EMPTY, 0, Some(outdir.path()));
        assert!(
            result.success,
            "empty archive extraction must succeed (no files to extract)"
        );
    }
}
