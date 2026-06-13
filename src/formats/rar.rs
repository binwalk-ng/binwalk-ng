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

    let Some(slice) = file_data.get(offset..) else {
        error!("RAR extractor received invalid offset {offset}");
        return result;
    };

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
