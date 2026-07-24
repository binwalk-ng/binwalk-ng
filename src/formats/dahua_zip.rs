use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::formats::zip;
use crate::formats::zip::find_zip_eof;
use crate::signatures::{SignatureError, SignatureResult};
use std::path::Path;

/// Human readable description
pub const DESCRIPTION: &str = "Dahua ZIP archive";

// The first ZIP file entry in the Dahua ZIP file is has "DH" instead of "PK".
// Otherwise, it is a normal ZIP file.
pub(crate) const DAHUA_ZIP_LOCAL_FILE_MAGIC: [u8; 4] = *b"DH\x03\x04";

/// Dahua ZIP file entry magic bytes
pub fn dahua_zip_magic() -> Vec<Vec<u8>> {
    vec![DAHUA_ZIP_LOCAL_FILE_MAGIC.to_vec()]
}

/// Validates a Dahua ZIP file entry signature
pub fn dahua_zip_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Parse & validate the Dahua ZIP file like a normal ZIP file
    if let Ok(mut result) = zip::zip_parser(file_data, offset) {
        // Replace the normal ZIP description string with our description string
        result.description = result.description.replace(zip::DESCRIPTION, DESCRIPTION);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Defines the internal extractor function for carving Dahua ZIP files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::dahua_zip::dahua_zip_extractor;
///
/// match dahua_zip_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn dahua_zip_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_dahua_zip),
        ..Default::default()
    }
}

/// Carves out a Dahua ZIP file and converts it to a normal ZIP file
pub fn extract_dahua_zip(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "dahua.zip";
    const ZIP_HEADER: &[u8] = b"PK";

    let mut result = ExtractionResult::default();

    // Locate the end of the zip archive
    if let Ok(zip_info) = find_zip_eof(file_data, offset) {
        // Calculate total size of the zip archive, report success
        result.size = Some(zip_info.eof - offset);
        result.success = true;

        // If extraction was requested, carve the zip archive to disk, replacing the Dahua ZIP magic bytes
        // with the standard ZIP magic bytes.
        if let Some(output_directory) = output_directory {
            // Start and end offsets of the data to carve
            let start_data = offset + ZIP_HEADER.len();
            let end_data = offset + result.size.unwrap();

            let chroot = Chroot::new(output_directory);

            // Get the data to carve
            match file_data.get(start_data..end_data) {
                None => {
                    result.success = false;
                }
                Some(zip_data) => {
                    // First write the normal ZIP header magic bytes to disk
                    if !chroot.create_file(OUTFILE_NAME, ZIP_HEADER) {
                        result.success = false;
                    } else {
                        // Append the rest of the ZIP archive to disk
                        result.success = chroot.append_to_file(OUTFILE_NAME, zip_data);
                    }
                }
            }
        }
    }

    result
}
