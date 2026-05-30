use crate::common::is_offset_safe;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;

/// Human readable description
pub const DESCRIPTION: &str = "CPIO ASCII archive";

/// Magic bytes for CPIO archives with and without CRC's
pub fn cpio_magic() -> Vec<Vec<u8>> {
    vec![b"070701".to_vec(), b"070702".to_vec()]
}

/// Parse and validate CPIO archives
pub fn cpio_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The last CPIO entry will have this file name
    const EOF_MARKER: &str = "TRAILER!!!";

    let mut header_count: usize = 0;
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let mut next_header_offset = offset;
    let mut previous_header_offset = None;
    let available_data = file_data.len();

    // Loop over all the available data, or until CPIO EOF, or until error
    while is_offset_safe(available_data, next_header_offset, previous_header_offset) {
        // Get the CPIO entry's raw data
        match file_data.get(next_header_offset..) {
            None => {
                break;
            }
            Some(cpio_entry_data) => {
                // Parse this CPIO entry's header
                match parse_cpio_entry_header(cpio_entry_data) {
                    Err(_) => {
                        break;
                    }
                    Ok(cpio_header) => {
                        // Sanity check the magic bytes
                        if !cpio_magic().contains(&cpio_header.magic) {
                            break;
                        }

                        // Keep a tally of how many CPIO headers have been processed
                        header_count += 1;

                        // Update the total size of the CPIO file to include this header and its data
                        result.size += cpio_header.header_size + cpio_header.data_size;

                        // If EOF marker has been found, we're done
                        if cpio_header.file_name == EOF_MARKER {
                            // If one or fewer CPIO headers were found, consider it a false positive;
                            // a CPIO archive should have at least one file/directory entry, and one EOF entry.
                            if header_count > 1 {
                                // Return the result; reported file count does not include the EOF entry
                                result.description = format!(
                                    "{}, file count: {}",
                                    result.description,
                                    header_count - 1
                                );
                                return Ok(result);
                            }

                            break;
                        }

                        // Update the previous and next header offset values for the next loop iteration
                        previous_header_offset = Some(next_header_offset);
                        next_header_offset = offset + result.size;
                    }
                }
            }
        }
    }

    // No EOF marker was found, or an error occurred in processing the CPIO headers
    Err(SignatureError)
}

/// Expected minimum size of a CPIO entry header
pub const CPIO_HEADER_SIZE: usize = 110;

/// Storage struct for CPIO entry header info
#[derive(Debug, Clone, Default)]
pub struct CPIOEntryHeader {
    pub magic: Vec<u8>,
    pub data_size: usize,
    pub file_name: String,
    pub header_size: usize,
}

/// Parses a CPIO entry header
pub fn parse_cpio_entry_header(cpio_data: &[u8]) -> Result<CPIOEntryHeader, StructureError> {
    // Some expected constants
    const NULL_BYTE_SIZE: usize = 1;
    const CPIO_MAGIC_START: usize = 0;
    const CPIO_MAGIC_END: usize = 6;
    const FILE_SIZE_START: usize = 54;
    const FILE_SIZE_END: usize = 62;
    const FILE_NAME_SIZE_START: usize = 94;
    const FILE_NAME_SIZE_END: usize = 102;

    let available_data: usize = cpio_data.len();

    // TODO: If file mode parsing is added, internal extractor would be pretty easy to implement...
    if available_data > CPIO_HEADER_SIZE {
        // Grab the CPIO header magic bytes
        let header_magic = cpio_data[CPIO_MAGIC_START..CPIO_MAGIC_END].to_vec();

        // Get the ASCII hex string representing the file's data size
        if let Ok(file_data_size_str) =
            String::from_utf8(cpio_data[FILE_SIZE_START..FILE_SIZE_END].to_vec())
        {
            // Convert the file data size from ASCII hex to an integer
            if let Ok(file_data_size) = usize::from_str_radix(&file_data_size_str, 16) {
                // Get the ASCII hex string representing the file name's size
                if let Ok(file_name_size_str) =
                    String::from_utf8(cpio_data[FILE_NAME_SIZE_START..FILE_NAME_SIZE_END].to_vec())
                {
                    // Convert the file name size from ASCII hex to an integer
                    if let Ok(file_name_size) = usize::from_str_radix(&file_name_size_str, 16) {
                        // The file name immediately follows the fixed-length header data.
                        let file_name_start: usize = CPIO_HEADER_SIZE;
                        let file_name_end: usize =
                            file_name_start + file_name_size - NULL_BYTE_SIZE;

                        // Get the file name
                        if let Some(file_name_raw_bytes) =
                            cpio_data.get(file_name_start..file_name_end)
                            && let Ok(file_name) = String::from_utf8(file_name_raw_bytes.to_vec())
                        {
                            let header_total_size = CPIO_HEADER_SIZE + file_name_size;

                            return Ok(CPIOEntryHeader {
                                magic: header_magic,
                                file_name,
                                data_size: file_data_size + byte_padding(file_data_size),
                                header_size: header_total_size + byte_padding(header_total_size),
                            });
                        }
                    }
                }
            }
        }
    }

    Err(StructureError)
}

/// File data and CPIO headers are padded to 4-byte boundaries
const fn byte_padding(n: usize) -> usize {
    let modulus: usize = n % 4;
    if modulus == 0 { 0 } else { 4 - modulus }
}
