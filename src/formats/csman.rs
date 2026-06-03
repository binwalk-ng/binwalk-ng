use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use miniz_oxide::inflate;
use std::collections::HashMap;
use std::path::Path;

/// Human readable description
pub const DESCRIPTION: &str = "CSman DAT file";

/// CSMAN DAT files always start with these bytes
pub fn csman_magic() -> Vec<Vec<u8>> {
    // Big and little endian magic
    vec![b"SC".to_vec(), b"CS".to_vec()]
}

/// Validates the CSMAN DAT file
pub fn csman_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let dry_run = extract_csman_dat(file_data, offset, None);

    if dry_run.success
        && let Some(total_size) = dry_run.size
    {
        result.size = total_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Struct to store CSMAN header info
#[derive(Debug, Default, Clone)]
pub struct CSManHeader {
    pub compressed: bool,
    pub data_size: usize,
    pub endianness: String,
    pub header_size: usize,
}

/// Parses a CSMAN header
pub fn parse_csman_header(csman_data: &[u8]) -> Result<CSManHeader, StructureError> {
    const COMPRESSED_MAGIC: &[u8] = b"\x78";
    const LITTLE_ENDIAN_MAGIC: usize = 0x4353;

    let csman_header_structure = vec![
        ("magic", "u16"),
        ("unknown1", "u16"),
        ("compressed_size", "u32"),
        ("unknown2", "u32"),
        ("decompressed_size", "u32"),
    ];

    let mut result = CSManHeader::default();

    // Parse the header
    if let Ok(mut csman_header) =
        crate::structures::parse(csman_data, &csman_header_structure, "big")
    {
        // Detect the endianness
        if csman_header["magic"] == LITTLE_ENDIAN_MAGIC {
            // If this is a little endian header, re-parse the data as little endian
            if let Ok(csman_header_le) =
                crate::structures::parse(csman_data, &csman_header_structure, "little")
            {
                csman_header = csman_header_le;
                result.endianness = "little".to_string();
            }
        } else {
            result.endianness = "big".to_string();
        }

        // Should have been able to determine the endianness
        if !result.endianness.is_empty() {
            result.data_size = csman_header["compressed_size"];
            result.header_size = crate::structures::size(&csman_header_structure);
            result.compressed =
                csman_header["compressed_size"] != csman_header["decompressed_size"];

            // If compressed, check the expected compressed magic bytes
            if result.compressed
                && let Some(compressed_magic) =
                    csman_data.get(result.header_size..result.header_size + COMPRESSED_MAGIC.len())
                && compressed_magic != COMPRESSED_MAGIC
            {
                return Err(StructureError);
            }

            return Ok(result);
        }
    }

    Err(StructureError)
}

/// Stores info about a single CSMan DAT file entry
#[derive(Debug, Default, Clone)]
pub struct CSManEntry {
    pub size: usize,
    pub eof: bool,
    pub key: usize,
    pub value: Vec<u8>,
}

/// Parses a single CSMan DAT file entry
pub fn parse_csman_entry(
    entry_data: &[u8],
    endianness: &str,
) -> Result<CSManEntry, StructureError> {
    const EOF_TAG: usize = 0;

    // The last entry is just a single 4-byte NULL value
    let csman_last_entry_structure = vec![("eof", "u32")];

    // Entries consist of a 4-byte identifier, a 2-byte size, and a value
    let csman_entry_structure = vec![
        ("key", "u32"),
        ("size", "u16"),
        // value of size bytes immediately follows
    ];

    let mut entry = CSManEntry::default();

    if let Ok(entry_header) =
        crate::structures::parse(entry_data, &csman_entry_structure, endianness)
    {
        let value_start = crate::structures::size(&csman_entry_structure);
        let value_end = value_start + entry_header["size"];

        if let Some(entry_value) = entry_data.get(value_start..value_end) {
            entry.key = entry_header["key"];
            entry.value = entry_value.to_vec();
            entry.size = crate::structures::size(&csman_entry_structure) + entry_value.len();
            return Ok(entry);
        }
    } else if let Ok(entry_header) =
        crate::structures::parse(entry_data, &csman_last_entry_structure, endianness)
        && entry_header["eof"] == EOF_TAG
    {
        entry.eof = true;
        entry.size = crate::structures::size(&csman_last_entry_structure);
        return Ok(entry);
    }

    Err(StructureError)
}

/// Defines the internal extractor function for CSMan DAT files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::csman::csman_extractor;
///
/// match csman_extractor().utility {
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
pub fn csman_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_csman_dat),
        ..Default::default()
    }
}

/// Validate and extract CSMan DAT file entries
pub fn extract_csman_dat(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const COMPRESSED_HEADER_SIZE: usize = 2;

    // Return value
    let mut result = ExtractionResult::default();

    let mut csman_entries: Vec<CSManEntry> = Vec::new();

    // Parse the CSMAN header
    if let Ok(csman_header) = parse_csman_header(&file_data[offset..]) {
        // Calulate the start and end offsets of the CSMAN entries
        let entries_start: usize = offset + csman_header.header_size;
        let entries_end: usize = entries_start + csman_header.data_size;

        // Get the CSMAN entry data
        if let Some(raw_entry_data) = file_data.get(entries_start..entries_end) {
            let mut entry_data = raw_entry_data.to_vec();

            // If the entries are compressed, decompress it (zlib compression)
            if csman_header.compressed
                && let Some(compressed_data) = raw_entry_data.get(COMPRESSED_HEADER_SIZE..)
            {
                match inflate::decompress_to_vec(compressed_data) {
                    Err(_) => {
                        return result;
                    }
                    Ok(decompressed_data) => {
                        entry_data = decompressed_data;
                    }
                }
            }

            // Offsets for processing CSMAN entries in entry_data
            let mut next_offset: usize = 0;
            let mut previous_offset = None;
            let available_data: usize = entry_data.len();

            // Loop while there is still data that can be safely parsed
            while is_offset_safe(available_data, next_offset, previous_offset) {
                // Get the next entry's data
                match entry_data.get(next_offset..) {
                    None => {
                        break;
                    }
                    Some(next_entry_data) => {
                        // Parse the next entry
                        match parse_csman_entry(next_entry_data, &csman_header.endianness) {
                            Err(_) => {
                                break;
                            }
                            Ok(entry) => {
                                if entry.eof {
                                    // Last entry should be an EOF marker; an EOF marker should always exist.
                                    // There should be at least one valid entry.
                                    result.success = !csman_entries.is_empty();
                                    break;
                                } else {
                                    // Append this entry to the list of entries and update the offsets to process the next entry
                                    csman_entries.push(entry.clone());
                                    previous_offset = Some(next_offset);
                                    next_offset += entry.size;
                                }
                            }
                        }
                    }
                }
            }

            // If all entries were processed successfully
            if result.success {
                // Update the reported size of data processed
                result.size = Some(csman_header.header_size + csman_header.data_size);

                // If extraction was requested, extract each entry using the entry key as the file name
                if let Some(output_directory) = output_directory {
                    // All files will be written inside the provided output directory
                    let chroot = Chroot::new(output_directory);

                    // There may be more than one entry with the same key; track the key and how many times it was encountered
                    let mut processed_entries: HashMap<usize, usize> = HashMap::new();

                    // Loop through all entries
                    for entry in csman_entries {
                        // File name is [key value, in ASCII hex].dat
                        let mut file_name = format!("{:08X}.dat", entry.key);

                        // If this key value has already been extracted, file name is [key value, in ASCII hex].dat_[count]
                        if processed_entries.contains_key(&entry.key) {
                            file_name = format!("{}_{}", file_name, processed_entries[&entry.key]);
                            processed_entries.insert(entry.key, processed_entries[&entry.key] + 1);
                        } else {
                            processed_entries.insert(entry.key, 1);
                        }

                        if !chroot.create_file(&file_name, &entry.value) {
                            result.success = false;
                            break;
                        }
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSMAN_BIG_ENDIAN: &[u8] = &[
        // Header
        0x53, 0x43, // magic "SC" (big endian file)
        0x00, 0x00, // unknown1
        0x00, 0x00, 0x00, 0x0E, // compressed_size = 14
        0x00, 0x00, 0x00, 0x00, // unknown2
        0x00, 0x00, 0x00, 0x0E, // decompressed_size = 14 (uncompressed)
        // Entry: key=1, size=4, value=[0xDE, 0xAD, 0xBE, 0xEF]
        0x00, 0x00, 0x00, 0x01, // key
        0x00, 0x04, // size
        0xDE, 0xAD, 0xBE, 0xEF, // value
        // EOF marker
        0x00, 0x00, 0x00, 0x00,
    ];

    const CSMAN_LITTLE_ENDIAN: &[u8] = &[
        // Header
        0x43, 0x53, // magic "CS" (little endian file)
        0x00, 0x00, // unknown1
        0x0E, 0x00, 0x00, 0x00, // compressed_size = 14
        0x00, 0x00, 0x00, 0x00, // unknown2
        0x0E, 0x00, 0x00, 0x00, // decompressed_size = 14 (uncompressed)
        // Entry: key=1, size=4, value=[0xDE, 0xAD, 0xBE, 0xEF]
        0x01, 0x00, 0x00, 0x00, // key
        0x04, 0x00, // size
        0xDE, 0xAD, 0xBE, 0xEF, // value
        // EOF marker
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_csman_parser_big_endian() {
        let result = csman_parser(CSMAN_BIG_ENDIAN, 0);
        let sig = result.unwrap();
        assert_eq!(sig.offset, 0);
        assert_eq!(sig.size, CSMAN_BIG_ENDIAN.len());
        assert_eq!(sig.description, "CSman DAT file, total size: 30 bytes")
    }

    #[test]
    fn test_csman_parser_little_endian() {
        let result = csman_parser(CSMAN_LITTLE_ENDIAN, 0);
        let sig = result.unwrap();
        assert_eq!(sig.offset, 0);
        assert_eq!(sig.size, CSMAN_LITTLE_ENDIAN.len());
        assert_eq!(sig.description, "CSman DAT file, total size: 30 bytes")
    }

    #[test]
    fn test_csman_parser_with_offset() {
        let full_data = [b"A", CSMAN_LITTLE_ENDIAN].concat();
        let result = csman_parser(&full_data, 1);
        let sig = result.unwrap();
        assert_eq!(sig.offset, 1);
        assert_eq!(sig.size, CSMAN_LITTLE_ENDIAN.len());
        assert_eq!(sig.description, "CSman DAT file, total size: 30 bytes")
    }

    #[test]
    fn test_compressed_duplicate_keys_extraction() {
        use miniz_oxide::deflate;
        use std::fs;

        // Build uncompressed entry data (big-endian):
        //   Entry 1: key=1, value=[0xAA, 0xBB, 0xCC]
        //   Entry 2: key=1, value=[0xDD, 0xEE]  (duplicate key)
        //   EOF marker
        let entries: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC, // entry 1
            0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xDD, 0xEE, // entry 2 (duplicate key)
            0x00, 0x00, 0x00, 0x00, // EOF
        ];
        let decompressed_size = entries.len() as u32;

        // Compress as raw deflate and prepend 2-byte zlib header (0x78, 0x9C)
        let deflated = deflate::compress_to_vec(&entries, 6);
        let mut payload: Vec<u8> = vec![0x78, 0x9C];
        payload.extend_from_slice(&deflated);
        let compressed_size = payload.len() as u32;

        // Build the big-endian CSMAN file
        let mut file_data: Vec<u8> = vec![
            0x53, 0x43, // magic "SC" (big-endian)
            0x00, 0x00, // unknown1
        ];
        file_data.extend_from_slice(&compressed_size.to_be_bytes());
        file_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unknown2
        file_data.extend_from_slice(&decompressed_size.to_be_bytes());
        file_data.extend_from_slice(&payload);

        let tmp = tempfile::tempdir().unwrap();

        let result = extract_csman_dat(&file_data, 0, Some(tmp.path()));
        assert!(result.success);
        assert_eq!(result.size, Some(file_data.len()));

        // First occurrence of key=1: "00000001.dat"
        assert_eq!(
            fs::read(tmp.path().join("00000001.dat")).unwrap(),
            &[0xAA, 0xBB, 0xCC]
        );
        // Duplicate key=1: "00000001.dat_1"
        assert_eq!(
            fs::read(tmp.path().join("00000001.dat_1")).unwrap(),
            &[0xDD, 0xEE]
        );
    }
}
