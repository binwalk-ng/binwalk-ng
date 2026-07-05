use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use miniz_oxide::inflate;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "CSman DAT file";

const MAGIC: u16 = 0x5343;
const LITTLE_ENDIAN_MAGIC: dyn_endian::U16 = dyn_endian::U16::new(MAGIC, Endianness::Little);
const BIG_ENDIAN_MAGIC: dyn_endian::U16 = dyn_endian::U16::new(MAGIC, Endianness::Big);

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
#[derive(Debug, Clone)]
pub struct CSManHeader {
    pub compressed: bool,
    pub data_size: usize,
    pub endianness: Endianness,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
pub struct CSManHeaderBytes {
    magic: dyn_endian::U16,
    unknown1: dyn_endian::U16,
    compressed_size: dyn_endian::U32,
    unknown2: dyn_endian::U32,
    decompressed_size: dyn_endian::U32,
}

/// Parses a CSMAN header
pub fn parse_csman_header(csman_data: &[u8]) -> Result<(CSManHeader, &[u8]), StructureError> {
    const COMPRESSED_MAGIC: &[u8] = b"\x78";
    let (csman_header, rest) =
        CSManHeaderBytes::ref_from_prefix(csman_data).map_err(|_| StructureError)?;
    let endianness = match csman_header.magic {
        LITTLE_ENDIAN_MAGIC => Endianness::Little,
        BIG_ENDIAN_MAGIC => Endianness::Big,
        _ => return Err(StructureError),
    };

    let compressed_size = csman_header.compressed_size.get(endianness) as usize;
    let decompressed_size = csman_header.decompressed_size.get(endianness) as usize;
    let compressed = compressed_size != decompressed_size;

    let payload = rest.get(..compressed_size).ok_or(StructureError)?;

    if compressed && !payload.starts_with(COMPRESSED_MAGIC) {
        return Err(StructureError);
    }

    Ok((
        CSManHeader {
            compressed,
            data_size: compressed_size,
            endianness,
            header_size: size_of::<CSManHeaderBytes>(),
        },
        payload,
    ))
}

/// Stores info about a single CSMan DAT file entry
#[derive(Debug, Clone)]
pub enum CSManEntry<'a> {
    Eof,
    Data { key: u32, value: &'a [u8] },
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EofEntryBytes {
    key: dyn_endian::U32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EntryBytes {
    key: dyn_endian::U32,
    size: dyn_endian::U16,
}

/// Parses a single CSMan DAT file entry
pub fn parse_csman_entry(
    entry_data: &[u8],
    endianness: Endianness,
) -> Result<(CSManEntry<'_>, &[u8]), StructureError> {
    const EOF_TAG: u32 = 0;

    if let Ok((entry_header, rest)) = EntryBytes::ref_from_prefix(entry_data) {
        let key = entry_header.key.get(endianness);
        let size = entry_header.size.get(endianness) as usize;
        let (value, rest) = rest.split_at_checked(size).ok_or(StructureError)?;
        Ok((CSManEntry::Data { key, value }, rest))
    } else if let Ok((eof_entry, rest)) = EofEntryBytes::ref_from_prefix(entry_data) {
        if eof_entry.key.get(endianness) != EOF_TAG {
            return Err(StructureError);
        }
        Ok((CSManEntry::Eof, rest))
    } else {
        Err(StructureError)
    }
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

    // Maximum size, in bytes, that the compressed entry data is allowed to decompress to.
    // This bounds memory allocation during decompression so that a small, maliciously-crafted
    // file cannot trigger an unbounded allocation (decompression "bomb") and exhaust system memory.
    const MAX_DECOMPRESSED_SIZE: usize = 100 * 1024 * 1024;

    // Return value
    let mut result = ExtractionResult::default();

    let Ok((csman_header, payload)) = parse_csman_header(&file_data[offset..]) else {
        return result;
    };

    let decompressed_data: Vec<u8>;
    let entry_data = if csman_header.compressed {
        // If the entries are compressed, decompress it (zlib compression)
        let Some(compressed_payload) = payload.get(COMPRESSED_HEADER_SIZE..) else {
            return result;
        };
        // Decompress with a hard upper bound on the output size; this prevents a
        // crafted, highly-compressible payload from allocating an arbitrary amount
        // of memory (decompression bomb / DoS). Exceeding the limit fails the extraction.
        match inflate::decompress_to_vec_with_limit(compressed_payload, MAX_DECOMPRESSED_SIZE) {
            Ok(data) => decompressed_data = data,
            Err(_) => return result,
        }
        &decompressed_data[..]
    } else {
        payload
    };

    let mut csman_entries: Vec<(u32, &[u8])> = Vec::new();

    let mut remaining = entry_data;
    while let Ok((entry, rest)) = parse_csman_entry(remaining, csman_header.endianness) {
        remaining = rest;
        match entry {
            CSManEntry::Eof => {
                result.success = !csman_entries.is_empty();
                break;
            }
            CSManEntry::Data { key, value } => {
                csman_entries.push((key, value));
            }
        }
    }
    if !result.success {
        return result;
    }

    result.size = Some(csman_header.header_size + csman_header.data_size);
    if let Some(output_directory) = output_directory {
        // If extraction was requested, extract each entry using the entry key as the file name
        let chroot = Chroot::new(output_directory);
        // There may be more than one entry with the same key; track the key and how many times it was encountered
        let mut processed_entries: HashMap<u32, usize> = HashMap::new();

        for &(key, data) in &csman_entries {
            // File name is [key value, in ASCII hex].dat
            let mut file_name = format!("{key:08X}.dat");
            // If this key value has already been extracted, file name is [key value, in ASCII hex].dat_[count]
            let count = processed_entries.entry(key).or_insert(0);
            if *count != 0 {
                write!(file_name, "_{}", *count).unwrap();
            }
            *count += 1;

            if !chroot.create_file(&file_name, data) {
                result.success = false;
                break;
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
