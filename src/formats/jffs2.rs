use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use aho_corasick::AhoCorasick;
use crc32fast::Hasher;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "JFFS2 filesystem";

/// JFFS2 magic bytes
pub fn jffs2_magic() -> Vec<Vec<u8>> {
    /*
     * Big and little endian patterns to search for.
     * These assume that the first JFFS2 node will be a directory, inode, or clean marker type.
     * Longer signatures are less prone to false positive matches.
     */
    vec![
        b"\x19\x85\xe0\x01".to_vec(),
        b"\x19\x85\xe0\x02".to_vec(),
        b"\x19\x85\x20\x03".to_vec(),
        b"\x85\x19\x01\xe0".to_vec(),
        b"\x85\x19\x02\xe0".to_vec(),
        b"\x85\x19\x03\x20".to_vec(),
    ]
}

/// Parse and validate a JFFS2 image
pub fn jffs2_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Useful constants
    const MAX_PAGE_SIZE: usize = 0x20000;
    const MIN_VALID_NODE_COUNT: usize = 2;
    const JFFS2_BIG_ENDIAN_MAGIC: &[u8; 2] = b"\x19\x85";
    const JFFS2_LITTLE_ENDIAN_MAGIC: &[u8; 2] = b"\x85\x19";

    let mut result = SignatureResult {
        size: 0,
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse this first JFFS2 node header to ensure correctness
    if let Ok(first_node_header) = parse_jffs2_node_header(&file_data[offset..]) {
        // The known end of JFFS2 data in the raw file data. This will be updated as we find more nodes.
        let mut jffs2_eof: usize = offset + roundup(first_node_header.size);

        // Make sure that jffs2_eof is sane
        if jffs2_eof < file_data.len() {
            // Start searching for subsequent JFFS2 nodes at the end of this node's data
            let grep_offset: usize = jffs2_eof;

            // Keep a count of how many valid nodes were found
            let mut node_count: usize = 1;

            // Determine which node magic bytes to search for based on the first node's endianness
            let node_magic = match first_node_header.endianness {
                Endianness::Big => JFFS2_BIG_ENDIAN_MAGIC,
                Endianness::Little => JFFS2_LITTLE_ENDIAN_MAGIC,
            };

            // Need to grep for all JFFS2 nodes to figure out how big this file system really is
            let grep = AhoCorasick::new(vec![node_magic]).unwrap();

            // Find all matching JFFS2 node magic bytes
            for magic_match in grep.find_overlapping_iter(&file_data[grep_offset..].to_vec()) {
                // Calculate the start and end of the node header inside the file data
                let header_start: usize = grep_offset + magic_match.start();
                let header_end: usize = header_start + JFFS2_NODE_STRUCT_SIZE;

                // This is a false positive that is inside the node data of a previously validated node
                if header_start < jffs2_eof {
                    continue;
                }

                // If we haven't found a valid header within MAX_PAGE_SIZE bytes, quit
                if (header_start - jffs2_eof) > MAX_PAGE_SIZE {
                    break;
                }

                // Get the node header's raw bytes
                match file_data.get(header_start..header_end) {
                    None => {
                        break;
                    }
                    Some(node_header_data) => {
                        // Parse this node's header
                        if let Ok(this_node_header) = parse_jffs2_node_header(node_header_data) {
                            node_count += 1;
                            jffs2_eof = header_start + roundup(this_node_header.size);
                        }
                    }
                }
            }

            // Make sure we've processed at least a few JFFS2 nodes
            if node_count > MIN_VALID_NODE_COUNT {
                result.size = jffs2_eof - result.offset;
                result.description = format!(
                    "{}, {}, nodes: {}, total size: {} bytes",
                    result.description, first_node_header.endianness, node_count, result.size
                );
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// JFFS2 nodes are padded to a 4 byte boundary
fn roundup(num: usize) -> usize {
    let base: f64 = 4.0;
    let number: f64 = num as f64;
    let div: f64 = number / base;
    (base * div.ceil()) as usize
}

/// JFFS2 node header size
pub const JFFS2_NODE_STRUCT_SIZE: usize = 12;

/// Structure for storing useful JFFS node info
#[derive(Debug, Clone)]
pub struct JFFS2Node {
    pub size: usize,
    pub endianness: Endianness,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct JFFS2NodeBytes {
    magic: dyn_endian::U16,
    node_type: dyn_endian::U16,
    size: dyn_endian::U32,
    crc: dyn_endian::U32,
}

/// Parse a JFFS2 node header
pub fn parse_jffs2_node_header(node_data: &[u8]) -> Result<JFFS2Node, StructureError> {
    // Expected JFFS2 node magic
    const MAGIC: u16 = 0x1985;
    const LITTLE_ENDIAN_MAGIC: dyn_endian::U16 = dyn_endian::U16::new(MAGIC, Endianness::Little);
    const BIG_ENDIAN_MAGIC: dyn_endian::U16 = dyn_endian::U16::new(MAGIC, Endianness::Big);

    // Number of header bytes over which the header CRC is calculated
    const JFFS2_HEADER_CRC_SIZE: usize = 8;

    // Parse the node header
    let (node_header, _) =
        JFFS2NodeBytes::ref_from_prefix(node_data).map_err(|_| StructureError)?;

    let endianness = match node_header.magic {
        LITTLE_ENDIAN_MAGIC => Endianness::Little,
        BIG_ENDIAN_MAGIC => Endianness::Big,
        _ => return Err(StructureError),
    };

    // Calculate the node header CRC
    let node_calculated_crc = jffs2_node_crc(&node_data[0..JFFS2_HEADER_CRC_SIZE]);

    // Validate the node header CRC
    if node_calculated_crc == node_header.crc.get(endianness) {
        return Ok(JFFS2Node {
            size: node_header.size.get(endianness) as usize,
            endianness,
        });
    }

    Err(StructureError)
}

/// CRC calculation for JFFS
fn jffs2_node_crc(file_data: &[u8]) -> u32 {
    let mut hasher = Hasher::new_with_initial(0xFFFFFFFF);
    hasher.update(file_data);
    hasher.finalize() ^ 0xFFFFFFFF
}

/// Describes how to run the jefferson utility to extract JFFS file systems
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::jffs2::jffs2_extractor;
///
/// match jffs2_extractor().utility {
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
pub fn jffs2_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("jefferson".to_string()),
        extension: "img".to_string(),
        arguments: vec![
            "-f".to_string(), // Force overwrite if output file, for some reason, exists
            "-d".to_string(), // Output to jffs2-root directory
            "jffs2-root".to_string(),
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        exit_codes: vec![0, 1, 2],
        ..Default::default()
    }
}
