use crate::common::epoch_to_string;
use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::collections::HashMap;

/// Human readable description
pub const DESCRIPTION: &str = "SquashFS file system";

/// All of the known magic bytes that could indicate the beginning of a SquashFS image
pub fn squashfs_magic() -> Vec<Vec<u8>> {
    vec![
        b"sqsh".to_vec(),
        b"hsqs".to_vec(),
        b"sqlz".to_vec(),
        b"qshs".to_vec(),
        b"tqsh".to_vec(),
        b"hsqt".to_vec(),
        b"shsq".to_vec(),
    ]
}

/// Responsible for parsing and validating a suspected SquashFS image header
pub fn squashfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const SQUASHFSV4: usize = 4;

    let squashfs_compression_types = HashMap::from([
        (0, "unknown"),
        (1, "gzip"),
        (2, "lzma"),
        (3, "lzo"),
        (4, "xz"),
        (5, "lz4"),
        (6, "zstd"),
    ]);

    let mut result = SignatureResult {
        size: 0,
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data: usize = file_data.len() - offset;

    // Parse the squashfs header
    if let Ok(squashfs_header) = parse_squashfs_header(&file_data[offset..]) {
        // Sanity check the reported image size
        if squashfs_header.image_size <= available_data {
            /*
             * To better validate SquashFS images, we want to verify at least some of the SquashFS image contents.
             * There are situations where the SquashFS header itself is valid and in-tact, but the data is not; for example,
             * gzipping a SquashFS image often leaves some of the SquashFS data uncompressed, since SquashFS images are already
             * compressed and the gzip utility realizes that it cannot further compress some sections. This can result in the
             * contents of the gzipped data containing an uncorrupted copy of the SquashFS header, while some of the SquashFS
             * image contents are gzipped compressed.
             *
             * The easiest field to validate seems to be the UID table pointer, which is an offset in the SquashFS image whre
             * the UID table resides. This table is just an array of 64-bit pointers, each one pointing to a compressed data block
             * which contains the actual UIDs. Validate that the UID table pointer is sane, *and* that the first 64-bit pointer
             * in the UID table is sane.
             */

            // Get the offset of the UID table, an array of pointers to metadata blocks containing lists of user IDs
            let uid_table_start: usize = offset + squashfs_header.uid_table_start;

            // Validate that the UID table pointer points to a location after the end of the SquashFS header (it's usually at the end of the image)
            if uid_table_start > squashfs_header.header_size {
                // Get the UID table data
                if let Some(uid_entry_data) = file_data.get(uid_table_start..) {
                    // Parse one entry from the UID table
                    if let Ok(uid_entry) = parse_squashfs_uid_entry(
                        uid_entry_data,
                        squashfs_header.major_version,
                        &squashfs_header.endianness,
                    ) {
                        // Make sure the first UID table entry is either 0, or falls within the bounds of the SquashFS image data
                        if (uid_entry == 0)
                            || (uid_entry > squashfs_header.header_size
                                && uid_entry <= squashfs_header.image_size)
                        {
                            // Format the modified time into something human readable
                            let create_date = epoch_to_string(squashfs_header.timestamp as u32);

                            // Make sure the compression type is supported
                            if let Some(compression_type) =
                                squashfs_compression_types.get(&squashfs_header.compression)
                            {
                                let compression_type_str = compression_type.to_string();

                                // Select the appropriate extractor to use
                                if squashfs_header.endianness == "little" {
                                    result.preferred_extractor = Some(squashfs_le_extractor());
                                } else if squashfs_header.major_version == SQUASHFSV4 {
                                    result.preferred_extractor = Some(squashfs_v4_be_extractor());
                                } else {
                                    result.preferred_extractor = Some(squashfs_be_extractor());
                                }

                                result.size = squashfs_header.image_size;
                                result.description = format!(
                                    "{}, {} endian, version: {}.{}, compression: {}, inode count: {}, block size: {}, image size: {} bytes, created: {}",
                                    result.description,
                                    squashfs_header.endianness,
                                    squashfs_header.major_version,
                                    squashfs_header.minor_version,
                                    compression_type_str,
                                    squashfs_header.inode_count,
                                    squashfs_header.block_size,
                                    squashfs_header.image_size,
                                    create_date
                                );

                                return Ok(result);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(SignatureError)
}

/// Stores SquashFS header info
#[derive(Debug, Default, Clone)]
pub struct SquashFSHeader {
    pub timestamp: usize,
    pub block_size: usize,
    pub image_size: usize,
    pub header_size: usize,
    pub inode_count: usize,
    pub endianness: String,
    pub compression: usize,
    pub major_version: usize,
    pub minor_version: usize,
    pub uid_table_start: usize,
}

/// Parse a SquashFS superblock header
pub fn parse_squashfs_header(sqsh_data: &[u8]) -> Result<SquashFSHeader, StructureError> {
    // Size & offset constants
    const MAX_SQUASHFS_VERSION: u16 = 4;
    const SQUASHFS_VERSION_END: usize = 30;
    const SQUASHFS_VERSION_START: usize = 28;
    const MIN_SQUASHFS_HEADER_SIZE: usize = 120;

    let squashfs_v4_structure = vec![
        ("magic", "u32"),
        ("inode_count", "u32"),
        ("modification_time", "u32"),
        ("block_size", "u32"),
        ("fragment_count", "u32"),
        ("compression_id", "u16"),
        ("block_log", "u16"),
        ("flags", "u16"),
        ("id_count", "u16"),
        ("major_version", "u16"),
        ("minor_version", "u16"),
        ("root_inode_ref", "u64"),
        ("image_size", "u64"),
        ("uid_start", "u64"),
    ];

    let squashfs_v3_structure = vec![
        ("magic", "u32"),
        ("inode_count", "u32"),
        ("bytes_used_2", "u32"),
        ("uid_start_2", "u32"),
        ("guid_start_2", "u32"),
        ("inode_table_start_2", "u32"),
        ("directory_table_start_2", "u32"),
        ("major_version", "u16"),
        ("minor_version", "u16"),
        ("block_size_1", "u16"),
        ("block_log", "u16"),
        ("flags", "u8"),
        ("uid_count", "u8"),
        ("guid_count", "u8"),
        ("modification_time", "u32"),
        ("root_inode_ref", "u64"),
        ("block_size", "u32"),
        ("fragment_entry_count", "u32"),
        ("fragment_table_start_2", "u32"),
        ("image_size", "u64"),
        ("uid_start", "u64"),
        ("guid_start", "u64"),
        ("inode_table_start", "u64"),
        ("directory_table_start", "u64"),
        ("fragment_table_start", "u64"),
        ("lookup_table_start", "u64"),
    ];

    // Default to little endian
    let mut sqsh_header = SquashFSHeader {
        endianness: "little".to_string(),
        ..Default::default()
    };

    // Make sure there is at least enough data to read in a SquashFS header
    if sqsh_data.len() > MIN_SQUASHFS_HEADER_SIZE {
        /*
         * Regardless of the SquashFS version, the version number is always at the same location in the SquashFS suprblock header.
         * This can then be reliably used to determine both the SquashFS superblock header version, as well as the endianness used.
         * Interpret the squashfs major version, assuming little endian.
         */
        let mut squashfs_version = u16::from_le_bytes(
            sqsh_data[SQUASHFS_VERSION_START..SQUASHFS_VERSION_END]
                .try_into()
                .unwrap(),
        );

        // If the version number doesn't look sane, switch to big endian
        if squashfs_version == 0 || squashfs_version > MAX_SQUASHFS_VERSION {
            sqsh_header.endianness = "big".to_string();
            squashfs_version = u16::from_be_bytes(
                sqsh_data[SQUASHFS_VERSION_START..SQUASHFS_VERSION_END]
                    .try_into()
                    .unwrap(),
            );
        }

        // Sanity check the version number
        if squashfs_version <= MAX_SQUASHFS_VERSION && squashfs_version > 0 {
            let squashfs_header_size: usize;
            let mut squashfs_header: HashMap<String, usize>;

            // Parse the SquashFS header, using the appropriate version header.
            if squashfs_version == 4 {
                squashfs_header_size = crate::structures::size(&squashfs_v4_structure);
                match crate::structures::parse(
                    sqsh_data,
                    &squashfs_v4_structure,
                    &sqsh_header.endianness,
                ) {
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(squash4_header) => {
                        squashfs_header = squash4_header;
                    }
                }
            } else {
                squashfs_header_size = crate::structures::size(&squashfs_v3_structure);
                match crate::structures::parse(
                    sqsh_data,
                    &squashfs_v3_structure,
                    &sqsh_header.endianness,
                ) {
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(squash3_header) => {
                        squashfs_header = squash3_header;

                        // Adjust the reported header values for v1 and v2 images
                        if squashfs_version < 3 {
                            squashfs_header
                                .insert("uid_start".to_string(), squashfs_header["uid_start_2"]);
                            squashfs_header
                                .insert("guid_start".to_string(), squashfs_header["guid_start_2"]);
                            squashfs_header
                                .insert("image_size".to_string(), squashfs_header["bytes_used_2"]);
                            squashfs_header.insert(
                                "inode_table_start".to_string(),
                                squashfs_header["inode_table_start_2"],
                            );
                            squashfs_header.insert(
                                "directory_table_start".to_string(),
                                squashfs_header["directory_table_start_2"],
                            );
                        }
                    }
                }
            }

            // Report the total size of this SquashFS image
            sqsh_header.image_size = squashfs_header["image_size"];

            // Make sure the reported image size is at least bigger than the SquashFS header
            if sqsh_header.image_size > MIN_SQUASHFS_HEADER_SIZE {
                // Make sure the block size and block log fields agree
                if squashfs_header["block_size"] > 0
                    && squashfs_header["block_log"]
                        == (squashfs_header["block_size"].ilog2() as usize)
                {
                    // Report relevant squashfs fields
                    sqsh_header.timestamp = squashfs_header["modification_time"];
                    sqsh_header.block_size = squashfs_header["block_size"];
                    sqsh_header.header_size = squashfs_header_size;
                    sqsh_header.inode_count = squashfs_header["inode_count"];
                    sqsh_header.major_version = squashfs_header["major_version"];
                    sqsh_header.minor_version = squashfs_header["minor_version"];
                    sqsh_header.uid_table_start = squashfs_header["uid_start"];

                    // v3 headers don't have a compression ID
                    if let Some(compression_id) = squashfs_header.get("compression_id").copied() {
                        sqsh_header.compression = compression_id;
                    }

                    return Ok(sqsh_header);
                }
            }
        }
    }

    Err(StructureError)
}

/// Parse a UID entry for either SquashFSv4 or SquashFSv3
pub fn parse_squashfs_uid_entry(
    uid_data: &[u8],
    version: usize,
    endianness: &str,
) -> Result<usize, StructureError> {
    let squashfs_v4_uid_table_structure = vec![("uid_block_ptr", "u64")];
    let squashfs_v3_uid_table_structure = vec![("uid_block_ptr", "u32")];

    // Parse one entry from the UID table
    if version == 4 {
        match crate::structures::parse(uid_data, &squashfs_v4_uid_table_structure, endianness) {
            Err(e) => Err(e),
            Ok(uidv4) => Ok(uidv4["uid_block_ptr"]),
        }
    } else {
        match crate::structures::parse(uid_data, &squashfs_v3_uid_table_structure, endianness) {
            Err(e) => Err(e),
            Ok(uidv3) => Ok(uidv3["uid_block_ptr"]),
        }
    }
}

/// Describes how to run the sasquatch utility to extract SquashFS images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::squashfs::squashfs_extractor;
///
/// match squashfs_extractor().utility {
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
pub fn squashfs_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("sasquatch".to_string()),
        extension: "sqsh".to_string(),
        arguments: vec![extractors::SOURCE_FILE_PLACEHOLDER.to_string()],
        // Exit code may be 0 or 2; 2 indicates running as not root, but otherwise extraction is ok
        exit_codes: vec![0, 2],
        ..Default::default()
    }
}

/// Describes how to run the sasquatch utility to extract little endian SquashFS images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::squashfs::squashfs_le_extractor;
///
/// match squashfs_le_extractor().utility {
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
pub fn squashfs_le_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("sasquatch".to_string()),
        extension: "sqsh".to_string(),
        arguments: vec![
            "-le".to_string(),
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        // Exit code may be 0 or 2; 2 indicates running as not root, but otherwise extraction is ok
        exit_codes: vec![0, 2],
        ..Default::default()
    }
}

/// Describes how to run the sasquatch utility to extract big endian SquashFS images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::squashfs::squashfs_be_extractor;
///
/// match squashfs_be_extractor().utility {
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
pub fn squashfs_be_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("sasquatch".to_string()),
        extension: "sqsh".to_string(),
        arguments: vec![
            "-be".to_string(),
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        // Exit code may be 0 or 2; 2 indicates running as not root, but otherwise extraction is ok
        exit_codes: vec![0, 2],
        ..Default::default()
    }
}

/// Describes how to run the sasquatch-v4be utility to extract big endian SquashFSv4 images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::squashfs::squashfs_v4_be_extractor;
///
/// match squashfs_v4_be_extractor().utility {
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
pub fn squashfs_v4_be_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("sasquatch-v4be".to_string()),
        extension: "sqsh".to_string(),
        arguments: vec![extractors::SOURCE_FILE_PLACEHOLDER.to_string()],
        // Exit code may be 0 or 2; 2 indicates running as not root, but otherwise extraction is ok
        exit_codes: vec![0, 2],
        ..Default::default()
    }
}
