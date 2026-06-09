use crate::common::epoch_to_string;
use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use std::mem::offset_of;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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
    const SQUASHFS_V4: u16 = 4;

    let mut result = SignatureResult {
        size: 0,
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data: usize = file_data.len() - offset;

    // Parse the squashfs header
    let squashfs_header =
        parse_squashfs_header(&file_data[offset..]).map_err(|_| SignatureError)?;
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
        if uid_table_start > squashfs_header.header_size
            && let Some(uid_entry_data) = file_data.get(uid_table_start..)
            && let Ok(uid_entry) = parse_squashfs_uid_entry(
                uid_entry_data,
                squashfs_header.major_version,
                squashfs_header.endianness,
            )
        {
            // Make sure the first UID table entry is either 0, or falls within the bounds of the SquashFS image data
            if (uid_entry == 0)
                || (uid_entry > squashfs_header.header_size
                    && uid_entry <= squashfs_header.image_size)
            {
                // Make sure the compression type is supported
                if let Some(compression_type) = parse_compression_type(squashfs_header.compression)
                {
                    // Select the appropriate extractor to use
                    if squashfs_header.endianness == Endianness::Little {
                        result.preferred_extractor = Some(squashfs_le_extractor());
                    } else if squashfs_header.major_version == SQUASHFS_V4 {
                        result.preferred_extractor = Some(squashfs_v4_be_extractor());
                    } else {
                        result.preferred_extractor = Some(squashfs_be_extractor());
                    }

                    // Format the modified time into something human readable
                    let create_date = epoch_to_string(squashfs_header.timestamp);

                    result.size = squashfs_header.image_size;
                    result.description = format!(
                        "{}, {} endian, version: {}.{}, compression: {}, inode count: {}, block size: {}, image size: {} bytes, created: {}",
                        result.description,
                        squashfs_header.endianness,
                        squashfs_header.major_version,
                        squashfs_header.minor_version,
                        compression_type,
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

    Err(SignatureError)
}

/// Stores SquashFS header info
#[derive(Debug, Clone)]
pub struct SquashFSHeader {
    pub timestamp: u32,
    pub block_size: usize,
    pub image_size: usize,
    pub header_size: usize,
    pub inode_count: usize,
    pub endianness: Endianness,
    pub compression: u16,
    pub major_version: u16,
    pub minor_version: u16,
    pub uid_table_start: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SquashFSV4Header {
    magic: dyn_endian::U32,
    inode_count: dyn_endian::U32,
    modification_time: dyn_endian::U32,
    block_size: dyn_endian::U32,
    fragment_count: dyn_endian::U32,
    compression_id: dyn_endian::U16,
    block_log: dyn_endian::U16,
    flags: dyn_endian::U16,
    id_count: dyn_endian::U16,
    major_version: dyn_endian::U16,
    minor_version: dyn_endian::U16,
    root_inode_ref: dyn_endian::U64,
    image_size: dyn_endian::U64,
    uid_start: dyn_endian::U64,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SquashFSV3Header {
    magic: dyn_endian::U32,
    inode_count: dyn_endian::U32,
    bytes_used_2: dyn_endian::U32,
    uid_start_2: dyn_endian::U32,
    guid_start_2: dyn_endian::U32,
    inode_table_start_2: dyn_endian::U32,
    directory_table_start_2: dyn_endian::U32,
    major_version: dyn_endian::U16,
    minor_version: dyn_endian::U16,
    block_size_1: dyn_endian::U16,
    block_log: dyn_endian::U16,
    flags: u8,
    uid_count: u8,
    guid_count: u8,
    modification_time: dyn_endian::U32,
    root_inode_ref: dyn_endian::U64,
    block_size: dyn_endian::U32,
    fragment_entry_count: dyn_endian::U32,
    fragment_table_start_2: dyn_endian::U32,
    image_size: dyn_endian::U64,
    uid_start: dyn_endian::U64,
    guid_start: dyn_endian::U64,
    inode_table_start: dyn_endian::U64,
    directory_table_start: dyn_endian::U64,
    fragment_table_start: dyn_endian::U64,
    lookup_table_start: dyn_endian::U64,
}

const SQUASHFS_VERSION_START: usize = {
    assert!(
        offset_of!(SquashFSV4Header, major_version) == offset_of!(SquashFSV3Header, major_version)
    );
    offset_of!(SquashFSV4Header, major_version)
};
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct VersionOnlyHeader {
    _ignored: [u8; SQUASHFS_VERSION_START],
    major_version: dyn_endian::U16,
}

/// Parse a SquashFS superblock header
pub fn parse_squashfs_header(sqsh_data: &[u8]) -> Result<SquashFSHeader, StructureError> {
    // Size & offset constants
    const MAX_SQUASHFS_VERSION: u16 = 4;
    const MIN_SQUASHFS_HEADER_SIZE: usize = 120;

    // Make sure there is at least enough data to read in a SquashFS header
    if sqsh_data.len() > MIN_SQUASHFS_HEADER_SIZE {
        let (version_header, _) =
            VersionOnlyHeader::ref_from_prefix(sqsh_data).expect("checked min header size");
        let (squashfs_version, endianness) =
            match version_header.major_version.get(Endianness::Little) {
                le_v if (0..=MAX_SQUASHFS_VERSION).contains(&le_v) => (le_v, Endianness::Little),
                le_v => (le_v.swap_bytes(), Endianness::Big),
            };

        // Sanity check the version number
        if squashfs_version <= MAX_SQUASHFS_VERSION && squashfs_version > 0 {
            let squashfs_header_size: usize;

            // Parse the SquashFS header, using the appropriate version header.
            if squashfs_version == 4 {
                squashfs_header_size = std::mem::size_of::<SquashFSV4Header>();
                let (squashfs_header, _) =
                    SquashFSV4Header::ref_from_prefix(sqsh_data).map_err(|_| StructureError)?;

                let image_size = squashfs_header.image_size.get(endianness) as usize;

                if image_size > MIN_SQUASHFS_HEADER_SIZE {
                    // Make sure the block size and block log fields agree
                    if squashfs_header.block_size.get(endianness) > 0
                        && squashfs_header.block_log.get(endianness)
                            == (squashfs_header.block_size.get(endianness).ilog2() as u16)
                    {
                        return Ok(SquashFSHeader {
                            timestamp: squashfs_header.modification_time.get(endianness),
                            block_size: squashfs_header.block_size.get(endianness) as usize,
                            image_size,
                            header_size: squashfs_header_size,
                            inode_count: squashfs_header.inode_count.get(endianness) as usize,
                            endianness,
                            compression: squashfs_header.compression_id.get(endianness),
                            major_version: squashfs_header.major_version.get(endianness),
                            minor_version: squashfs_header.minor_version.get(endianness),
                            uid_table_start: squashfs_header.uid_start.get(endianness) as usize,
                        });
                    }
                }
            } else {
                squashfs_header_size = std::mem::size_of::<SquashFSV3Header>();
                let (squashfs_header, _) =
                    SquashFSV3Header::ref_from_prefix(sqsh_data).map_err(|_| StructureError)?;

                // Adjust the reported header values for v1 and v2 images
                let uid_start = if squashfs_version < 3 {
                    squashfs_header.uid_start_2.get(endianness) as usize
                } else {
                    squashfs_header.uid_start.get(endianness) as usize
                };
                let image_size = if squashfs_version < 3 {
                    squashfs_header.bytes_used_2.get(endianness) as usize
                } else {
                    squashfs_header.image_size.get(endianness) as usize
                };

                if image_size > MIN_SQUASHFS_HEADER_SIZE {
                    // Make sure the block size and block log fields agree
                    if squashfs_header.block_size.get(endianness) > 0
                        && squashfs_header.block_log.get(endianness)
                            == (squashfs_header.block_size.get(endianness).ilog2() as u16)
                    {
                        return Ok(SquashFSHeader {
                            timestamp: squashfs_header.modification_time.get(endianness),
                            block_size: squashfs_header.block_size.get(endianness) as usize,
                            image_size,
                            header_size: squashfs_header_size,
                            inode_count: squashfs_header.inode_count.get(endianness) as usize,
                            endianness,
                            compression: 0,
                            major_version: squashfs_header.major_version.get(endianness),
                            minor_version: squashfs_header.minor_version.get(endianness),
                            uid_table_start: uid_start,
                        });
                    }
                }
            }
            // Make sure the reported image size is at least bigger than the SquashFS header
        }
    }

    Err(StructureError)
}

/// Parse a UID entry for either SquashFSv4 or SquashFSv3
pub fn parse_squashfs_uid_entry(
    uid_data: &[u8],
    version: u16,
    endianness: Endianness,
) -> Result<usize, StructureError> {
    // Parse one entry from the UID table
    if version == 4 {
        let (uid, _) = dyn_endian::U64::ref_from_prefix(uid_data).map_err(|_| StructureError)?;
        Ok(uid.get(endianness) as usize)
    } else {
        let (uid, _) = dyn_endian::U32::ref_from_prefix(uid_data).map_err(|_| StructureError)?;
        Ok(uid.get(endianness) as usize)
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

const fn parse_compression_type(compression_type: u16) -> Option<&'static str> {
    Some(match compression_type {
        0 => "unknown",
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => return None,
    })
}
