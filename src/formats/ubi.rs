use crate::common::crc32;
use crate::extractors;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use aho_corasick::AhoCorasick;
use std::collections::HashMap;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable desciptions
pub const UBI_FS_DESCRIPTION: &str = "UBIFS image";
pub const UBI_IMAGE_DESCRIPTION: &str = "UBI image";

/// Erase block magic bytes; header version is assumed to be 1
pub fn ubi_magic() -> Vec<Vec<u8>> {
    vec![b"UBI#\x01".to_vec()]
}

/// UBI node magic; this matches *any* UBI node, but ubifs_parser ensures that only superblock nodes are reported
pub fn ubifs_magic() -> Vec<Vec<u8>> {
    vec![b"\x31\x18\x10\x06".to_vec()]
}

/// Validates a UBIFS signature
pub fn ubifs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: UBI_FS_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the UBIFS superblock header
    if let Ok(sb_header) = parse_ubi_superblock_header(&file_data[offset..]) {
        // Image size is the number of logical erase blocks times the size of each logical erase block
        result.size = (sb_header.leb_count as usize) * (sb_header.leb_size as usize);
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Validates a UBI signature
pub fn ubi_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: UBI_IMAGE_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the UBI header
    if let Ok(ubi_header) = parse_ubi_ec_header(&file_data[offset..]) {
        let data_offset: usize = offset + ubi_header.data_offset;
        let volume_offset: usize = offset + ubi_header.volume_id_offset;

        // Sanity check the reported volume and data offsets
        if file_data.len() > data_offset && file_data.len() > volume_offset {
            // Get the size of the UBI image
            if let Ok(image_size) = get_ubi_image_size(&file_data[offset..]) {
                result.size = image_size;
                result.description = format!(
                    "{}, version: {}, image size: {} bytes",
                    result.description, ubi_header.version, result.size
                );
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Determines the LEB size and returns the size of the UBI image
fn get_ubi_image_size(ubi_data: &[u8]) -> Result<usize, SignatureError> {
    let mut leb_size: usize = 0;
    let mut block_count: usize = 0;
    let mut best_leb_match_count: usize = 0;
    let mut previous_volume_offset: usize = 0;
    let mut possible_leb_sizes: HashMap<usize, usize> = HashMap::new();

    // Volume magic bytes, version is assumed to be 1
    let ubi_vol_magic = vec![b"UBI!\x01"];

    let grep = AhoCorasick::new(ubi_vol_magic).unwrap();

    // grep for all volume header magic bytes
    for magic_match in grep.find_overlapping_iter(ubi_data) {
        // Offset in the UBI image where this magic match was found
        let this_volume_offset = magic_match.start();

        // Parse the volume header
        if parse_ubi_volume_header(&ubi_data[this_volume_offset..]).is_ok() {
            // Header looks valid, increment the block count
            block_count += 1;

            // If there was a previous UBI volume header identified, calculate the leb size as the distance between the two volume header
            if previous_volume_offset != 0 {
                let this_leb_size = this_volume_offset - previous_volume_offset;

                // Keep track of the calculated leb size, and how many times each possible leb size was found
                *possible_leb_sizes.entry(this_leb_size).or_insert(0) += 1;
            }

            previous_volume_offset = this_volume_offset;
        }
    }

    // Pick the most common leb size
    for (leb_candidate_size, leb_candidate_count) in possible_leb_sizes.iter() {
        if *leb_candidate_count > best_leb_match_count {
            leb_size = *leb_candidate_size;
            best_leb_match_count = *leb_candidate_count;
        }
    }

    // Image size is leb size times the number of blocks
    if leb_size != 0 && block_count != 0 {
        return Ok(block_count * leb_size);
    }

    Err(SignatureError)
}

/// Stores UBI superblock header info
#[derive(Debug, Default, Clone)]
pub struct UbiSuperBlockHeader {
    pub leb_size: u32,
    pub leb_count: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UbiSuperBlockHeaderBytes {
    magic: zerocopy::U32<LE>,
    header_crc: zerocopy::U32<LE>,
    sequence_number: zerocopy::U64<LE>,
    node_len: zerocopy::U32<LE>,
    node_type: u8,
    group_type: u8,
    padding1: zerocopy::U32<LE>,
    key_hash: u8,
    key_format: u8,
    flags: zerocopy::U32<LE>,
    min_io_size: zerocopy::U32<LE>,
    leb_size: zerocopy::U32<LE>,
    leb_count: zerocopy::U32<LE>,
    max_leb_count: zerocopy::U32<LE>,
    max_bud_bytes: zerocopy::U64<LE>,
    log_lebs: zerocopy::U32<LE>,
    lpt_lebs: zerocopy::U32<LE>,
    orph_lebs: zerocopy::U32<LE>,
    jhead_count: zerocopy::U32<LE>,
    fanout: zerocopy::U32<LE>,
    lsave_count: zerocopy::U32<LE>,
    fmt_version: zerocopy::U32<LE>,
    default_compression: zerocopy::U16<LE>,
    padding2: zerocopy::U16<LE>,
    rp_uid: zerocopy::U32<LE>,
    rp_gid: zerocopy::U32<LE>,
    rp_size: zerocopy::U64<LE>,
    time_gran: zerocopy::U32<LE>,
    uuid_p1: zerocopy::U64<LE>,
    uuid_p2: zerocopy::U64<LE>,
    ro_compat_version: zerocopy::U32<LE>,
}

/// Partially parse a UBI superblock header
pub fn parse_ubi_superblock_header(ubi_data: &[u8]) -> Result<UbiSuperBlockHeader, StructureError> {
    // Type & offset constants
    const MAX_GROUP_TYPE: u8 = 2;
    const CRC_START_OFFSET: usize = 8;
    const SUPERBLOCK_NODE_TYPE: u8 = 6;

    // There are some other fields in the superblock header that we don't parse because we don't really care about them...
    const SUPERBLOCK_STRUCTURE_EXTRA_SIZE: usize = 3968;

    let sb_struct_size: usize =
        std::mem::size_of::<UbiSuperBlockHeaderBytes>() + SUPERBLOCK_STRUCTURE_EXTRA_SIZE;

    // Parse the UBI superblock header
    let (sb_header, _) =
        UbiSuperBlockHeaderBytes::ref_from_prefix(ubi_data).map_err(|_| StructureError)?;

    // Make sure the padding fields are NULL
    if sb_header.padding1.get() == 0 && sb_header.padding2.get() == 0 {
        // Make sure the node type is SUPERBLOCK
        if sb_header.node_type == SUPERBLOCK_NODE_TYPE {
            // Make sure the group type is valid
            if sb_header.group_type <= MAX_GROUP_TYPE {
                // Validate the header CRC, which is calculated over the entire header except for the magic bytes and CRC field
                if let Some(crc_data) = ubi_data.get(CRC_START_OFFSET..sb_struct_size)
                    && ubi_crc(crc_data) == sb_header.header_crc.get()
                {
                    return Ok(UbiSuperBlockHeader {
                        leb_size: sb_header.leb_size.get(),
                        leb_count: sb_header.leb_count.get(),
                    });
                }
            }
        }
    }

    Err(StructureError)
}

/// Stores info about a UBI erase count header
#[derive(Debug, Default, Clone)]
pub struct UbiECHeader {
    pub version: u8,
    pub data_offset: usize,
    pub volume_id_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UbiECHeaderBytes {
    magic: zerocopy::U32<BE>,
    version: u8,
    padding1: [u8; 3],
    ec: zerocopy::U64<BE>,
    volume_id_header_offset: zerocopy::U32<BE>,
    data_offset: zerocopy::U32<BE>,
    image_sequence_number: zerocopy::U32<BE>,
    padding2: [u8; 32],
    header_crc: zerocopy::U32<BE>,
}

/// Parse a UBI erase count header
pub fn parse_ubi_ec_header(ubi_data: &[u8]) -> Result<UbiECHeader, StructureError> {
    let ec_header_size: usize = std::mem::size_of::<UbiECHeaderBytes>();
    let crc_data_size: usize = ec_header_size - std::mem::size_of::<u32>();

    // Parse the first half of the header
    let (ubi_ec_header, _) =
        UbiECHeaderBytes::ref_from_prefix(ubi_data).map_err(|_| StructureError)?;

    // Offsets should be beyond the EC header
    if ubi_ec_header.data_offset.get() as usize >= ec_header_size
        && ubi_ec_header.volume_id_header_offset.get() as usize >= ec_header_size
    {
        // Validate the header CRC
        if let Some(crc_data) = ubi_data.get(0..crc_data_size)
            && ubi_crc(crc_data) == ubi_ec_header.header_crc.get()
        {
            return Ok(UbiECHeader {
                version: ubi_ec_header.version,
                data_offset: ubi_ec_header.data_offset.get() as usize,
                volume_id_offset: ubi_ec_header.volume_id_header_offset.get() as usize,
            });
        }
    }

    Err(StructureError)
}

/// Dummy structure indicating a UBI volume header was parsed successfully
#[derive(Debug, Default, Clone)]
pub struct UbiVolumeHeader;

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UbiVolumeHeaderBytes {
    magic: zerocopy::U32<BE>,
    version: u8,
    volume_type: u8,
    copy_flag: u8,
    compat_type: u8,
    volume_id: zerocopy::U32<BE>,
    logical_erase_block_number: zerocopy::U32<BE>,
    padding1: [u8; 4],
    data_size: zerocopy::U32<BE>,
    used_erase_block_count: zerocopy::U32<BE>,
    data_padding_size: zerocopy::U32<BE>,
    data_crc: zerocopy::U32<BE>,
    padding2: [u8; 4],
    sequence_number: zerocopy::U64<BE>,
    padding3: [u8; 12],
    header_crc: zerocopy::U32<BE>,
}

/// Parse a UBI volume header
pub fn parse_ubi_volume_header(ubi_data: &[u8]) -> Result<UbiVolumeHeader, StructureError> {
    let vol_header_size: usize = std::mem::size_of::<UbiVolumeHeaderBytes>();
    let crc_data_size: usize = vol_header_size - std::mem::size_of::<u32>();

    // Parse the volume header
    let (ubi_vol_header, _) =
        UbiVolumeHeaderBytes::ref_from_prefix(ubi_data).map_err(|_| StructureError)?;

    // Sanity check padding fields, they should all be null
    if ubi_vol_header
        .padding1
        .iter()
        .chain(&ubi_vol_header.padding2)
        .chain(&ubi_vol_header.padding3)
        .all(|&b| b == 0)
    {
        // Validate the header CRC
        if let Some(crc_data) = ubi_data.get(0..crc_data_size)
            && ubi_crc(crc_data) == ubi_vol_header.header_crc.get()
        {
            return Ok(UbiVolumeHeader);
        }
    }

    Err(StructureError)
}

/// Calculate a UBI checksum
fn ubi_crc(data: &[u8]) -> u32 {
    const UBI_CRC_INIT: u32 = 0xFFFFFFFF;
    (!crc32(data)) & UBI_CRC_INIT
}

/// Describes how to run the ubireader_extract_images utility to extract UBI images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::ubi::ubi_extractor;
///
/// match ubi_extractor().utility {
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
pub fn ubi_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("ubireader_extract_images".to_string()),
        extension: "img".to_string(),
        arguments: vec![extractors::SOURCE_FILE_PLACEHOLDER.to_string()],
        exit_codes: vec![0],
        ..Default::default()
    }
}

/// Describes how to run the ubireader_extract_files utility to extract UBIFS images
pub fn ubifs_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("ubireader_extract_files".to_string()),
        extension: "ubifs".to_string(),
        arguments: vec![extractors::SOURCE_FILE_PLACEHOLDER.to_string()],
        exit_codes: vec![0],
        ..Default::default()
    }
}
