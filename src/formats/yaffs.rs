use crate::common::is_offset_safe;
use crate::extractors;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Minimum number of expected YAFFS objects in a YAFFS image
const MIN_NUMBER_OF_OBJS: usize = 2;

/// Human readable description
pub const DESCRIPTION: &str = "YAFFSv2 filesystem";

/// Expect the first YAFFS entry to be either a directory (0x00000003) or file (0x00000001), big or little endian
pub fn yaffs_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x03\x00\x00\x00\x01\x00\x00\x00\xFF\xFF".to_vec(),
        b"\x00\x00\x00\x03\x00\x00\x00\x01\xFF\xFF".to_vec(),
        b"\x01\x00\x00\x00\x01\x00\x00\x00\xFF\xFF".to_vec(),
        b"\x00\x00\x00\x01\x00\x00\x00\x01\xFF\xFF".to_vec(),
    ]
}

/// Validate a YAFFS signature
pub fn yaffs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Max page size + max spare size
    const MAX_OBJ_SIZE: usize = 16896;
    const BIG_ENDIAN_FIRST_BYTE: u8 = 0;

    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        size: 0,
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let available_data = file_data.len();
    let required_min_offset = offset + (MAX_OBJ_SIZE * MIN_NUMBER_OF_OBJS);

    // Sanity check the amount of available data
    if is_offset_safe(available_data, required_min_offset, None) {
        // Detect endianness
        let endianness = match file_data[offset] {
            BIG_ENDIAN_FIRST_BYTE => Endianness::Big,
            _ => Endianness::Little,
        };

        // Determine the page
        if let Ok(page_size) = get_page_size(&file_data[offset..]) {
            // Determine the chunk size
            if let Ok(spare_size) = get_spare_size(&file_data[offset..], page_size, endianness) {
                // Get the total image size
                if let Ok(image_size) =
                    get_image_size(&file_data[offset..], page_size, spare_size, endianness)
                {
                    result.size = image_size;
                    result.description = format!(
                        "{}, {}, page size: {}, spare size: {}, image size: {} bytes",
                        result.description, endianness, page_size, spare_size, image_size
                    );
                    return Ok(result);
                }
            }
        }
    }

    Err(SignatureError)
}

/// Returns the detected page size used by the YAFFS image
fn get_page_size(file_data: &[u8]) -> Result<usize, SignatureError> {
    // Spare area is expected to start with these bytes, depending on endianness and ECC settings (YAFFS2 only)
    let spare_magics = [
        b"\x00\x00\x10\x00".to_vec(),
        b"\x00\x10\x00\x00".to_vec(),
        b"\xFF\xFF\x00\x00\x10\x00".to_vec(),
        b"\xFF\xFF\x00\x10\x00\x00".to_vec(),
    ];

    // Valid YAFFS page sizes
    let page_sizes = [512, 1024, 2048, 4096, 8192, 16384];

    // Loop through each page size looking for one that is immediately followed by a valid spare data entry.
    // This is only for YAFFS2! It will fail for YAFFS1 images.
    for page_size in &page_sizes {
        for spare_magic in &spare_magics {
            let start_spare_offset: usize = *page_size;
            let end_spare_offset: usize = start_spare_offset + spare_magic.len();

            if let Some(spare_magic_candidate) = file_data.get(start_spare_offset..end_spare_offset)
            {
                // If this spare data starts with the expected bytes, then we've guessed the page size correctly
                if spare_magic_candidate == *spare_magic {
                    return Ok(*page_size);
                }
            }
        }
    }

    // Nothing valid found
    Err(SignatureError)
}

/// Returns the detected spare size of the YAFFS image
fn get_spare_size(
    file_data: &[u8],
    page_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // Valid spare sizes
    let spare_sizes = [16, 32, 64, 128, 256, 512];

    // Loop through all spare sizes until a valid object header is found
    // This is only for YAFFS2! It will fail for YAFFS1 images.
    for spare_size in &spare_sizes {
        // If this spare size is correct, this should be the location of the next object header
        let next_obj_offset: usize = (page_size + *spare_size) * MIN_NUMBER_OF_OBJS;

        if let Some(obj_header_data) = file_data.get(next_obj_offset..) {
            // Attempt to parse this data as a YAFFS object header
            if parse_yaffs_obj_header(obj_header_data, endianness).is_ok() {
                return Ok(*spare_size);
            }
        }
    }

    // Nothing valid found
    Err(SignatureError)
}

/// Returns the total size of the image, in bytes
fn get_image_size(
    file_data: &[u8],
    page_size: usize,
    spare_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // Object type for files
    const FILE_TYPE: u32 = 1;

    let mut image_size: usize = 0;
    let mut next_obj_offset: usize = 0;
    let mut previous_obj_offset = None;

    let available_data = file_data.len();
    let block_size: usize = page_size + spare_size;

    // Loop through all available data, parsing YAFFS object headers
    while is_offset_safe(available_data, next_obj_offset, previous_obj_offset) {
        match file_data.get(next_obj_offset..) {
            None => {
                return Err(SignatureError);
            }
            Some(obj_data) => {
                // Parse and validate the object header
                match parse_yaffs_obj_header(obj_data, endianness) {
                    Err(_) => {
                        // This is not necessarily an error; could just be that there is trailing data after the YAFFS image
                        break;
                    }
                    Ok(header) => {
                        // Each object header takes up at least one block of data
                        let mut data_blocks: usize = 1;

                        // If this is a file, the file data wil take up additional data blocks
                        if header.obj_type == FILE_TYPE {
                            match get_file_block_count(obj_data, page_size, endianness) {
                                Err(e) => {
                                    return Err(e);
                                }
                                Ok(block_count) => {
                                    data_blocks += block_count;
                                }
                            }
                        }

                        // Update calculated image size and object header offsets
                        previous_obj_offset = Some(next_obj_offset);
                        image_size += data_blocks * block_size;
                        next_obj_offset = image_size;
                    }
                }
            }
        }
    }

    // Sanity check the calculated image size; should be large enough to fit MIN_NUMBER_OF_OBJS, but not extend past EOF
    if (block_size * MIN_NUMBER_OF_OBJS) < image_size && image_size <= available_data {
        return Ok(image_size);
    }

    Err(SignatureError)
}

/// Returns the number of data blocks used to store file data; this size is only valid for file type objects
fn get_file_block_count(
    obj_data: &[u8],
    page_size: usize,
    endianness: Endianness,
) -> Result<usize, SignatureError> {
    // parse_yaffs_file_header only parses a portion of the header that we need; the partial structure starts this many bytes into the object data
    const INFO_STRUCT_START: usize = 268;

    if let Some(file_header_data) = obj_data.get(INFO_STRUCT_START..) {
        // Parse the partial object header.
        if let Ok(file_info) = parse_yaffs_file_header(file_header_data, endianness) {
            // File data is broken up into blocks of page_size bytes
            let file_block_count: usize =
                ((file_info.file_size as f64) / (page_size as f64)).ceil() as usize;
            return Ok(file_block_count);
        }
    }

    Err(SignatureError)
}

/// Stores info about a YAFFS object
#[derive(Debug, Default, Clone)]
pub struct YAFFSObject {
    // All that is needed for now is the object type; this may be updated in the future as necessary
    pub obj_type: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct YAFFSHeader {
    obj_type: dyn_endian::U32,
    parent_id: dyn_endian::U32,
    name_checksum: dyn_endian::U16,
}

/// Partially parse a YAFFS object header
pub fn parse_yaffs_obj_header(
    header_data: &[u8],
    endianness: Endianness,
) -> Result<YAFFSObject, StructureError> {
    // The name checksum field is unused and should be 0xFFFF
    const UNUSED: u16 = 0xFFFF;

    // Allowed object types
    let allowed_types = [0, 1, 2, 3, 4, 5];

    // Parse the object header
    let (obj_header, _) = YAFFSHeader::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    // Validate that the header looks sane
    if allowed_types.contains(&obj_header.obj_type.get(endianness))
        && (obj_header.parent_id.get(endianness) > 0)
        && (obj_header.name_checksum.get(endianness) == UNUSED)
    {
        return Ok(YAFFSObject {
            obj_type: obj_header.obj_type.get(endianness),
        });
    }

    Err(StructureError)
}

/// Stores info about a YAFFS file header
#[derive(Debug, Default, Clone)]
pub struct YAFFSFileHeader {
    // Only this field is needed, for now. Struct may be updated in the future if necessary.
    pub file_size: usize,
}

// Second part of an object header (after the name field)
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct YAFFSFileHeaderBytes {
    mode: dyn_endian::U32,
    uid: dyn_endian::U32,
    gid: dyn_endian::U32,
    atime: dyn_endian::U32,
    mtime: dyn_endian::U32,
    ctime: dyn_endian::U32,
    file_size: dyn_endian::U32,
}

/// Partially parse a YAFFS file header
pub fn parse_yaffs_file_header(
    header_data: &[u8],
    endianness: Endianness,
) -> Result<YAFFSFileHeader, StructureError> {
    let (file_info, _) =
        YAFFSFileHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    Ok(YAFFSFileHeader {
        file_size: file_info.file_size.get(endianness) as usize,
    })
}

/// Describes how to run the unyaffs utility to extract YAFFS2 file systems
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::yaffs::yaffs2_extractor;
///
/// match yaffs2_extractor().utility {
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
pub fn yaffs2_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("unyaffs".to_string()),
        extension: "img".to_string(),
        arguments: vec![
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
            "yaffs-root".to_string(),
        ],
        exit_codes: vec![0],
        ..Default::default()
    }
}
