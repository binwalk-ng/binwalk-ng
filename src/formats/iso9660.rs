use crate::extractors;
use crate::formats::sevenzip::sevenzip_extractor;
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "ISO9660 primary volume";

/// ISOs start with these magic bytes
pub fn iso_magic() -> Vec<Vec<u8>> {
    vec![b"\x01CD001\x01\x00".to_vec()]
}

/// Validate ISO signatures
pub fn iso_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Offset from the beginning of the ISO image to the magic bytes
    const ISO_MAGIC_OFFSET: usize = 32768;

    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // We need at least ISO_MAGIC_OFFSET bytes to exist before the magic match offset
    if offset >= ISO_MAGIC_OFFSET {
        // Calculate the actual starting offset of the ISO
        result.offset = offset - ISO_MAGIC_OFFSET;

        // Parse the header, if parsing succeeds assume it's valid
        if let Ok(iso_header) = parse_iso_header(&file_data[result.offset..]) {
            result.size = iso_header.image_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store useful ISO info
#[derive(Debug, Default, Clone)]
pub struct ISOHeader {
    pub image_size: usize,
}

// Partial ISO header structure, enough to reasonably validate that this is not a false positive and to calculate the total ISO size
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ISOHeaderBytes {
    unused1: [u8; 8],
    volume_size_1: zerocopy::U32<LE>,
    volume_size_2: zerocopy::U32<BE>,
    unused2: [u8; 32],
    set_size_1: zerocopy::U16<LE>,
    set_size_2: zerocopy::U16<BE>,
    sequence_number_1: zerocopy::U16<LE>,
    sequence_number_2: zerocopy::U16<BE>,
    block_size_1: zerocopy::U16<LE>,
    block_size_2: zerocopy::U16<BE>,
    path_table_size_1: zerocopy::U32<LE>,
    path_table_size_2: zerocopy::U32<BE>,
}

/// Partially parses an ISO header
pub fn parse_iso_header(iso_data: &[u8]) -> Result<ISOHeader, StructureError> {
    // Offset from the beginning of the ISO image to the start of iso_structure
    const ISO_STRUCT_START: usize = 32840;

    if let Some(iso_header_data) = iso_data.get(ISO_STRUCT_START..) {
        // Parse the ISO header
        let (iso_header, _) =
            ISOHeaderBytes::ref_from_prefix(iso_header_data).map_err(|_| StructureError)?;

        // Make sure all the unused fields are, in fact, unused
        if iso_header
            .unused1
            .iter()
            .chain(&iso_header.unused2)
            .all(|&b| b == 0)
        {
            // Make sure all the identical, but byte-swapped, fields agree.
            if iso_header.set_size_1 == iso_header.set_size_2.get()
                && iso_header.block_size_1 == iso_header.block_size_2.get()
                && iso_header.volume_size_1 == iso_header.volume_size_2.get()
                && iso_header.sequence_number_1 == iso_header.sequence_number_2.get()
                && iso_header.path_table_size_1 == iso_header.path_table_size_2.get()
            {
                return Ok(ISOHeader {
                    image_size: iso_header.volume_size_1.get() as usize
                        * iso_header.block_size_1.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}

/// Describes how to run the 7z utility to extract ISO images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::iso9660::iso9660_extractor;
///
/// match iso9660_extractor().utility {
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
pub fn iso9660_extractor() -> extractors::Extractor {
    // Same as the normal 7z extractor, but give the carved file an ISO file extension.
    // The file extension matters, and 7z doesn't handle some ISO sub-formats correctly if the file extension is not '.iso'.
    let mut extractor = sevenzip_extractor();
    extractor.extension = "iso".to_string();
    extractor
}
