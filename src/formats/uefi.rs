use crate::extractors;
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable descriptions
pub const VOLUME_DESCRIPTION: &str = "UEFI PI firmware volume";
pub const CAPSULE_DESCRIPTION: &str = "UEFI capsule image";

/// UEFI volume magic bytes
pub fn uefi_volume_magic() -> Vec<Vec<u8>> {
    vec![b"_FVH".to_vec()]
}

/// UEFI capsule GUIDs
pub fn uefi_capsule_magic() -> Vec<Vec<u8>> {
    vec![
        b"\xBD\x86\x66\x3B\x76\x0D\x30\x40\xB7\x0E\xB5\x51\x9E\x2F\xC5\xA0".to_vec(), // EFI capsule GUID
        b"\x8B\xA6\x3C\x4A\x23\x77\xFB\x48\x80\x3D\x57\x8C\xC1\xFE\xC4\x4D".to_vec(), // EFI2 capsule GUID
        b"\xB9\x82\x91\x53\xB5\xAB\x91\x43\xB6\x9A\xE3\xA9\x43\xF7\x2F\xCC".to_vec(), // UEFI capsule GUID
    ]
}

/// Validates UEFI volume signatures
pub fn uefi_volume_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // The magic signature begins this many bytes from the start of the UEFI volume
    const UEFI_MAGIC_OFFSET: usize = 40;

    let mut result = SignatureResult {
        size: 0,
        offset: 0,
        description: VOLUME_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Volume actually starts UEFI_MAGIC_OFFSET bytes before the magic bytes; make sure there are at least that many bytes preceeding the magic offset
    if offset >= UEFI_MAGIC_OFFSET {
        // Set the correct starting offset for this volume
        result.offset = offset - UEFI_MAGIC_OFFSET;

        // Parse the volume header
        if let Ok(uefi_volume_header) = parse_uefi_volume_header(&file_data[result.offset..]) {
            // Make sure the volume size is sane
            if file_data.len() >= (result.offset + uefi_volume_header.volume_size) {
                result.size = uefi_volume_header.volume_size;
                result.description = format!(
                    "{}, header CRC: {:#X}, header size: {} bytes, total size: {} bytes",
                    result.description,
                    uefi_volume_header.header_crc as u32,
                    uefi_volume_header.header_size,
                    uefi_volume_header.volume_size
                );
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Validates UEFI capsule signatures
pub fn uefi_capsule_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        description: CAPSULE_DESCRIPTION.to_string(),
        offset,
        size: 0,
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let available_data: usize = file_data.len() - offset;

    if let Ok(capsule_header) = parse_uefi_capsule_header(&file_data[offset..]) {
        // Sanity check on header total size field
        if capsule_header.total_size >= available_data {
            result.size = capsule_header.total_size;
            result.description = format!(
                "{}, header size: {} bytes, total size: {} bytes",
                result.description, capsule_header.header_size, capsule_header.total_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores info about a UEFI volume header
#[derive(Debug, Default, Clone)]
pub struct UEFIVolumeHeader {
    pub header_crc: u16,
    pub header_size: usize,
    pub volume_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UEFIPiHeader {
    volume_size: zerocopy::U64<LE>,
    magic: zerocopy::U32<LE>,
    attributes: zerocopy::U32<LE>,
    header_size: zerocopy::U16<LE>,
    header_crc: zerocopy::U16<LE>,
    extended_header_offset: zerocopy::U16<LE>,
    reserved: u8,
    revision: u8,
}

/// Parse a UEFI volume header
pub fn parse_uefi_volume_header(uefi_data: &[u8]) -> Result<UEFIVolumeHeader, StructureError> {
    // The revision field must be 1 or 2
    let valid_revisions = [1, 2];

    // Parse the volume header
    let (uefi_volume_header, _) =
        UEFIPiHeader::ref_from_prefix(uefi_data).map_err(|_| StructureError)?;
    // Make sure the header size is sane (must be smaller than the total volume size)
    if (uefi_volume_header.header_size.get() as u64) < uefi_volume_header.volume_size.get() {
        // The reserved field *must* be 0
        if uefi_volume_header.reserved == 0 {
            // The revision number must be 1 or 2
            if valid_revisions.contains(&uefi_volume_header.revision) {
                return Ok(UEFIVolumeHeader {
                    // TODO: Validate UEFI header CRC
                    header_crc: uefi_volume_header.header_crc.get(),
                    header_size: uefi_volume_header.header_size.get() as usize,
                    volume_size: uefi_volume_header.volume_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}

/// Stores info about a UEFI capsule header
#[derive(Debug, Default, Clone)]
pub struct UEFICapsuleHeader {
    pub total_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UEFICapsuleHeaderBytes {
    guid_p1: zerocopy::U64<LE>,
    guid_p2: zerocopy::U64<LE>,
    header_size: zerocopy::U32<LE>,
    flags: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
}

/// Parse  UEFI capsule header
pub fn parse_uefi_capsule_header(uefi_data: &[u8]) -> Result<UEFICapsuleHeader, StructureError> {
    // Parse the capsule header
    let (capsule_header, _) =
        UEFICapsuleHeaderBytes::ref_from_prefix(uefi_data).map_err(|_| StructureError)?;

    // Sanity check on header and total size fields
    if capsule_header.header_size.get() < capsule_header.total_size.get() {
        return Ok(UEFICapsuleHeader {
            total_size: capsule_header.total_size.get() as usize,
            header_size: capsule_header.header_size.get() as usize,
        });
    }

    Err(StructureError)
}

/// Describes how to run the uefi-firmware-parser utility to extract UEFI images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::uefi::uefi_extractor;
///
/// match uefi_extractor().utility {
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
pub fn uefi_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::External("uefi-firmware-parser".to_string()),
        extension: "img".to_string(),
        arguments: vec![
            "-o.".to_string(), // Output to the current working directory
            "-q".to_string(),  // Don't print verbose output
            "-e".to_string(),  // Extract
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
        ],
        exit_codes: vec![0],
        /*
         * This extractor recursively pulls out all the UEFI stuff *and* leaves raw copies of the extracted data on disk.
         * Recursing into this data would result in double extractions for no good reason.
         */
        do_not_recurse: true,
    }
}
