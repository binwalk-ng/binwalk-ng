//! Matter OTA (Over-The-Air) firmware update image format.
//!
//! Defined in §11.21 of the [Matter Core Specification][1]. All multibyte fields are little-endian.
//!
//! [1]: https://csa-iot.org/wp-content/uploads/2024/11/24-27349-006_Matter-1.4-Core-Specification.pdf

use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

mod tags {
    pub const VENDOR_ID: u8 = 0;
    pub const PRODUCT_ID: u8 = 1;
    pub const SOFTWARE_VERSION_STRING: u8 = 3;
    pub const PAYLOAD_SIZE: u8 = 4;
    pub const IMAGE_DIGEST_TYPE: u8 = 8;
    pub const IMAGE_DIGEST: u8 = 9;
}

/// Human readable description
pub const DESCRIPTION: &str = "Matter OTA firmware";

/// Matter OTA firmware images always start with these bytes
pub fn matter_ota_magic() -> Vec<Vec<u8>> {
    vec![b"\x1e\xf1\xee\x1b".to_vec()]
}

/// Validates the Matter OTA header
pub fn matter_ota_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    if let Ok(ota_header) = parse_matter_ota_header(&file_data[offset..]) {
        let result = SignatureResult {
            offset,
            size: ota_header.header_size,
            confidence: CONFIDENCE_HIGH,
            description: format!(
                "{}, total size: {} bytes, tlv header size: {} bytes, vendor id: 0x{:x}, product id: 0x{:x}, version: {}, payload size: {} bytes, digest type: {}, payload digest: {}",
                DESCRIPTION,
                ota_header.total_size,
                ota_header.header_size,
                ota_header.vendor_id,
                ota_header.product_id,
                ota_header.version,
                ota_header.payload_size,
                ota_header.image_digest_type,
                ota_header.image_digest,
            ),
            ..Default::default()
        };

        return Ok(result);
    }
    Err(SignatureError)
}

/// Struct to store Matter OTA header info
#[derive(Debug, Default, Clone)]
pub struct MatterOTAHeader {
    pub total_size: usize,
    pub header_size: usize,
    pub vendor_id: usize,
    pub product_id: usize,
    pub version: String,
    pub payload_size: usize,
    pub image_digest_type: usize,
    pub image_digest: String,
}

#[derive(Debug)]
enum Value<'a> {
    Struct,
    EndOfContainer,
    Unsigned(usize),
    String(&'a str),
    OctetString(&'a [u8]),
}

#[derive(Debug)]
struct Element<'a> {
    tag: Option<u8>,
    value: Value<'a>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct OtaHeaderBytes {
    magic: zerocopy::U32<LE>,
    total_size: zerocopy::U64<LE>,
    header_size: zerocopy::U32<LE>,
}

/// Parse a Matter OTA firmware header
pub fn parse_matter_ota_header(ota_data: &[u8]) -> Result<MatterOTAHeader, StructureError> {
    let (ota_header, rest) =
        OtaHeaderBytes::ref_from_prefix(ota_data).map_err(|_| StructureError)?;
    let total_size = ota_header.total_size.get() as usize;
    let header_size = ota_header.header_size.get() as usize;

    let (mut header_data, _payload) = rest.split_at_checked(header_size).ok_or(StructureError)?;

    let mut result = MatterOTAHeader {
        total_size,
        header_size,
        ..Default::default()
    };

    while !header_data.is_empty() {
        let element = parse_tlv_element(&mut header_data).ok_or(StructureError)?;
        // Ignore anonymous (non tagged) values
        let Some(tag) = element.tag else { continue };
        match tag {
            tags::VENDOR_ID => {
                let Value::Unsigned(vendor_id) = element.value else {
                    return Err(StructureError);
                };
                result.vendor_id = vendor_id;
            }
            tags::PRODUCT_ID => {
                let Value::Unsigned(product_id) = element.value else {
                    return Err(StructureError);
                };
                result.product_id = product_id;
            }
            tags::SOFTWARE_VERSION_STRING => {
                let Value::String(version_str) = element.value else {
                    return Err(StructureError);
                };
                result.version = String::from(version_str);
            }
            tags::PAYLOAD_SIZE => {
                let Value::Unsigned(payload_size) = element.value else {
                    return Err(StructureError);
                };
                result.payload_size = payload_size;
            }
            tags::IMAGE_DIGEST_TYPE => {
                let Value::Unsigned(image_digest_type) = element.value else {
                    return Err(StructureError);
                };
                result.image_digest_type = image_digest_type;
            }
            tags::IMAGE_DIGEST => {
                let Value::OctetString(image_digest) = element.value else {
                    return Err(StructureError);
                };
                result.image_digest = hex::encode(image_digest);
            }
            // Ignore other fields
            _ => {}
        }
    }

    // Sanity check
    if (result.payload_size + size_of::<OtaHeaderBytes>() + header_size) == total_size {
        return Ok(result);
    }

    Err(StructureError)
}

fn parse_tlv_element<'a>(data: &mut &'a [u8]) -> Option<Element<'a>> {
    let control_octet = *data.split_off_first()?;

    let element_type = control_octet & 0x1f;
    let tag_control = control_octet >> 5;

    // Parse numerical tag. Only supports anonymous fields and fields with a one byte tag
    let tag = match tag_control {
        0 => None, // Anonymous field
        1 => Some(*data.split_off_first()?),
        _ => return None,
    };

    let element = match element_type {
        0b1_0101 => {
            // Struct container
            Element {
                tag,
                value: Value::Struct,
            }
        }
        0b1_1000 => {
            // End of container
            Element {
                tag,
                value: Value::EndOfContainer,
            }
        }
        0b0_0100..=0b0_0111 => {
            // Unsigned integer
            let value = split_off_variable_integer(data, element_type)?;
            Element {
                tag,
                value: Value::Unsigned(value),
            }
        }
        0b0_1100..=0b0_1111 => {
            // UTF-8 String
            let len = split_off_variable_integer(data, element_type)?;
            let string_data = data.split_off(..len)?;
            let string = std::str::from_utf8(string_data).ok()?;
            Element {
                tag,
                value: Value::String(string),
            }
        }
        0b1_0000..=0b1_0011 => {
            let len = split_off_variable_integer(data, element_type)?;
            let octet_data = data.split_off(..len)?;
            Element {
                tag,
                value: Value::OctetString(octet_data),
            }
        }
        _ => return None, // Other types are not implemented, but not necessary for header parsing
    };
    Some(element)
}

fn split_off_variable_integer(data: &mut &[u8], element_type: u8) -> Option<usize> {
    let mut res = [0; 8];

    let len = 1 << (element_type & 0x3);
    res[..len].copy_from_slice(data.split_off(..len)?);

    Some(usize::from_le_bytes(res))
}

/// Defines the internal extractor function for extracting a Matter OTA firmware payload */
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::matter_ota::matter_ota_extractor;
///
/// match matter_ota_extractor().utility {
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
pub fn matter_ota_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_matter_ota),
        ..Default::default()
    }
}

/// Matter OTA firmware payload extractor
pub fn extract_matter_ota(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "matter_payload.bin";

    let mut result = ExtractionResult::default();

    if let Ok(ota_header) = parse_matter_ota_header(&file_data[offset..]) {
        let total_header_size = size_of::<OtaHeaderBytes>() + ota_header.header_size;

        result.success = true;
        result.size = Some(ota_header.total_size);

        let payload_start = offset + total_header_size;
        let payload_end = offset + total_header_size + ota_header.payload_size;

        // Sanity check reported payload size and get the payload data
        if let Some(payload_data) = file_data.get(payload_start..payload_end)
            && let Some(output_directory) = output_directory
        {
            let chroot = Chroot::new(output_directory);
            result.success = chroot.carve_file(OUTFILE_NAME, payload_data, 0, payload_data.len());
        }
    }

    result
}
