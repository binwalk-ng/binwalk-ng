use crate::signatures::{CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "Android boot image";

/// Android boot images always start with these bytes
pub fn android_bootimg_magic() -> Vec<Vec<u8>> {
    vec![b"ANDROID!".to_vec()]
}

/// Validates the android boot image header
pub fn android_bootimg_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    if let Ok(bootimg_header) = parse_android_bootimg_header(&file_data[offset..]) {
        if offset == 0 {
            result.confidence = CONFIDENCE_MEDIUM;
        }

        result.description = format!(
            "{}, kernel size: {} bytes, kernel load address: {:#X}, ramdisk size: {} bytes, ramdisk load address: {:#X}",
            result.description,
            bootimg_header.kernel_size,
            bootimg_header.kernel_load_address,
            bootimg_header.ramdisk_size,
            bootimg_header.ramdisk_load_address,
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Struct to store Android boot image header info
#[derive(Debug, Default, Clone)]
pub struct AndroidBootImageHeader {
    pub kernel_size: u32,
    pub ramdisk_size: u32,
    pub kernel_load_address: u32,
    pub ramdisk_load_address: u32,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AndroidBootImageHeaderBytes {
    magic: zerocopy::U64<LE>,
    kernel_size: zerocopy::U32<LE>,
    kernel_load_addr: zerocopy::U32<LE>,
    ramdisk_size: zerocopy::U32<LE>,
    ramdisk_load_addr: zerocopy::U32<LE>,
}

/// Parses an Android boot image header
pub fn parse_android_bootimg_header(
    bootimg_data: &[u8],
) -> Result<AndroidBootImageHeader, StructureError> {
    let (bootimg_header, _) =
        AndroidBootImageHeaderBytes::ref_from_prefix(bootimg_data).map_err(|_| StructureError)?;

    Ok(AndroidBootImageHeader {
        kernel_size: bootimg_header.kernel_size.get(),
        kernel_load_address: bootimg_header.kernel_load_addr.get(),
        ramdisk_size: bootimg_header.ramdisk_size.get(),
        ramdisk_load_address: bootimg_header.ramdisk_load_addr.get(),
    })
}
