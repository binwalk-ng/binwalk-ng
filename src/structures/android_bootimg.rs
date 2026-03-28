use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};
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
