use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store linux ARM64 boot image header info
#[derive(Debug, Default, Clone)]
pub struct LinuxARM64BootHeader {
    pub header_size: usize,
    pub image_size: usize,
    pub endianness: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct zImageHeader {
    noops: [zerocopy::U32<LE>; 8],
}

// https://www.kernel.org/doc/Documentation/arm64/booting.txt
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BootImageHeader {
    code0: zerocopy::U32<LE>,
    code1: zerocopy::U32<LE>,
    image_load_offset: zerocopy::U64<LE>,
    image_size: zerocopy::U64<LE>,
    flags: zerocopy::U64<LE>,
    reserved1: zerocopy::U64<LE>,
    reserved2: zerocopy::U64<LE>,
    reserved3: zerocopy::U64<LE>,
    magic: zerocopy::U32<LE>,
    pe_offset: zerocopy::U32<LE>,
}

/// Struct to store Linux ARM zImage info
#[derive(Debug, Default, Clone)]
pub struct LinuxARMzImageHeader {
    pub endianness: String,
}

/// Parses a Linux ARM zImage header
pub fn parse_linux_arm_zimage_header(
    zimage_data: &[u8],
) -> Result<LinuxARMzImageHeader, StructureError> {
    const NOP_LE: u32 = 0xE1A00000;
    const NOP_BE: u32 = 0x0000A0E1;

    let zimage_header = zImageHeader::ref_from_bytes(zimage_data).map_err(|_| StructureError)?;

    let first = zimage_header.noops.first().ok_or(StructureError)?;
    if !zimage_header.noops.iter().all(|x| x == first) {
        return Err(StructureError);
    }
    match first.get() {
        NOP_LE => Ok(LinuxARMzImageHeader {
            endianness: "little".to_string(),
        }),
        NOP_BE => Ok(LinuxARMzImageHeader {
            endianness: "big".to_string(),
        }),
        _ => Err(StructureError),
    }
}

/// Parses a linux ARM64 boot header
pub fn parse_linux_arm64_boot_image_header(
    img_data: &[u8],
) -> Result<LinuxARM64BootHeader, StructureError> {
    const PE: &[u8] = b"PE";
    const FLAGS_RESERVED_MASK: u64 =
        0b11111111_11111111_11111111_11111111_11111111_11111111_11111111_11110000;
    const FLAGS_ENDIAN_MASK: u64 = 1;
    const BIG_ENDIAN: u64 = 1;

    let mut result = LinuxARM64BootHeader {
        ..Default::default()
    };

    let boot_image_header =
        BootImageHeader::ref_from_bytes(img_data).map_err(|_| StructureError)?;

    // Parse the header

    // Make sure the reserved fields are not set
    if !(boot_image_header.reserved1.get() == 0
        && boot_image_header.reserved2.get() == 0
        && boot_image_header.reserved3.get() == 0)
    {
        return Err(StructureError);
    }
    // Start and end of PE signature
    let pe_start = boot_image_header.pe_offset.get() as usize;
    let pe_end = pe_start + PE.len();

    // Get the data pointed to by the pe_offset header field
    if let Some(pe_data) = img_data.get(pe_start..pe_end) {
        // There should be a PE header here
        if pe_data != PE {
            return Err(StructureError);
        }
        // Make sure the reserved flag bits are not set
        if (boot_image_header.flags.get() & FLAGS_RESERVED_MASK) == 0 {
            // Determine the endianness from the flags field
            if (boot_image_header.flags.get() & FLAGS_ENDIAN_MASK) == BIG_ENDIAN {
                result.endianness = "big".to_string();
            } else {
                result.endianness = "little".to_string();
            }

            // Report the kernel image and header sizes
            result.image_size = boot_image_header.image_size.get() as usize;
            result.header_size = std::mem::size_of::<BootImageHeader>();

            return Ok(result);
        }
    }

    Err(StructureError)
}
