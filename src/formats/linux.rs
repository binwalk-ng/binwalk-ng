use crate::common::get_cstring;
use crate::extractors;
use crate::signatures::{CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError};
use aho_corasick::AhoCorasick;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable descriptions
pub const LINUX_ARM_ZIMAGE_DESCRIPTION: &str = "Linux ARM boot executable zImage";
pub const LINUX_BOOT_IMAGE_DESCRIPTION: &str = "Linux kernel boot image";
pub const LINUX_KERNEL_VERSION_DESCRIPTION: &str = "Linux kernel version";
pub const LINUX_ARM64_BOOT_IMAGE_DESCRIPTION: &str = "Linux kernel ARM64 boot image";

/// Magic bytes for a linux boot image
pub fn linux_boot_image_magic() -> Vec<Vec<u8>> {
    vec![b"\xb8\xc0\x07\x8e\xd8\xb8\x00\x90\x8e\xc0\xb9\x00\x01\x29\xf6\x29".to_vec()]
}

/// Kernel version string magic
pub fn linux_kernel_version_magic() -> Vec<Vec<u8>> {
    vec![b"Linux\x20version\x20".to_vec()]
}

/// Magic bytes for a linux ARM64 boot image
pub fn linux_arm64_boot_image_magic() -> Vec<Vec<u8>> {
    vec![b"\x00\x00\x00\x00\x00\x00\x00\x00ARMd".to_vec()]
}

/// Magic bytes for Linux ARM zImage
pub fn linux_arm_zimage_magic() -> Vec<Vec<u8>> {
    vec![b"\x18\x28\x6F\x01".to_vec(), b"\x01\x6F\x28\x18".to_vec()]
}

/// Validate a Linux ARM zImage
pub fn linux_arm_zimage_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    const MAGIC_OFFSET: usize = 36;

    let mut result = SignatureResult {
        confidence: CONFIDENCE_MEDIUM,
        description: LINUX_ARM_ZIMAGE_DESCRIPTION.to_string(),
        ..Default::default()
    };

    if offset >= MAGIC_OFFSET {
        result.offset = offset - MAGIC_OFFSET;

        if let Some(zimage_data) = file_data.get(result.offset..)
            && let Ok(zimage_header) = parse_linux_arm_zimage_header(zimage_data)
        {
            result.description = format!(
                "{}, {} endian",
                result.description, zimage_header.endianness
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate a linux ARM64 boot image signature
pub fn linux_arm64_boot_image_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Magic bytes are 56 bytes into the image
    const MAGIC_OFFSET: usize = 0x30;

    let mut result = SignatureResult {
        confidence: CONFIDENCE_MEDIUM,
        description: LINUX_ARM64_BOOT_IMAGE_DESCRIPTION.to_string(),
        ..Default::default()
    };

    if offset >= MAGIC_OFFSET {
        // Set the real starting offset
        result.offset = offset - MAGIC_OFFSET;

        // Parse and validate the header data
        if let Ok(image_header) = parse_linux_arm64_boot_image_header(&file_data[result.offset..]) {
            result.size = image_header.header_size;
            result.description = format!(
                "{}, {} endian, effective image size: {} bytes",
                result.description, image_header.endianness, image_header.image_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate a linux boot image signature
pub fn linux_boot_image_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // There should be the string "!HdrS" 514 bytes from the start of the magic signature
    const HDRS_OFFSET: usize = 514;
    const HDRS_EXPECTED_VALUE: &str = "!HdrS";

    let result = SignatureResult {
        description: LINUX_BOOT_IMAGE_DESCRIPTION.to_string(),
        offset,
        size: 0,
        ..Default::default()
    };

    // Calculate start and end offset of the expected !HdrS string
    let hdrs_start: usize = offset + HDRS_OFFSET;
    let hdrs_end: usize = hdrs_start + HDRS_EXPECTED_VALUE.len();

    if let Some(hdrs_bytes) = file_data.get(hdrs_start..hdrs_end) {
        // Get the string that should equal HDRS_EXPECTED_VALUE
        if let Ok(actual_hdrs_value) = String::from_utf8(hdrs_bytes.to_vec()) {
            // Validate that the hdrs string matches
            if actual_hdrs_value == HDRS_EXPECTED_VALUE {
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Validate a linux kernel version signature and detect if a symbol table is present
pub fn linux_kernel_version_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Kernel version string format is expected to be something like:
    // "Linux version 4.9.241 (root@server2) (gcc version 10.0.1 (OpenWrt GCC 10.0.1 r12423-0493d57e04) ) #755 SMP Wed Nov 4 03:59:02 +03 2020\n"
    const PERIOD: u8 = 0x2E;
    const NEW_LINE: &str = "\n";
    const AMPERSAND: &str = "@";
    const PERIOD_OFFSET_1: usize = 15;
    const PERIOD_OFFSET_2: usize = 17;
    const PERIOD_OFFSET_3: usize = 18;
    const MIN_FILE_SIZE: usize = 100 * 1024;
    const MIN_VERSION_STRING_LENGTH: usize = 75;
    const GCC_VERSION_STRING: &str = "gcc ";

    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    let file_size = file_data.len();

    // Sanity check the size of the file; this automatically eliminates small text files that might match the magic bytes
    if file_size > MIN_FILE_SIZE {
        // Get the kernel version string
        let kernel_version_string = get_cstring(&file_data[offset..]);

        // Sanity check the length of the version string
        if kernel_version_string.len() > MIN_VERSION_STRING_LENGTH {
            // Make sure the string includes the GCC version string too
            if kernel_version_string.contains(GCC_VERSION_STRING) {
                // Make sure the string includes an ampersand
                if kernel_version_string.contains(AMPERSAND) {
                    // The kernel version string should end with a new line
                    if kernel_version_string.ends_with(NEW_LINE) {
                        let kv_bytes = kernel_version_string.as_bytes();

                        // Make sure the linux kernel version has periods at the expected locations
                        if kv_bytes[PERIOD_OFFSET_1] == PERIOD
                            && (kv_bytes[PERIOD_OFFSET_2] == PERIOD
                                || kv_bytes[PERIOD_OFFSET_3] == PERIOD)
                        {
                            // Try to locate a Linux kernel symbol table
                            let symtab_present = has_linux_symbol_table(file_data);

                            // If a symbol table is present, assume the entire file is a raw Linux kernel.
                            // This is necessary for vmlinux-to-elf extraction.
                            // Otherwise just report the kernel version string and decline extraction.
                            if symtab_present {
                                result.offset = 0;
                                result.size = file_data.len();
                            } else {
                                result.size = kernel_version_string.len();
                                result.extraction_declined = true;
                            }

                            // Report the result
                            result.description = format!(
                                "{}, has symbol table: {}",
                                kernel_version_string.trim(),
                                symtab_present
                            );
                            return Ok(result);
                        }
                    }
                }
            }
        }
    }

    Err(SignatureError)
}

/// Searches the file data for a linux symbol table
fn has_linux_symbol_table(file_data: &[u8]) -> bool {
    // Same magic bytes that vmlinux-to-elf searches for
    let symtab_magic = vec![b"\x000\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00"];

    let grep = AhoCorasick::new(symtab_magic).unwrap();

    // Grep for matches on the Linux symbol table magic bytes, there should be only one match
    grep.find_overlapping_iter(file_data).count() == 1
}

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
#[derive(Debug, Clone)]
pub struct LinuxARMzImageHeader {
    pub endianness: Endianness,
}

/// Parses a Linux ARM zImage header
pub fn parse_linux_arm_zimage_header(
    zimage_data: &[u8],
) -> Result<LinuxARMzImageHeader, StructureError> {
    const NOP_LE: u32 = 0xE1A00000;
    const NOP_BE: u32 = 0x0000A0E1;

    let (zimage_header, _) =
        zImageHeader::ref_from_prefix(zimage_data).map_err(|_| StructureError)?;

    let first = zimage_header.noops.first().ok_or(StructureError)?;
    if !zimage_header.noops.iter().all(|x| x == first) {
        return Err(StructureError);
    }
    match first.get() {
        NOP_LE => Ok(LinuxARMzImageHeader {
            endianness: Endianness::Little,
        }),
        NOP_BE => Ok(LinuxARMzImageHeader {
            endianness: Endianness::Big,
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

    let mut result = LinuxARM64BootHeader::default();

    let (boot_image_header, _) =
        BootImageHeader::ref_from_prefix(img_data).map_err(|_| StructureError)?;

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

/// Describes how to run the vmlinux-to-elf utility to convert raw kernel images to ELF files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::linux::linux_kernel_extractor;
///
/// match linux_kernel_extractor().utility {
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
pub fn linux_kernel_extractor() -> extractors::Extractor {
    extractors::Extractor {
        do_not_recurse: true,
        utility: extractors::ExtractorType::External("vmlinux-to-elf".to_string()),
        extension: "bin".to_string(),
        arguments: vec![
            // Input file
            extractors::SOURCE_FILE_PLACEHOLDER.to_string(),
            // Output file
            "linux_kernel.elf".to_string(),
        ],
        exit_codes: vec![0],
    }
}
