use crate::common::{crc32, epoch_to_string, get_cstring};
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "uImage firmware image";

/// uImage magic bytes
pub fn uimage_magic() -> Vec<Vec<u8>> {
    vec![
        // Standard uImage magic
        b"\x27\x05\x19\x56".to_vec(),
        // Alternate uImage magic (https://git.openwrt.org/?p=openwrt/openwrt.git;a=commitdiff;h=01a1e21863aa30c7a2c252ff06b9aef0cf957970)
        b"OKLI".to_vec(),
    ]
}

/// Validates uImage signatures
pub fn uimage_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        size: 0,
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run
    let dry_run = extract_uimage(file_data, offset, None);

    if dry_run.success
        && let Some(uimage_size) = dry_run.size
    {
        // Extraction dry-run ok, parse the header to display some useful info
        if let Ok(uimage_header) = parse_uimage_header(&file_data[offset..]) {
            result.size = uimage_size;
            // Decline extraction if the header CRC does not match, or if the reported data size is 0
            result.extraction_declined =
                !uimage_header.header_crc_valid || uimage_header.data_size == 0;
            result.description = format!(
                "{}, header size: {} bytes, data size: {} bytes, compression: {}, CPU: {}, OS: {}, image type: {}, load address: {:#X}, entry point: {:#X}, creation time: {}, image name: \"{}\"",
                result.description,
                uimage_header.header_size,
                uimage_header.data_size,
                uimage_header.compression_type,
                uimage_header.cpu_type,
                uimage_header.os_type,
                uimage_header.image_type,
                uimage_header.load_address,
                uimage_header.entry_point_address,
                epoch_to_string(uimage_header.timestamp as u32),
                uimage_header.name
            );
            // If the header CRC is invalid, adjust the reported confidence level and report the checksum mis-match
            if !uimage_header.header_crc_valid {
                // If the uImage header was otherwise valid and starts at file offset 0 then we're still fairly confident in the result
                if result.offset == 0 {
                    result.confidence = CONFIDENCE_MEDIUM;
                } else {
                    result.confidence = CONFIDENCE_LOW;
                }

                result.description = format!("{}, invalid checksum", result.description);
            }

            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores info about a uImage header
#[derive(Debug, Default, Clone)]
pub struct UImageHeader {
    pub header_size: usize,
    pub name: String,
    pub data_size: usize,
    pub data_checksum: u32,
    pub load_address: usize,
    pub entry_point_address: usize,
    pub timestamp: usize,
    pub compression_type: String,
    pub cpu_type: String,
    pub os_type: String,
    pub image_type: String,
    pub header_crc_valid: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UImageHeaderBytes {
    magic: zerocopy::U32<BE>,
    header_crc: zerocopy::U32<BE>,
    creation_timestamp: zerocopy::U32<BE>,
    data_size: zerocopy::U32<BE>,
    load_address: zerocopy::U32<BE>,
    entry_point_address: zerocopy::U32<BE>,
    data_crc: zerocopy::U32<BE>,
    os_type: u8,
    cpu_type: u8,
    image_type: u8,
    compression_type: u8,
}

/// Pase a uImage header
pub fn parse_uimage_header(uimage_data: &[u8]) -> Result<UImageHeader, StructureError> {
    const UIMAGE_HEADER_SIZE: usize = 64;
    const UIMAGE_NAME_OFFSET: usize = 32;

    // Parse the first half of the header
    let (uimage_header, _) =
        UImageHeaderBytes::ref_from_prefix(uimage_data).map_err(|_| StructureError)?;

    // Sanity check header fields (None becomes Err(StructureError) and returns)
    let os_type = match uimage_header.os_type {
        1 => "OpenBSD",
        2 => "NetBSD",
        3 => "FreeBSD",
        4 => "4.4BSD",
        5 => "Linux",
        6 => "SVR4",
        7 => "Esix",
        8 => "Solaris",
        9 => "Irix",
        10 => "SCO",
        11 => "Dell",
        12 => "NCR",
        13 => "LynxOS",
        14 => "VxWorks",
        15 => "pSOS",
        16 => "QNX",
        17 => "Firmware",
        18 => "RTEMS",
        19 => "ARTOS",
        20 => "Unity OS",
        21 => "INTEGRITY",
        22 => "OSE",
        23 => "Plan 9",
        24 => "OpenRTOS",
        25 => "ARM Trusted Firmware",
        26 => "Trusted Execution Environment",
        27 => "OpenSBI",
        28 => "EFI Firmware",
        29 => "ELF Image",
        _ => return Err(StructureError),
    };
    let cpu_type = match uimage_header.cpu_type {
        1 => "Alpha",
        2 => "ARM",
        3 => "Intel x86",
        4 => "IA64",
        5 => "MIPS32",
        6 => "MIPS64",
        7 => "PowerPC",
        8 => "IBM S390",
        10 => "SuperH",
        11 => "Sparc",
        12 => "Sparc64",
        13 => "M68K",
        14 => "Nios-32",
        15 => "MicroBlaze",
        16 => "Nios-II",
        17 => "Blackfin",
        18 => "AVR32",
        19 => "ST200",
        20 => "Sandbox",
        21 => "NDS32",
        22 => "OpenRISC",
        23 => "ARM64",
        24 => "ARC",
        25 => "x86-64",
        26 => "Xtensa",
        27 => "RISC-V",
        _ => return Err(StructureError),
    };
    let image_type = match uimage_header.image_type {
        1 => "Standalone Program",
        2 => "OS Kernel Image",
        3 => "RAMDisk Image",
        4 => "Multi-File Image",
        5 => "Firmware Image",
        6 => "Script file",
        7 => "Filesystem Image",
        8 => "Binary Flat Device Tree Blob",
        9 => "Kirkwood Boot Image",
        10 => "Freescale IMXBoot Image",
        11 => "Davinci UBL Image",
        12 => "TI OMAP Config Header Image",
        13 => "TI Davinci AIS Image",
        14 => "OS Kernel Image",
        15 => "Freescale PBL Boot Image",
        16 => "Freescale MXSBoot Image",
        17 => "TI Keystone GPHeader Image",
        18 => "ATMEL ROM bootable Image",
        19 => "Altera SOCFPGA CV/AV Preloader",
        20 => "x86 setup.bin Image",
        21 => "x86 setup.bin Image",
        22 => "A list of typeless images",
        23 => "Rockchip Boot Image",
        24 => "Rockchip SD card",
        25 => "Rockchip SPI image",
        26 => "Xilinx Zynq Boot Image",
        27 => "Xilinx ZynqMP Boot Image",
        28 => "Xilinx ZynqMP Boot Image (bif)",
        29 => "FPGA Image",
        30 => "VYBRID .vyb Image",
        31 => "Trusted Execution Environment OS Image",
        32 => "Firmware Image with HABv4 IVT",
        33 => "TI Power Management Micro-Controller Firmware",
        34 => "STMicroelectronics STM32 Image",
        35 => "Altera SOCFPGA A10 Preloader",
        36 => "MediaTek BootROM loadable Image",
        37 => "Freescale IMX8MBoot Image",
        38 => "Freescale IMX8Boot Image",
        39 => "Coprocessor Image for remoteproc",
        40 => "Allwinner eGON Boot Image",
        41 => "Allwinner TOC0 Boot Image",
        42 => "Binary Flat Device Tree Blob in a Legacy Image",
        43 => "Renesas SPKG image",
        44 => "StarFive SPL image",
        _ => return Err(StructureError),
    };
    let compression_type = match uimage_header.compression_type {
        0 => "none",
        1 => "gzip",
        2 => "bzip2",
        3 => "lzma",
        4 => "lzo",
        5 => "lz4",
        6 => "zstd",
        _ => return Err(StructureError),
    };

    // Get the header bytes to validate the CRC
    let crc_data = uimage_data
        .get(0..UIMAGE_HEADER_SIZE)
        .ok_or(StructureError)?;

    Ok(UImageHeader {
        header_size: UIMAGE_HEADER_SIZE,
        name: get_cstring(&uimage_data[UIMAGE_NAME_OFFSET..]),
        data_size: uimage_header.data_size.get() as usize,
        data_checksum: uimage_header.data_crc.get(),
        timestamp: uimage_header.creation_timestamp.get() as usize,
        load_address: uimage_header.load_address.get() as usize,
        entry_point_address: uimage_header.entry_point_address.get() as usize,
        compression_type: compression_type.to_string(),
        cpu_type: cpu_type.to_string(),
        os_type: os_type.to_string(),
        image_type: image_type.to_string(),
        header_crc_valid: uimage_header.header_crc == calculate_uimage_header_checksum(crc_data),
    })
}

/// uImage checksum calculator
fn calculate_uimage_header_checksum(hdr: &[u8]) -> u32 {
    const HEADER_CRC_START: usize = 4;
    const HEADER_CRC_END: usize = 8;

    // Header checksum has to be nulled out to calculate the CRC
    let mut uimage_header = hdr.to_vec();
    uimage_header[HEADER_CRC_START..HEADER_CRC_END].fill(0);

    crc32(&uimage_header)
}

/// Describes the internal extractor for carving uImage files to disk
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::uimage::uimage_extractor;
///
/// match uimage_extractor().utility {
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
pub fn uimage_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_uimage),
        ..Default::default()
    }
}

pub fn extract_uimage(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // If no name is provided in the uImage header, use this as the output file name
    const DEFAULT_OUTPUT_FILE_NAME: &str = "uimage_data";
    const OUTPUT_FILE_EXT: &str = "bin";

    let mut result = ExtractionResult::default();

    // Get the uImage data and parse the header
    if let Some(uimage_header_data) = file_data.get(offset..)
        && let Ok(uimage_header) = parse_uimage_header(uimage_header_data)
    {
        let image_data_start = offset + uimage_header.header_size;
        let image_data_end = image_data_start + uimage_header.data_size;

        // Get the raw image data after the uImage header to validate the data CRC
        if let Some(image_data) = file_data.get(image_data_start..image_data_end) {
            result.success = true;
            result.size = Some(uimage_header.header_size);

            // Check the data CRC
            let data_crc_valid: bool = crc32(image_data) == uimage_header.data_checksum;

            // If the data CRC is valid, include the size of the data in the reported size
            if data_crc_valid {
                result.size = Some(result.size.unwrap() + uimage_header.data_size);
            }

            // If extraction was requested and the data CRC is valid, carve the uImage data out to a file
            if data_crc_valid && let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);
                let file_base_name = if uimage_header.name.is_empty() {
                    DEFAULT_OUTPUT_FILE_NAME.to_string()
                } else {
                    uimage_header.name.replace(" ", "_")
                };

                let output_file = format!("{file_base_name}.{OUTPUT_FILE_EXT}");

                result.success = chroot.create_file(&output_file, image_data);
            }
        }
    }

    result
}
