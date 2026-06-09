use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const PCAPNG_DESCRIPTION: &str = "Pcap-NG capture file";

/// Pcap-NG files always start with these bytes
pub fn pcapng_magic() -> Vec<Vec<u8>> {
    vec![b"\x0A\x0D\x0D\x0A".to_vec()]
}

/// Parses and validates the Pcap-NG file
pub fn pcapng_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: PCAPNG_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run
    let dry_run = pcapng_carver(file_data, offset, None);

    // If dry-run was successful, this is almost certainly a valid pcap-ng file
    if dry_run.success
        && let Some(pcap_size) = dry_run.size
    {
        // If this file is just a pcap file, no need to carve it out to yet another file on disk
        if offset == 0 && pcap_size == file_data.len() {
            result.extraction_declined = true;
        }

        // Return parser results
        result.size = pcap_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Storage struct for Pcap block info
#[derive(Debug, Clone, Default)]
pub struct PcapBlock {
    pub block_type: u32,
    pub block_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BlockHeader {
    block_type: dyn_endian::U32,
    block_size: dyn_endian::U32,
}

/// Parse a Pcap-ng block
pub fn parse_pcapng_block(
    block_data: &[u8],
    endianness: Endianness,
) -> Result<PcapBlock, StructureError> {
    // Reserved bit in block type field
    const BLOCK_TYPE_RESERVED_MASK: u32 = 0x80000000;

    let footer_size = std::mem::size_of::<dyn_endian::U32>();

    // Parse the block header
    let (block_header, _) = BlockHeader::ref_from_prefix(block_data).map_err(|_| StructureError)?;

    // Populate the block type and size values
    let result = PcapBlock {
        block_type: block_header.block_type.get(endianness),
        block_size: block_header.block_size.get(endianness) as usize,
    };

    // Make sure the reserved bit of the block type is not set
    if (result.block_type & BLOCK_TYPE_RESERVED_MASK) == 0 {
        // Calculate the block footer offsets
        let block_footer_start = result.block_size - footer_size;

        // Validate that the block size in the block footer matches the block size in the block header
        if let Some(block_footer_data) = block_data.get(block_footer_start..)
            && let Ok((block_size, _)) = dyn_endian::U32::ref_from_prefix(block_footer_data)
            && block_size.get(endianness) as usize == result.block_size
        {
            return Ok(result);
        }
    }

    Err(StructureError)
}

#[derive(Debug, Clone)]
pub struct PcapSectionBlock {
    pub block_size: usize,
    pub endianness: Endianness,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SectionHeader {
    block_type: dyn_endian::U32,
    block_size: dyn_endian::U32,
    endian_magic: dyn_endian::U32,
    major_version: dyn_endian::U16,
    minor_version: dyn_endian::U16,
    section_length: dyn_endian::U32,
}

/// Parse a Pcap-ng section block
pub fn parse_pcapng_section_block(block_data: &[u8]) -> Result<PcapSectionBlock, StructureError> {
    // Section header block type (same value, regardless of endianness)
    const SECTION_HEADER_BLOCK_TYPE: u32 = 0x0A0D0D0A;
    const MAGIC: u32 = 0x1A2B3C4D;
    const LITTLE_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Little);
    const BIG_ENDIAN_MAGIC: dyn_endian::U32 = dyn_endian::U32::new(MAGIC, Endianness::Big);

    // Parse the section header structure; endianness doesn't matter (yet)
    let (section_header, _) =
        SectionHeader::ref_from_prefix(block_data).map_err(|_| StructureError)?;

    // Determine the endianness based on the endian magic bytes
    let endianness = match section_header.endian_magic {
        LITTLE_ENDIAN_MAGIC => Endianness::Little,
        BIG_ENDIAN_MAGIC => Endianness::Big,
        _ => return Err(StructureError),
    };
    // Parse the section header block as a generic block to ensure it is valid
    if let Ok(block_header) = parse_pcapng_block(block_data, endianness) {
        // Make sure the section header block type is the expected value
        if block_header.block_type == SECTION_HEADER_BLOCK_TYPE {
            return Ok(PcapSectionBlock {
                block_size: block_header.block_size,
                endianness,
            });
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor function for extracting pcap-ng files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::pcap::pcapng_extractor;
///
/// match pcapng_extractor().utility {
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
pub fn pcapng_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(pcapng_carver),
        ..Default::default()
    }
}

/// Carves a pcap-ng file to disk
pub fn pcapng_carver(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    // Output file name
    const OUTPUT_FILE_NAME: &str = "capture.pcapng";

    // Pcap-NG files must have at least two blocks: a section header block and an interface description block
    const MIN_BLOCK_COUNT: usize = 2;

    // Return value
    let mut result = ExtractionResult::default();

    // All pcap-ng files start with a section header; parse it
    if let Ok(section_header) = parse_pcapng_section_block(&file_data[offset..]) {
        let mut block_count: usize = 1;
        let available_data = file_data.len() - offset;
        let mut next_offset = offset + section_header.block_size;
        let mut previous_offset = None;

        // Loop through all blocks in the pcap-ng file
        while is_offset_safe(available_data, next_offset, previous_offset) {
            match file_data.get(next_offset..) {
                None => {
                    break;
                }
                Some(block_data) => {
                    // Parse the next block header
                    match parse_pcapng_block(block_data, section_header.endianness) {
                        Err(_) => {
                            break;
                        }
                        Ok(block_header) => {
                            // This block looks valid, go to the next one
                            block_count += 1;
                            previous_offset = Some(next_offset);
                            next_offset += block_header.block_size;
                        }
                    }
                }
            }
        }

        // Must have processed the minimum number of blocks
        if block_count >= MIN_BLOCK_COUNT {
            // Everything looks OK
            result.size = Some(next_offset - offset);
            result.success = true;

            // Do extraction if requested
            if let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);
                result.success =
                    chroot.carve_file(OUTPUT_FILE_NAME, file_data, offset, result.size.unwrap());
            }
        }
    }

    result
}
