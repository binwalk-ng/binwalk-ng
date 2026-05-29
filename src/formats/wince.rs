use crate::common::is_offset_safe;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "Windows CE binary image";

/// Windows CE magic bytes
pub fn wince_magic() -> Vec<Vec<u8>> {
    vec![b"B000FF\n".to_vec()]
}

/// Validates the Windows CE header
pub fn wince_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run
    let dry_run = wince_dump(file_data, offset, None);

    if dry_run.success
        && let Some(total_size) = dry_run.size
    {
        result.size = total_size;

        // Parse the WinCE header to get some useful info to display
        if let Ok(wince_header) = parse_wince_header(&file_data[offset..]) {
            result.description = format!(
                "{}, base address: {:#X}, image size: {} bytes, file size: {} bytes",
                result.description, wince_header.base_address, wince_header.image_size, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store WindowsCE header info
#[derive(Debug, Default, Clone)]
pub struct WinCEHeader {
    pub base_address: usize,
    pub image_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct WinCEHeaderBytes {
    magic: [u8; 7],
    image_start: zerocopy::U32<LE>,
    image_size: zerocopy::U32<LE>,
}

/// Parses a Windows CE header
pub fn parse_wince_header(wince_data: &[u8]) -> Result<WinCEHeader, StructureError> {
    // Parse the WinCE header
    let (wince_header, _) =
        WinCEHeaderBytes::ref_from_prefix(wince_data).map_err(|_| StructureError)?;

    Ok(WinCEHeader {
        base_address: wince_header.image_start.get() as usize,
        image_size: wince_header.image_size.get() as usize,
        header_size: std::mem::size_of::<WinCEHeaderBytes>(),
    })
}

/// Struct to store WindowsCE block info
#[derive(Debug, Default, Clone)]
pub struct WinCEBlock {
    pub address: usize,
    pub data_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct WinCEBlockHeaderBytes {
    address: zerocopy::U32<LE>,
    size: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
}

/// Parse a WindowsCE block header
pub fn parse_wince_block_header(block_data: &[u8]) -> Result<WinCEBlock, StructureError> {
    let (block_header, _) =
        WinCEBlockHeaderBytes::ref_from_prefix(block_data).map_err(|_| StructureError)?;
    Ok(WinCEBlock {
        address: block_header.address.get() as usize,
        data_size: block_header.size.get() as usize,
        header_size: std::mem::size_of::<WinCEBlockHeaderBytes>(),
    })
}

/// Defines the internal extractor function for extracting Windows CE images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::wince::wince_extractor;
///
/// match wince_extractor().utility {
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
pub fn wince_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(wince_dump),
        ..Default::default()
    }
}

/// Internal extractor for extracting data blocks from Windows CE images
pub fn wince_dump(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    // Parse the file header
    if let Some(wince_data) = file_data.get(offset..)
        && let Ok(wince_header) = parse_wince_header(wince_data)
    {
        // Get the block data, immediately following the file header
        if let Some(wince_block_data) = wince_data.get(wince_header.header_size..) {
            // Process all blocks in the block data
            if let Some(data_blocks) = process_wince_blocks(wince_block_data) {
                // The first block entry's address should equal the WinCE header's base address
                if data_blocks.entries[0].address == wince_header.base_address {
                    // Block processing was successful
                    result.success = true;
                    result.size = Some(wince_header.header_size + data_blocks.total_size);

                    // If extraction was requested, extract each block to a file on disk
                    if let Some(output_directory) = output_directory {
                        let chroot = Chroot::new(output_directory);

                        for block in data_blocks.entries {
                            let block_file_name = format!("{:X}.bin", block.address);

                            // If file carving fails, report a failure to extract
                            if !chroot.carve_file(
                                block_file_name,
                                wince_block_data,
                                block.offset,
                                block.size,
                            ) {
                                result.success = false;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

/// Stores info about each WinCE block
#[derive(Debug, Default, Clone)]
struct BlockInfo {
    pub address: usize,
    pub offset: usize,
    pub size: usize,
}

/// Stores info about all WinCE blocks
#[derive(Debug, Default, Clone)]
struct BlockData {
    pub total_size: usize,
    pub entries: Vec<BlockInfo>,
}

/// Process all WinCE blocks
fn process_wince_blocks(blocks_data: &[u8]) -> Option<BlockData> {
    // Arbitrarily chosen, just to make sure more than one or two blocks were processed and sane
    const MIN_ENTRIES_COUNT: usize = 5;

    let mut blocks = BlockData::default();

    let mut next_offset: usize = 0;
    let mut previous_offset = None;
    let available_data = blocks_data.len();

    // Process all blocks until the end block is reached, or an error is encountered
    while is_offset_safe(available_data, next_offset, previous_offset) {
        // Parse this block's header
        match parse_wince_block_header(&blocks_data[next_offset..]) {
            Err(_) => {
                break;
            }
            Ok(block_header) => {
                // Include the block header size in the total size of the block data
                blocks.total_size += block_header.header_size;

                // A block header address of NULL indicates EOF
                if block_header.address == 0 {
                    // Sanity check the number of blocks processed
                    if blocks.entries.len() > MIN_ENTRIES_COUNT {
                        return Some(blocks);
                    } else {
                        break;
                    }
                } else {
                    // Include this block's size in the total size of the block data
                    blocks.total_size += block_header.data_size;

                    // Add this block to the list of block entries
                    blocks.entries.push(BlockInfo {
                        address: block_header.address,
                        offset: next_offset + block_header.header_size,
                        size: block_header.data_size,
                    });

                    // Update the offsets for the next loop iteration
                    previous_offset = Some(next_offset);
                    next_offset += block_header.header_size + block_header.data_size;
                }
            }
        }
    }

    None
}
