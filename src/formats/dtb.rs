use crate::common::{get_cstring, is_offset_safe};
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::error;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "Device tree blob (DTB)";

/// DTB files start with these magic bytes
pub fn dtb_magic() -> Vec<Vec<u8>> {
    vec![b"\xD0\x0D\xFE\xED".to_vec()]
}

/// Validates the DTB header
pub fn dtb_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Sucessful result
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Parse the DTB header
    if let Ok(dtb_header) = parse_dtb_header(&file_data[offset..]) {
        // Calculate the offsets of where the dt_struct and dt_strings end
        let dt_struct_end: usize = offset + dtb_header.struct_offset + dtb_header.struct_size;
        let dt_strings_end: usize = offset + dtb_header.strings_offset + dtb_header.strings_size;

        // Sanity check the dt_struct and dt_strings offsets
        if file_data.len() >= dt_struct_end && file_data.len() >= dt_strings_end {
            result.size = dtb_header.total_size;
            result.description = format!(
                "{}, version: {}, CPU ID: {}, total size: {} bytes",
                result.description, dtb_header.version, dtb_header.cpu_id, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Struct to store DTB info
#[derive(Debug, Default, Clone)]
pub struct DTBHeader {
    pub total_size: usize,
    pub version: u32,
    pub cpu_id: u32,
    pub struct_offset: usize,
    pub strings_offset: usize,
    pub struct_size: usize,
    pub strings_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DTBHeaderBytes {
    magic: zerocopy::U32<BE>,
    total_size: zerocopy::U32<BE>,
    dt_struct_offset: zerocopy::U32<BE>,
    dt_strings_offset: zerocopy::U32<BE>,
    mem_reservation_block_offset: zerocopy::U32<BE>,
    version: zerocopy::U32<BE>,
    min_compatible_version: zerocopy::U32<BE>,
    cpu_id: zerocopy::U32<BE>,
    dt_strings_size: zerocopy::U32<BE>,
    dt_struct_size: zerocopy::U32<BE>,
}

/// Parse  DTB header
pub fn parse_dtb_header(dtb_data: &[u8]) -> Result<DTBHeader, StructureError> {
    // Expected version numbers
    const EXPECTED_VERSION: u32 = 17;
    const EXPECTED_COMPAT_VERSION: u32 = 16;

    const STRUCT_ALIGNMENT: u32 = 4;
    const MEM_RESERVATION_ALIGNMENT: u32 = 8;

    let dtb_structure_size = std::mem::size_of::<DTBHeaderBytes>();

    // Parse the header
    let (dtb_header, _) = DTBHeaderBytes::ref_from_prefix(dtb_data).map_err(|_| StructureError)?;
    // Check the reported versioning
    if dtb_header.version.get() == EXPECTED_VERSION
        && dtb_header.min_compatible_version.get() == EXPECTED_COMPAT_VERSION
    {
        // Check required byte alignments for the specified offsets
        if dtb_header
            .dt_struct_offset
            .get()
            .is_multiple_of(STRUCT_ALIGNMENT)
            && dtb_header
                .mem_reservation_block_offset
                .get()
                .is_multiple_of(MEM_RESERVATION_ALIGNMENT)
        {
            // All offsets must start after the header structure
            if dtb_header.dt_struct_offset.get() as usize >= dtb_structure_size
                && dtb_header.dt_strings_offset.get() as usize >= dtb_structure_size
                && dtb_header.mem_reservation_block_offset.get() as usize >= dtb_structure_size
            {
                return Ok(DTBHeader {
                    total_size: dtb_header.total_size.get() as usize,
                    version: dtb_header.version.get(),
                    cpu_id: dtb_header.cpu_id.get(),
                    struct_offset: dtb_header.dt_struct_offset.get() as usize,
                    strings_offset: dtb_header.dt_strings_offset.get() as usize,
                    struct_size: dtb_header.dt_struct_size.get() as usize,
                    strings_size: dtb_header.dt_strings_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}

/// Describes a DTB node entry
#[derive(Debug, Default, Clone)]
pub struct DTBNode {
    pub begin: bool,
    pub end: bool,
    pub eof: bool,
    pub nop: bool,
    pub property: bool,
    pub name: String,
    pub data: Vec<u8>,
    pub total_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct NodeToken {
    id: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct NodeProperty {
    data_len: zerocopy::U32<BE>,
    name_offset: zerocopy::U32<BE>,
}

/// Parse a DTB node from the DTB data structure
pub fn parse_dtb_node(
    dtb_header: &DTBHeader,
    dtb_data: &[u8],
    node_offset: usize,
) -> Result<DTBNode, StructureError> {
    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_NOP: u32 = 4;
    const FDT_END: u32 = 9;

    let mut node = DTBNode::default();

    if let Some(node_data) = dtb_data.get(node_offset..) {
        let (token, _) = NodeToken::ref_from_prefix(node_data).map_err(|_| StructureError)?;
        // Set total node size to the size of the token entry
        node.total_size = std::mem::size_of::<NodeToken>();

        let token_id = token.id.get();

        if token_id == FDT_END_NODE {
            node.end = true;
        } else if token_id == FDT_NOP {
            node.nop = true;
        } else if token_id == FDT_END {
            node.eof = true;
        // All other node types must include additional data, so the available data must be greater than just the token entry size
        } else if node_data.len() > node.total_size {
            if token_id == FDT_BEGIN_NODE {
                // Begin nodes are immediately followed by a NULL-terminated name, padded to a 4-byte boundary if necessary
                node.begin = true;
                node.name = get_cstring(&node_data[node.total_size..]);
                node.total_size += dtb_aligned(node.name.len() + 1);
            } else if token_id == FDT_PROP {
                // Property tokens are followed by a property structure

                let (property, _) = NodeProperty::ref_from_prefix(&node_data[node.total_size..])
                    .map_err(|_| StructureError)?;

                // Update the total node size to include the property structure
                node.total_size += std::mem::size_of::<NodeProperty>();

                // The property's data will immediately follow the property structure; property data may be NULL-padded for alignment
                if let Some(property_data) = node_data
                    .get(node.total_size..node.total_size + property.data_len.get() as usize)
                {
                    node.data = property_data.to_vec();
                    node.total_size += dtb_aligned(node.data.len());

                    // Get the property name from the DTB strings table
                    if let Some(property_name_data) = dtb_data
                        .get(dtb_header.strings_offset + (property.name_offset.get() as usize)..)
                    {
                        node.name = get_cstring(property_name_data);
                        if !node.name.is_empty() {
                            node.property = true;
                        }
                    }
                }
            }
        }
    }

    Ok(node)
}

/// DTB entries must be aligned to 4-byte boundaries
const fn dtb_aligned(len: usize) -> usize {
    const ALIGNMENT: usize = 4;

    match len % ALIGNMENT {
        0 => len,
        rem => len + (ALIGNMENT - rem),
    }
}

/// Defines the internal extractor function for extracting Device Tree Blobs
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::dtb::dtb_extractor;
///
/// match dtb_extractor().utility {
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
pub fn dtb_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_dtb),
        ..Default::default()
    }
}

/// Internal extractor for extracting Device Tree Blobs
pub fn extract_dtb(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut hierarchy: Vec<String> = Vec::new();

    let mut result = ExtractionResult::default();

    // Parse the DTB file header
    if let Ok(dtb_header) = parse_dtb_header(&file_data[offset..]) {
        // Get all the DTB data
        if let Some(dtb_data) = file_data.get(offset..offset + dtb_header.total_size) {
            // DTB node entries start at the structure offset specified in the DTB header
            let mut entry_offset = dtb_header.struct_offset;
            let mut previous_entry_offset = None;
            let available_data = dtb_data.len();

            // Loop over all DTB node entries
            while is_offset_safe(available_data, entry_offset, previous_entry_offset) {
                // Parse the next DTB node entry
                if let Ok(node) = parse_dtb_node(&dtb_header, dtb_data, entry_offset) {
                    // Beginning of a node, add it to the hierarchy list
                    if node.begin {
                        if !node.name.is_empty() {
                            hierarchy.push(node.name.clone());
                        }
                    // End of a node, remove it from the hierarchy list
                    } else if node.end {
                        if !hierarchy.is_empty() {
                            hierarchy.pop();
                        }
                    // End of the DTB structure, return success only if the whole DTB structure was parsed successfully up to the EOF marker
                    } else if node.eof {
                        result.success = true;
                        result.size = Some(available_data);
                        break;
                    // DTB property, extract it to disk
                    } else if node.property {
                        if let Some(output_directory) = output_directory {
                            let chroot = Chroot::new(output_directory);
                            let dir_path = hierarchy.join(std::path::MAIN_SEPARATOR_STR);
                            let file_path = chroot.safe_path_join(&dir_path, &node.name);

                            if !chroot.create_directory(dir_path) {
                                break;
                            }

                            if !chroot.create_file(file_path, &node.data) {
                                break;
                            }
                        }
                    // The only other supported node type is NOP
                    } else if !node.nop {
                        error!("Unknown or invalid DTB node");
                        break;
                    }

                    // Update offsets to parse the next DTB structure entry
                    previous_entry_offset = Some(entry_offset);
                    entry_offset += node.total_size;
                }
            }
        }
    }

    result
}
