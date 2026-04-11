use crate::common::get_cstring;
use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

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
fn dtb_aligned(len: usize) -> usize {
    const ALIGNMENT: usize = 4;

    match len % ALIGNMENT {
        0 => len,
        rem => len + (ALIGNMENT - rem),
    }
}
