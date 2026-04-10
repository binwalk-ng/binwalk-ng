use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store useful ISO info
#[derive(Debug, Default, Clone)]
pub struct ISOHeader {
    pub image_size: usize,
}

// Partial ISO header structure, enough to reasonably validate that this is not a false positive and to calculate the total ISO size
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ISOHeaderBytes {
    unused1: [u8; 8],
    volume_size_1: zerocopy::U32<LE>,
    volume_size_2: zerocopy::U32<BE>,
    unused2: [u8; 32],
    set_size_1: zerocopy::U16<LE>,
    set_size_2: zerocopy::U16<BE>,
    sequence_number_1: zerocopy::U16<LE>,
    sequence_number_2: zerocopy::U16<BE>,
    block_size_1: zerocopy::U16<LE>,
    block_size_2: zerocopy::U16<BE>,
    path_table_size_1: zerocopy::U32<LE>,
    path_table_size_2: zerocopy::U32<BE>,
}

/// Partially parses an ISO header
pub fn parse_iso_header(iso_data: &[u8]) -> Result<ISOHeader, StructureError> {
    // Offset from the beginning of the ISO image to the start of iso_structure
    const ISO_STRUCT_START: usize = 32840;

    let mut iso_info = ISOHeader {
        ..Default::default()
    };

    if let Some(iso_header_data) = iso_data.get(ISO_STRUCT_START..) {
        // Parse the ISO header
        let (iso_header, _) =
            ISOHeaderBytes::ref_from_prefix(iso_header_data).map_err(|_| StructureError)?;

        // Make sure all the unused fields are, in fact, unused
        if iso_header
            .unused1
            .iter()
            .chain(&iso_header.unused2)
            .all(|&b| b == 0)
        {
            // Make sure all the identical, but byte-swapped, fields agree.
            if iso_header.set_size_1 == iso_header.set_size_2.get()
                && iso_header.block_size_1 == iso_header.block_size_2.get()
                && iso_header.volume_size_1 == iso_header.volume_size_2.get()
                && iso_header.sequence_number_1 == iso_header.sequence_number_2.get()
                && iso_header.path_table_size_1 == iso_header.path_table_size_2.get()
            {
                iso_info.image_size = iso_header.volume_size_1.get() as usize
                    * iso_header.block_size_1.get() as usize;
                return Ok(iso_info);
            }
        }
    }

    Err(StructureError)
}
