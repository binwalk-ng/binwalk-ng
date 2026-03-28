use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};
/// Struct to store DLOB header info
#[derive(Debug, Default, Clone)]
pub struct DlobHeader {
    pub data_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DlobHeaderBytes1 {
    magic: zerocopy::U32<BE>,
    metadata_size: zerocopy::U32<BE>,
    data_size: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DlobHeaderBytes2 {
    magic: zerocopy::U32<BE>,
    metadata_size: zerocopy::U32<BE>,
    data_size: zerocopy::U32<BE>,
    unknown: [u8; 16],
}
/// Parses a DLOB header
pub fn parse_dlob_header(dlob_data: &[u8]) -> Result<DlobHeader, StructureError> {
    // Parse the first half of the header
    let (dlob_header_p1, _) =
        DlobHeaderBytes1::ref_from_prefix(dlob_data).map_err(|_| StructureError)?;

    // Calculate the offset to the second part of the header
    let dlob_header_p2_offset =
        std::mem::size_of::<DlobHeaderBytes1>() + (dlob_header_p1.metadata_size.get() as usize);

    // It is expected that the first header is metadata only
    if dlob_header_p1.data_size == 0 {
        // Parse the second part of the header
        let (dlob_header_p2, _) =
            DlobHeaderBytes2::ref_from_prefix(&dlob_data[dlob_header_p2_offset..])
                .map_err(|_| StructureError)?;

        // Both parts should have the same magic bytes
        if dlob_header_p1.magic == dlob_header_p2.magic {
            // Calculate total header size
            let header_total_size = dlob_header_p2_offset
                + std::mem::size_of::<DlobHeaderBytes2>()
                + (dlob_header_p2.metadata_size.get() as usize);

            // Basic sanity check on the reported data size vs header size
            if header_total_size < dlob_header_p2.data_size.get() as usize {
                return Ok(DlobHeader {
                    header_size: header_total_size,
                    data_size: dlob_header_p2.data_size.get() as usize,
                });
            }
        }
    }

    Err(StructureError)
}
