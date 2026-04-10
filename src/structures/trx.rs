use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};
/// Stores TRX firmware header info
#[derive(Debug, Clone, Default)]
pub struct TRXHeader {
    pub version: u16,
    pub checksum: u32,
    pub total_size: usize,
    pub header_size: usize,
    pub partitions: Vec<usize>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TRXHeaderBytes {
    magic: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
    crc32: zerocopy::U32<LE>,
    flags: zerocopy::U16<LE>,
    version: zerocopy::U16<LE>,
    partition1_offset: zerocopy::U32<LE>,
    partition2_offset: zerocopy::U32<LE>,
    partition3_offset: zerocopy::U32<LE>,
    partition4_offset: zerocopy::U32<LE>,
}

/// Parse a TRX firmware header
pub fn parse_trx_header(header_data: &[u8]) -> Result<TRXHeader, StructureError> {
    // TRX comes in two flavors: v1 and v2
    const TRX_VERSION_2: u16 = 2;

    let allowed_versions = [1, 2];

    // Size of the fixed-length portion of the header structure
    let mut struct_size: usize = std::mem::size_of::<TRXHeaderBytes>();

    // Parse the header
    let (trx_header, _) =
        TRXHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;
    // Sanity check partition offsets. Partition offsets may be 0.
    if trx_header.partition1_offset <= trx_header.total_size
        && trx_header.partition2_offset <= trx_header.total_size
        && trx_header.partition3_offset <= trx_header.total_size
    {
        // Sanity check the reported total size
        if trx_header.total_size.get() as usize > struct_size {
            // Sanity check the reported version number
            if allowed_versions.contains(&trx_header.version.get()) {
                let mut partitions = vec![];

                if trx_header.partition1_offset != 0 {
                    partitions.push(trx_header.partition1_offset.get() as usize);
                }

                if trx_header.partition2_offset != 0 {
                    partitions.push(trx_header.partition2_offset.get() as usize);
                }

                if trx_header.partition3_offset != 0 {
                    partitions.push(trx_header.partition3_offset.get() as usize);
                }

                // Only TRXv2 has a fourth partition entry
                if trx_header.version == TRX_VERSION_2 {
                    if trx_header.partition4_offset != 0 {
                        partitions.push(trx_header.partition4_offset.get() as usize);
                    }
                } else {
                    // For TRXv1, this means the real structure size is 4 bytes shorter
                    struct_size -= std::mem::size_of::<u32>();
                }

                return Ok(TRXHeader {
                    version: trx_header.version.get(),
                    checksum: trx_header.crc32.get(),
                    total_size: trx_header.total_size.get() as usize,
                    header_size: struct_size,
                    partitions: partitions.clone(),
                });
            }
        }
    }

    Err(StructureError)
}
