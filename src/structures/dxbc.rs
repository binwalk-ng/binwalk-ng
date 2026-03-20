use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

#[derive(Debug, Default, Clone)]
pub struct DXBCHeader {
    pub size: usize,
    pub chunk_ids: Vec<[u8; 4]>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DXBCHeaderBytes {
    magic: zerocopy::U32<LE>,
    signature: [u8; 16],
    one: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
    chunk_count: zerocopy::U32<LE>,
}

// http://timjones.io/blog/archive/2015/09/02/parsing-direct3d-shader-bytecode
pub fn parse_dxbc_header(data: &[u8]) -> Result<DXBCHeader, StructureError> {
    // Parse the header
    let (header, _) = DXBCHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;

    if header.one.get() != 1 {
        return Err(StructureError);
    }

    let count = header.chunk_count.get() as usize;

    // Sanity check: There are at least 14 known chunks, but most likely no more than 32.
    // Prevents the for loop from spiraling into an OOM on the offchance that both the magic and "one" check pass on garbage data
    if count > 32 {
        return Err(StructureError);
    }

    let header_end = std::mem::size_of::<DXBCHeaderBytes>();

    let chunk_ids: Result<Vec<[u8; 4]>, StructureError> = data
        .get(header_end..header_end + count * 4)
        .ok_or(StructureError)?
        .chunks_exact(4)
        .map(|offset_bytes| {
            let offset_bytes: [u8; 4] = offset_bytes.try_into().map_err(|_| StructureError)?;
            let offset = u32::from_le_bytes(offset_bytes) as usize;

            let chunk = data.get(offset..offset + 4).ok_or(StructureError)?;

            chunk.try_into().map_err(|_| StructureError)
        })
        .collect();
    let chunk_ids = chunk_ids?;

    Ok(DXBCHeader {
        size: header.total_size.get() as usize,
        chunk_ids,
    })
}
