use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Storage struct for AndroidSparse file header info
#[derive(Debug, Default, Clone)]
pub struct AndroidSparseHeader {
    pub major_version: u16,
    pub minor_version: u16,
    pub header_size: usize,
    pub block_size: usize,
    pub chunk_count: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AndroidSparseHeaderBytes {
    magic: zerocopy::U32<LE>,
    major_version: zerocopy::U16<LE>,
    minor_version: zerocopy::U16<LE>,
    header_size: zerocopy::U16<LE>,
    chunk_header_size: zerocopy::U16<LE>,
    block_size: zerocopy::U32<LE>,
    block_count: zerocopy::U32<LE>,
    total_chunks: zerocopy::U32<LE>,
    checksum: zerocopy::U32<LE>,
}

/// Parse Android Sparse header structures
pub fn parse_android_sparse_header(
    sparse_data: &[u8],
) -> Result<AndroidSparseHeader, StructureError> {
    // Version must be 1.0
    const MAJOR_VERSION: u16 = 1;
    const MINOR_VERSION: u16 = 0;

    // Blocks must be aligned on a 4-byte boundary
    const BLOCK_ALIGNMENT: u32 = 4;

    // Expected value for the reported chunk header size
    const CHUNK_HEADER_SIZE: u16 = 12;

    let expected_header_size = std::mem::size_of::<AndroidSparseHeaderBytes>();

    // Parse the header
    let (header, _) =
        AndroidSparseHeaderBytes::ref_from_prefix(sparse_data).map_err(|_| StructureError)?;

    // Sanity check header values
    if header.major_version.get() == MAJOR_VERSION
        && header.minor_version.get() == MINOR_VERSION
        && header.header_size.get() as usize == expected_header_size
        && header.chunk_header_size.get() == CHUNK_HEADER_SIZE
        && header.block_size.get().is_multiple_of(BLOCK_ALIGNMENT)
    {
        return Ok(AndroidSparseHeader {
            major_version: header.major_version.get(),
            minor_version: header.minor_version.get(),
            header_size: header.header_size.get() as usize,
            block_size: header.block_size.get() as usize,
            chunk_count: header.total_chunks.get() as usize,
        });
    }

    Err(StructureError)
}

/// Storage structure for Android Sparse chunk headers
#[derive(Debug, Default, Clone)]
pub struct AndroidSparseChunkHeader {
    pub header_size: usize,
    pub data_size: usize,
    pub block_count: usize,
    pub is_crc: bool,
    pub is_raw: bool,
    pub is_fill: bool,
    pub is_dont_care: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AndroidSparseChunkHeaderBytes {
    chunk_type: zerocopy::U16<LE>,
    reserved: zerocopy::U16<LE>,
    output_block_count: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
}

/// Parse the header for an Android Sparse chunk
pub fn parse_android_sparse_chunk_header(
    chunk_data: &[u8],
) -> Result<AndroidSparseChunkHeader, StructureError> {
    // Known chunk types
    const CHUNK_TYPE_RAW: u16 = 0xCAC1;
    const CHUNK_TYPE_FILL: u16 = 0xCAC2;
    const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
    const CHUNK_TYPE_CRC: u16 = 0xCAC4;

    let mut chonker = AndroidSparseChunkHeader {
        header_size: std::mem::size_of::<AndroidSparseChunkHeaderBytes>(),
        ..Default::default()
    };

    // Parse the header
    let (chunk_header, _) =
        AndroidSparseChunkHeaderBytes::ref_from_prefix(chunk_data).map_err(|_| StructureError)?;
    // Make sure the reserved field is zero
    if chunk_header.reserved == 0 {
        // Populate the structure values
        chonker.block_count = chunk_header.output_block_count.get() as usize;
        chonker.data_size = (chunk_header.total_size.get() as usize) - chonker.header_size;
        chonker.is_crc = chunk_header.chunk_type == CHUNK_TYPE_CRC;
        chonker.is_raw = chunk_header.chunk_type == CHUNK_TYPE_RAW;
        chonker.is_fill = chunk_header.chunk_type == CHUNK_TYPE_FILL;
        chonker.is_dont_care = chunk_header.chunk_type == CHUNK_TYPE_DONT_CARE;

        // The chunk type must be one of the known chunk types
        if chonker.is_crc || chonker.is_raw || chonker.is_fill || chonker.is_dont_care {
            return Ok(chonker);
        }
    }

    Err(StructureError)
}
