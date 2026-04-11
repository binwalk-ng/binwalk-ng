use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store LZFSE block info
#[derive(Debug, Default, Clone)]
pub struct LZFSEBlock {
    pub eof: bool,
    pub data_size: usize,
    pub header_size: usize,
    pub uncompressed_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BlockHeader {
    block_type: zerocopy::U32<LE>,
}

/// Parse an LZFSE block header
pub fn parse_lzfse_block_header(lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    // LZFSE block types
    const ENDOFSTREAM: u32 = 0x24787662;
    const UNCOMPRESSED: u32 = 0x2d787662;
    const COMPRESSEDV1: u32 = 0x31787662;
    const COMPRESSEDV2: u32 = 0x32787662;
    const COMPRESSEDLZVN: u32 = 0x6e787662;

    // Parse the block header
    let (block_type_header, _) =
        BlockHeader::ref_from_prefix(lzfse_data).map_err(|_| StructureError)?;

    // Block headers are different for different block types; process this block header accordingly
    match block_type_header.block_type.get() {
        ENDOFSTREAM => parse_endofstream_block_header(lzfse_data),
        UNCOMPRESSED => parse_uncompressed_block_header(lzfse_data),
        COMPRESSEDV1 => parse_compressedv1_block_header(lzfse_data),
        COMPRESSEDV2 => parse_compressedv2_block_header(lzfse_data),
        COMPRESSEDLZVN => parse_compressedlzvn_block_header(lzfse_data),
        _ => Err(StructureError),
    }
}

/// Parse an end-of-stream LZFSE block header
fn parse_endofstream_block_header(_lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    // This is easy; it's just the 4-byte magic bytes marking the end-of-stream
    Ok(LZFSEBlock {
        eof: true,
        data_size: 0,
        header_size: 4,
        uncompressed_size: 0,
    })
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct UncompressedBlockHeader {
    magic: zerocopy::U32<LE>,
    n_raw_bytes: zerocopy::U32<LE>,
}

/// Parse an uncompressed LZFSE block header
fn parse_uncompressed_block_header(lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    const HEADER_SIZE: usize = 8;

    let (header, _) =
        UncompressedBlockHeader::ref_from_prefix(lzfse_data).map_err(|_| StructureError)?;

    let data_size = header.n_raw_bytes.get() as usize;
    Ok(LZFSEBlock {
        eof: false,
        data_size,
        header_size: HEADER_SIZE,
        uncompressed_size: data_size,
    })
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BlockV1Header {
    magic: zerocopy::U32<LE>,
    n_raw_bytes: zerocopy::U32<LE>,
    n_payload_bytes: zerocopy::U32<LE>,
    n_literals: zerocopy::U32<LE>,
    n_matches: zerocopy::U32<LE>,
    n_literal_payload_bytes: zerocopy::U32<LE>,
    n_lmd_payload_bytes: zerocopy::U32<LE>,
    literal_bits: zerocopy::U32<LE>,
    literal_state: zerocopy::U64<LE>,
    lmd_bits: zerocopy::U32<LE>,
    l_state: zerocopy::U16<LE>,
    m_state: zerocopy::U16<LE>,
    d_state: zerocopy::U16<LE>,
    // Frequency tables follow
}

/// Parse a compressed (version 1) LZFSE block header
fn parse_compressedv1_block_header(lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    const HEADER_SIZE: usize = 770;

    let (header, _) = BlockV1Header::ref_from_prefix(lzfse_data).map_err(|_| StructureError)?;
    Ok(LZFSEBlock {
        eof: false,
        data_size: (header.n_literal_payload_bytes.get() + header.n_lmd_payload_bytes.get())
            as usize,
        header_size: HEADER_SIZE,
        uncompressed_size: header.n_raw_bytes.get() as usize,
    })
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BlockV2Header {
    magic: zerocopy::U32<LE>,
    uncompressed_size: zerocopy::U32<LE>,
    packed_field_1: zerocopy::U64<LE>,
    packed_field_2: zerocopy::U64<LE>,
    header_size: zerocopy::U32<LE>,
    state_fields: zerocopy::U32<LE>,
    // Variable length header field follows
}

/// Parse a compressed (version 2) LZFSE block header
fn parse_compressedv2_block_header(lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    const N_PAYLOAD_SHIFT: u64 = 20;
    const LMD_PAYLOAD_SHIFT: u64 = 40;
    const PAYLOAD_MASK: u64 = 0b11111_11111_11111_11111;

    let (block_header, _) =
        BlockV2Header::ref_from_prefix(lzfse_data).map_err(|_| StructureError)?;

    let n_lmd_payload_bytes =
        (block_header.packed_field_2.get() >> LMD_PAYLOAD_SHIFT) & PAYLOAD_MASK;
    let n_literal_payload_bytes =
        (block_header.packed_field_1.get() >> N_PAYLOAD_SHIFT) & PAYLOAD_MASK;

    Ok(LZFSEBlock {
        eof: false,
        data_size: (n_lmd_payload_bytes + n_literal_payload_bytes) as usize,
        header_size: block_header.header_size.get() as usize,
        uncompressed_size: block_header.uncompressed_size.get() as usize,
    })
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct BlockLZVNHeader {
    magic: zerocopy::U32<LE>,
    n_raw_bytes: zerocopy::U32<LE>,
    n_payload_bytes: zerocopy::U32<LE>,
}

/// Parse a LZVN compressed LZFSE block header
fn parse_compressedlzvn_block_header(lzfse_data: &[u8]) -> Result<LZFSEBlock, StructureError> {
    const HEADER_SIZE: usize = 12;
    let (header, _) = BlockLZVNHeader::ref_from_prefix(lzfse_data).map_err(|_| StructureError)?;
    Ok(LZFSEBlock {
        eof: false,
        data_size: header.n_payload_bytes.get() as usize,
        header_size: HEADER_SIZE,
        uncompressed_size: header.n_raw_bytes.get() as usize,
    })
}
